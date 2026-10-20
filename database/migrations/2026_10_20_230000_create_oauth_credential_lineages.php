<?php

use Illuminate\Database\Connection;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

return new class extends Migration
{
    public function up(): void
    {
        $connection = DB::connection($this->getConnection());
        $schema = $connection->getSchemaBuilder();
        // Passport is optional. These records deliberately have no foreign keys
        // to its purgeable token/code rows and contain no bearer/refresh secrets.
        if (! $schema->hasTable('oauth_access_tokens')) {
            return;
        }
        if (! $schema->hasTable('oauth_credential_revocations')) {
            $schema->create('oauth_credential_revocations', static function (Blueprint $table): void {
                $table->string('scope_key', 64)->primary();
                $table->unsignedBigInteger('sequence')->default(0);
            });
        }
        $connection->table('oauth_credential_revocations')->insertOrIgnore([
            'scope_key' => hash('sha256', 'bherila-auth.revocation-clock'), 'sequence' => 0,
        ]);
        if (! $schema->hasTable('oauth_credential_lineages')) {
            $schema->create('oauth_credential_lineages', static function (Blueprint $table): void {
                $table->uuid('id')->primary();
                $table->string('owner_key', 64)->index();
                $table->string('client_key', 64)->index();
                $table->string('owner_id', 191)->nullable();
                $table->string('client_id', 191);
                $table->unsignedBigInteger('issued_sequence');
                $table->boolean('revoked')->default(false);
            });
        }
        if (! $schema->hasTable('oauth_credential_members')) {
            $schema->create('oauth_credential_members', static function (Blueprint $table): void {
                $table->string('credential_key', 64)->primary();
                $table->uuid('lineage_id')->index();
                $table->string('kind', 16);
                $table->string('credential_id', 191);
            });
        }
        $registered = hash('sha256', 'bherila-auth.legacy-credentials-registered');
        if (! $connection->table('oauth_credential_revocations')->where('scope_key', $registered)->exists()) {
            $this->registerLegacyCredentials($connection);
            $connection->table('oauth_credential_revocations')->insertOrIgnore(['scope_key' => $registered, 'sequence' => 0]);
        }
    }

    /** Register only the rows present at cutover, in bounded batches. Never enroll later unknown writes on replay. */
    private function registerLegacyCredentials(Connection $connection): void
    {
        $schema = $connection->getSchemaBuilder();
        foreach (['oauth_access_tokens' => 'access', 'oauth_auth_codes' => 'code'] as $table => $kind) {
            if (! $schema->hasTable($table)) {
                continue;
            }
            $connection->table($table)->orderBy('id')->chunkById(100, function ($rows) use ($connection, $kind): void {
                $keys = $rows->map(fn ($row): string => $this->credentialKey($kind, (string) $row->id))->all();
                $known = $connection->table('oauth_credential_members')->whereIn('credential_key', $keys)->pluck('credential_key')->flip()->all();
                $lineages = [];
                $members = [];
                foreach ($rows as $row) {
                    $key = $this->credentialKey($kind, (string) $row->id);
                    if (isset($known[$key]) || ! is_string($row->client_id) || $row->client_id === '' || ($kind === 'code' && $row->user_id === null)) {
                        continue;
                    }
                    $lineage = $this->legacyLineage($row->user_id === null ? null : (string) $row->user_id, $row->client_id);
                    $lineages[] = $lineage;
                    $members[] = $this->legacyMember($kind, (string) $row->id, $lineage['id']);
                }
                if ($lineages !== []) {
                    $connection->table('oauth_credential_lineages')->insertOrIgnore($lineages);
                    $connection->table('oauth_credential_members')->insertOrIgnore($members);
                }
            });
        }
        if (! $schema->hasTable('oauth_refresh_tokens')) {
            return;
        }
        $connection->table('oauth_refresh_tokens')->orderBy('id')->chunkById(100, function ($rows) use ($connection): void {
            $keys = $rows->map(fn ($row): string => $this->credentialKey('refresh', (string) $row->id))->all();
            $known = $connection->table('oauth_credential_members')->whereIn('credential_key', $keys)->pluck('credential_key')->flip()->all();
            $parentKeys = $rows->map(fn ($row): string => $this->credentialKey('access', (string) $row->access_token_id))->all();
            $parents = $connection->table('oauth_credential_members as members')
                ->join('oauth_credential_lineages as lineages', 'lineages.id', '=', 'members.lineage_id')
                ->whereIn('members.credential_key', $parentKeys)->get(['members.credential_key', 'lineages.*'])->keyBy('credential_key')->all();
            $lineages = [];
            $members = [];
            foreach ($rows as $row) {
                $key = $this->credentialKey('refresh', (string) $row->id);
                if (isset($known[$key])) {
                    continue;
                }
                $parentKey = $this->credentialKey('access', (string) $row->access_token_id);
                $parent = $parents[$parentKey] ?? null;
                $owner = $row->provider_user_id ?? null;
                $client = $row->client_id ?? null;
                if ($parent !== null) {
                    // Never upgrade inconsistent owner/client metadata into an authority.
                    if (($owner !== null && (string) $owner !== $parent->owner_id) || ($client !== null && (string) $client !== $parent->client_id)) {
                        continue;
                    }
                    $lineageId = $parent->id;
                } else {
                    if ($owner === null || ! is_string($client) || $client === '') {
                        continue;
                    }
                    $lineage = $this->legacyLineage((string) $owner, $client);
                    $lineageId = $lineage['id'];
                    $parents[$parentKey] = (object) $lineage;
                    $lineages[] = $lineage;
                    // This membership survives even when the legacy access row was purged.
                    $members[] = $this->legacyMember('access', (string) $row->access_token_id, $lineageId);
                }
                $members[] = $this->legacyMember('refresh', (string) $row->id, $lineageId);
            }
            if ($lineages !== []) {
                $connection->table('oauth_credential_lineages')->insertOrIgnore($lineages);
            }
            if ($members !== []) {
                $connection->table('oauth_credential_members')->insertOrIgnore($members);
            }
        });
    }

    /** @return array{id: string, owner_key: string, client_key: string, owner_id: ?string, client_id: string, issued_sequence: int, revoked: bool} */
    private function legacyLineage(?string $owner, string $client): array
    {
        return ['id' => (string) Str::uuid(),
            'owner_key' => hash('sha256', json_encode(['owner', $owner], JSON_THROW_ON_ERROR)),
            'client_key' => hash('sha256', json_encode(['client', $owner, $client], JSON_THROW_ON_ERROR)),
            'owner_id' => $owner, 'client_id' => $client, 'issued_sequence' => 0, 'revoked' => false];
    }

    /** @return array{credential_key: string, lineage_id: string, kind: string, credential_id: string} */
    private function legacyMember(string $kind, string $id, string $lineage): array
    {
        return ['credential_key' => $this->credentialKey($kind, $id), 'lineage_id' => $lineage, 'kind' => $kind, 'credential_id' => $id];
    }

    private function credentialKey(string $kind, string $id): string
    {
        return hash('sha256', json_encode(['credential', $kind, $id], JSON_THROW_ON_ERROR));
    }

    // Durable revocations must not disappear on rollback. An application can
    // explicitly retire these tables only after every associated grant expires.
    public function down(): void {}

    public function getConnection(): ?string
    {
        return $this->connection ?? config('passport.connection');
    }
};
