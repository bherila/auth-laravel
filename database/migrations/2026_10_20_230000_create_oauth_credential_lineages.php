<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;

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
    }

    // Durable revocations must not disappear on rollback. An application can
    // explicitly retire these tables only after every associated grant expires.
    public function down(): void {}

    public function getConnection(): ?string
    {
        return $this->connection ?? config('passport.connection');
    }
};
