<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;

return new class extends Migration
{
    /** Retain the client association after an expired access-token row is purged. */
    public function up(): void
    {
        $connection = DB::connection($this->getConnection());
        $schema = $connection->getSchemaBuilder();
        if (! $schema->hasTable('oauth_refresh_tokens')) {
            return;
        }
        if (! $schema->hasColumn('oauth_refresh_tokens', 'client_id')) {
            $schema->table('oauth_refresh_tokens', static function (Blueprint $table): void {
                $table->string('client_id', 191)->nullable()->index();
            });
        }
        if (! $schema->hasTable('oauth_access_tokens')) {
            return;
        }

        // Existing linked rows can be recovered before their access rows disappear. Never
        // overwrite an application-owned client association or guess an orphan's client.
        $connection->table('oauth_refresh_tokens')->whereNull('client_id')
            ->whereIn('access_token_id', $connection->table('oauth_access_tokens')->select('id')->whereNotNull('client_id'))
            ->update(['client_id' => $connection->table('oauth_access_tokens')->select('client_id')
                ->whereColumn('oauth_access_tokens.id', 'oauth_refresh_tokens.access_token_id')]);
    }

    /** A skipped application-owned column cannot safely be removed on rollback. */
    public function down(): void {}

    public function getConnection(): ?string
    {
        return $this->connection ?? config('passport.connection');
    }
};
