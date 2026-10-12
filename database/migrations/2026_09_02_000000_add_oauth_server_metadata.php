<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Add only columns that are absent. Passport installations and application
     * migrations vary, so this migration is deliberately safe to publish after
     * an application has already added one of these columns.
     */
    public function up(): void
    {
        $this->addColumn('oauth_clients', 'dynamically_registered_at', function (Blueprint $table): void {
            $table->timestamp('dynamically_registered_at')->nullable();
        });
        $this->addColumn('oauth_clients', 'last_used_at', function (Blueprint $table): void {
            $table->timestamp('last_used_at')->nullable();
        });
        $this->addColumn('oauth_clients', 'scopes', function (Blueprint $table): void {
            $table->json('scopes')->nullable();
        });
        $this->addColumn('oauth_auth_codes', 'resource_uri', function (Blueprint $table): void {
            $table->text('resource_uri')->nullable();
        });
        $this->addColumn('oauth_access_tokens', 'resource_uri', function (Blueprint $table): void {
            $table->text('resource_uri')->nullable();
        });
        $this->addColumn('oauth_refresh_tokens', 'resource_uri', function (Blueprint $table): void {
            $table->text('resource_uri')->nullable();
        });
    }

    /**
     * Rollbacks are intentionally a no-op. Because the migration skips columns
     * that an application already owns, a later rollback cannot safely determine
     * which columns it is allowed to remove.
     */
    public function down(): void {}

    /** @param callable(Blueprint): void $definition */
    private function addColumn(string $tableName, string $column, callable $definition): void
    {
        if (! Schema::hasTable($tableName) || Schema::hasColumn($tableName, $column)) {
            return;
        }

        Schema::table($tableName, $definition);
    }
};
