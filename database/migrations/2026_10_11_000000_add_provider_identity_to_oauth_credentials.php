<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * The provider subject and credential generation an authorization code or access
     * token was issued under (refresh tokens use their access token's). Nullable: rows
     * issued before this migration have none, and are retired rather than upgraded once
     * provider identity enforcement is enabled. Adds only absent columns, like the
     * OAuth server metadata migration, so it is safe beside application-owned columns.
     */
    public function up(): void
    {
        foreach (['oauth_auth_codes', 'oauth_access_tokens'] as $table) {
            $this->addColumn($table, 'provider_subject', function (Blueprint $blueprint): void {
                $blueprint->string('provider_subject', 191)->nullable();
            });
            $this->addColumn($table, 'provider_generation', function (Blueprint $blueprint): void {
                $blueprint->unsignedBigInteger('provider_generation')->nullable();
            });
        }
    }

    /** Intentionally a no-op, for the same reason as the OAuth server metadata migration. */
    public function down(): void
    {
    }

    /** @param callable(Blueprint): void $definition */
    private function addColumn(string $tableName, string $column, callable $definition): void
    {
        if (! Schema::hasTable($tableName) || Schema::hasColumn($tableName, $column)) {
            return;
        }

        Schema::table($tableName, $definition);
    }
};
