<?php

use BWH\Auth\OAuth\DelegatedAccess\DatabaseNonceStore;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        $schema = Schema::connection(config('bherila-auth.delegated_access.nonce_connection'));
        if ($schema->hasTable(DatabaseNonceStore::TABLE)) {
            return;
        }

        $schema->create(DatabaseNonceStore::TABLE, function (Blueprint $table) {
            $table->string('key', 64)->primary();
            $table->unsignedBigInteger('expires_at')->index();
        });
    }

    public function down(): void
    {
        // Deliberately retain consumed nonces through application rollback.
    }
};
