<?php

use BWH\Auth\OAuth\DelegatedAccess\DatabaseNonceStore;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        if (Schema::hasTable(DatabaseNonceStore::TABLE)) {
            return;
        }

        Schema::create(DatabaseNonceStore::TABLE, function (Blueprint $table) {
            $table->string('key', 64)->primary();
            $table->unsignedBigInteger('expires_at')->index();
        });
    }

    public function down(): void
    {
        // Deliberately retain consumed nonces through application rollback.
    }
};
