<?php

use BWH\Auth\OAuth\DelegatedAccess\DatabaseReceiptStore;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        if (Schema::hasTable(DatabaseReceiptStore::TABLE)) {
            return;
        }

        Schema::create(DatabaseReceiptStore::TABLE, function (Blueprint $table) {
            $table->string('application', 191);
            // The key is a digest of the operation id: ids are case-sensitive, and a case-insensitive
            // collation (common on MySQL and MariaDB) would otherwise make `ABC…` and `abc…` one.
            $table->string('operation_key', 64);
            $table->string('operation_id', 64);
            $table->string('actor', 64);
            $table->string('request_hash', 64);
            // Null while the adapter is deciding; then the status and exact body that were sent.
            $table->unsignedSmallInteger('status')->nullable();
            $table->mediumText('response')->nullable();
            // When the current claim was taken; an unfinished claim older than the lease may be retaken.
            $table->unsignedBigInteger('claimed_at');
            $table->unsignedBigInteger('created_at')->index();

            // One request per operation reaches the adapter: this key is what decides which.
            $table->primary(['application', 'operation_key']);
        });
    }

    public function down(): void
    {
        // Deliberately retain receipts through application rollback: a provider may still ask for one.
    }
};
