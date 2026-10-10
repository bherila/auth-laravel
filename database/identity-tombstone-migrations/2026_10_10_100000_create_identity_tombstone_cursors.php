<?php

use BWH\Auth\OAuth\Lifecycle\IdentityTombstoneCursorStore;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        // The connection the cursor store uses (bherila-auth.identity_tombstones.connection),
        // which may not be the default one.
        $schema = Schema::connection(config('bherila-auth.identity_tombstones.connection'));
        if ($schema->hasTable(IdentityTombstoneCursorStore::table())) {
            return;
        }

        $schema->create(IdentityTombstoneCursorStore::table(), function (Blueprint $table) {
            // A digest of the provider base URL, provider name and client id: cursors belong to one client.
            $table->string('context', 64)->primary();
            // The provider's opaque next_cursor, which it caps at 512 characters; null starts from the oldest.
            $table->string('cursor', 512)->nullable();
            // The run consuming the feed, and when its lease lapses (unix seconds).
            $table->string('lease_owner', 32)->nullable();
            $table->unsignedBigInteger('lease_expires_at')->default(0);
            $table->unsignedBigInteger('updated_at');
        });
    }

    public function down(): void
    {
        // Deliberately retain the cursor and lease through application rollback: dropping the
        // table under a running consumer would release its lease to a second run.
    }
};
