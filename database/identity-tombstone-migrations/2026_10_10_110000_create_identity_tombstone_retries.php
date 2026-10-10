<?php

use BWH\Auth\OAuth\Lifecycle\IdentityTombstoneRetryStore;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        // The same connection as the cursor table (bherila-auth.identity_tombstones.connection).
        $schema = Schema::connection(config('bherila-auth.identity_tombstones.connection'));
        if ($schema->hasTable(IdentityTombstoneRetryStore::table())) {
            return;
        }

        $schema->create(IdentityTombstoneRetryStore::table(), function (Blueprint $table) {
            // The provider/client context, as in the cursor table: tombstones belong to one client.
            $table->string('context', 64);
            // Stored lower-case: the provider treats ids case-insensitively, and so must the key.
            $table->string('tombstone_id', 36);
            $table->string('provider', 191);
            // The opaque OAuth subject, needed to call the handler again without the feed.
            $table->string('subject', 255);
            // The provider's timestamps (unix seconds); rows are dropped once purge_after passes.
            $table->unsignedBigInteger('tombstoned_at');
            $table->unsignedBigInteger('purge_after')->index();
            $table->unsignedBigInteger('provider_purged_at')->nullable();
            $table->unsignedInteger('attempts');
            $table->unsignedBigInteger('last_attempt_at');

            $table->primary(['context', 'tombstone_id']);
        });
    }

    public function down(): void
    {
        // Deliberately retain pending retries through application rollback: dropping them would
        // silently delay those deletions until the feed cycles back to them.
    }
};
