<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * One row per session guard and account: the provider login generation that account's
     * remember-me token was issued under. A session restored from the remember-me cookie takes
     * its provider baseline from here, so provider lifecycle enforcement keeps checking it
     * instead of ending it for want of a baseline. The token is stored only as a SHA-256 hash.
     * The table is named by BWH\Auth\OAuth\Session\RememberedProviderLogins::TABLE.
     */
    public function up(): void
    {
        if (Schema::hasTable('provider_remembered_logins')) {
            return;
        }
        Schema::create('provider_remembered_logins', function (Blueprint $table): void {
            $table->id();
            // Illuminate\Auth\SessionGuard::getName(): one key per configured guard.
            $table->string('guard', 191);
            // The account's auth identifier, as a string so any identifier type fits.
            $table->string('user_id', 191);
            $table->string('provider', 64);
            $table->string('subject', 191);
            $table->unsignedBigInteger('generation');
            $table->char('token_hash', 64);
            $table->dateTime('recorded_at');
            $table->unique(['guard', 'user_id'], 'provider_remembered_logins_guard_user');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('provider_remembered_logins');
    }
};
