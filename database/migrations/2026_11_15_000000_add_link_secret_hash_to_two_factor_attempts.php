<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    private function table(): string
    {
        return (string) config('bherila-auth.two_factor.table', 'auth_two_factor_attempts');
    }

    /**
     * The SHA-256 of the secret the emailed confirm and report links carry.
     *
     * The attempt token is not enough to complete a sign-in from the email: it is handed to
     * the browser that passed the password step. Existing rows stay NULL, so their links stop
     * working and the emailed code still does.
     */
    public function up(): void
    {
        if (Schema::hasTable($this->table()) && ! Schema::hasColumn($this->table(), 'link_secret_hash')) {
            Schema::table($this->table(), function (Blueprint $table): void {
                $table->string('link_secret_hash', 64)->nullable();
            });
        }
    }

    public function down(): void
    {
        if (Schema::hasTable($this->table()) && Schema::hasColumn($this->table(), 'link_secret_hash')) {
            Schema::table($this->table(), function (Blueprint $table): void {
                $table->dropColumn('link_secret_hash');
            });
        }
    }
};
