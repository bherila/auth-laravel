<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    private function table(): string
    {
        return (string) config('bherila-auth.passkeys.table', 'auth_passkeys');
    }

    /**
     * Records the WebAuthn backup-eligible flag, which is fixed for a credential.
     *
     * Existing rows stay NULL, meaning "enrolled before this was recorded". The flag is
     * recorded at that credential's next verified assertion.
     */
    public function up(): void
    {
        if (Schema::hasTable($this->table()) && ! Schema::hasColumn($this->table(), 'backup_eligible')) {
            Schema::table($this->table(), function (Blueprint $table): void {
                $table->boolean('backup_eligible')->nullable();
            });
        }
    }

    public function down(): void
    {
        if (Schema::hasTable($this->table()) && Schema::hasColumn($this->table(), 'backup_eligible')) {
            Schema::table($this->table(), function (Blueprint $table): void {
                $table->dropColumn('backup_eligible');
            });
        }
    }
};
