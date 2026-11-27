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

    public function up(): void
    {
        if (Schema::hasTable($this->table()) && ! Schema::hasColumn($this->table(), 'recipient_hash')) {
            Schema::table($this->table(), function (Blueprint $table): void {
                // Legacy attempts prove no destination; their codes still work.
                $table->string('recipient_hash', 64)->nullable();
            });
        }
    }

    public function down(): void
    {
        if (Schema::hasTable($this->table()) && Schema::hasColumn($this->table(), 'recipient_hash')) {
            Schema::table($this->table(), function (Blueprint $table): void {
                $table->dropColumn('recipient_hash');
            });
        }
    }
};
