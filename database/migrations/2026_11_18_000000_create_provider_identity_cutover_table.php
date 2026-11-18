<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * At most one row: this installation's provider identity cutover. While it is recorded and
     * not withdrawn, provider lifecycle enforcement stays on whatever the configuration says.
     * Lives in the application's database so neither a configuration rollback nor redeploying
     * an older environment file can turn enforcement off. The table is named by
     * BWH\Auth\OAuth\Session\ProviderIdentityEnforcement::TABLE.
     */
    public function up(): void
    {
        if (Schema::hasTable('provider_identity_cutover')) {
            return;
        }
        Schema::create('provider_identity_cutover', function (Blueprint $table): void {
            $table->unsignedTinyInteger('id')->primary();
            $table->string('provider', 64);
            $table->timestamp('recorded_at');
            $table->timestamp('withdrawn_at')->nullable();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('provider_identity_cutover');
    }
};
