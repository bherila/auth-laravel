<?php

namespace BWH\Auth\Tests\Feature;

use BWH\Auth\Http\Middleware\RequireActiveProviderSession;
use BWH\Auth\OAuth\Server\ProviderIdentityTokens;
use BWH\Auth\OAuth\Session\ProviderIdentityEnforcement;
use BWH\Auth\Tests\Fixtures\User;
use BWH\Auth\Tests\TestCase;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;

/** A recorded cutover keeps provider lifecycle enforcement on whatever the configuration says. */
class ProviderIdentityCutoverTest extends TestCase
{
    protected function defineDatabaseMigrations(): void
    {
        parent::defineDatabaseMigrations();

        Schema::table('users', function (Blueprint $table): void {
            $table->string('oauth_provider')->nullable();
            $table->string('oauth_subject')->nullable();
        });
    }

    protected function setUp(): void
    {
        parent::setUp();
        config(['app.env' => 'testing']);
        config(['bherila-auth.oauth_client' => [
            'provider' => 'example-provider',
            'base_url' => 'https://identity.example.test',
            'client_id' => 'example-client',
            'client_secret' => 'example-secret',
            'redirect_uri' => 'https://app.example.test/oauth/callback',
            'token_path' => '/oauth/token',
            'identity_path' => '/api/oauth/user',
        ]]);
        config(['bherila-auth.provider_identity.enabled' => true]);
        $this->travelTo(Carbon::parse('2026-01-01T00:00:00Z'));
        Http::preventStrayRequests();

        Route::middleware(['web', RequireActiveProviderSession::class])->get('/private', fn () => 'ok');
    }

    public function test_without_a_cutover_enforcement_follows_the_setting(): void
    {
        config(['bherila-auth.provider_identity.enabled' => false]);
        Http::fake();

        $this->actingAs($this->user())->getJson('/private')->assertOk();
        $this->assertFalse($this->enforcement()->enabled());
        Http::assertNothingSent();
    }

    public function test_a_recorded_cutover_keeps_enforcement_on_when_the_setting_is_turned_off(): void
    {
        $this->artisan('bherila-auth:provider-identity-cutover', ['action' => 'record'])->assertSuccessful();
        $this->assertDatabaseHas(ProviderIdentityEnforcement::TABLE, ['id' => 1, 'provider' => 'example-provider', 'withdrawn_at' => null]);

        config(['bherila-auth.provider_identity.enabled' => false]);
        Http::fake();

        // A session with no provider baseline is ended, as it is with the setting on.
        $this->actingAs($this->user())->getJson('/private')->assertStatus(401);
        $this->assertTrue($this->enforcement()->enabled());
        $this->assertTrue(ProviderIdentityTokens::enabled(), 'Bearer credentials are held to the same lock.');
    }

    public function test_recording_refuses_a_configuration_that_is_not_already_enforcing(): void
    {
        config(['bherila-auth.provider_identity.enabled' => false]);
        $this->artisan('bherila-auth:provider-identity-cutover', ['action' => 'record'])->assertFailed();

        config(['bherila-auth.provider_identity.enabled' => true, 'bherila-auth.oauth_client.client_secret' => '']);
        $this->artisan('bherila-auth:provider-identity-cutover', ['action' => 'record'])->assertFailed();

        $this->assertSame(0, DB::table(ProviderIdentityEnforcement::TABLE)->count());
    }

    public function test_recording_twice_keeps_the_first_record(): void
    {
        $this->artisan('bherila-auth:provider-identity-cutover', ['action' => 'record'])->assertSuccessful();
        $this->travel(5)->minutes();
        $this->artisan('bherila-auth:provider-identity-cutover', ['action' => 'record'])->assertSuccessful();

        $this->assertSame('2026-01-01 00:00:00', (string) DB::table(ProviderIdentityEnforcement::TABLE)->value('recorded_at'));
    }

    public function test_check_fails_a_deploy_whose_configuration_disagrees_with_the_cutover(): void
    {
        $this->artisan('bherila-auth:provider-identity-cutover', ['action' => 'check'])->assertSuccessful();
        $this->artisan('bherila-auth:provider-identity-cutover', ['action' => 'record'])->assertSuccessful();
        $this->artisan('bherila-auth:provider-identity-cutover', ['action' => 'check'])->assertSuccessful();

        config(['bherila-auth.provider_identity.enabled' => false]);
        $this->artisan('bherila-auth:provider-identity-cutover', ['action' => 'check'])->assertFailed();

        config(['bherila-auth.provider_identity.enabled' => true, 'bherila-auth.oauth_client.base_url' => null]);
        $this->artisan('bherila-auth:provider-identity-cutover', ['action' => 'check'])->assertFailed();
    }

    public function test_only_a_confirmed_withdrawal_hands_enforcement_back_to_the_setting(): void
    {
        $this->artisan('bherila-auth:provider-identity-cutover', ['action' => 'record'])->assertSuccessful();
        config(['bherila-auth.provider_identity.enabled' => false]);

        $this->artisan('bherila-auth:provider-identity-cutover', ['action' => 'withdraw'])
            ->expectsConfirmation('Withdraw the provider identity cutover?', 'no')
            ->assertFailed();
        $this->assertTrue($this->enforcement()->enabled());

        $this->artisan('bherila-auth:provider-identity-cutover', ['action' => 'withdraw', '--force' => true])->assertSuccessful();

        $this->assertNotNull(DB::table(ProviderIdentityEnforcement::TABLE)->value('withdrawn_at'), 'The record is kept, marked withdrawn.');
        $this->assertFalse($this->enforcement()->enabled());
        Http::fake();
        $this->actingAs($this->user())->getJson('/private')->assertOk();
    }

    public function test_a_cutover_recorded_by_another_process_is_seen_within_a_minute(): void
    {
        config(['bherila-auth.provider_identity.enabled' => false]);
        $this->assertFalse($this->enforcement()->enabled());

        DB::table(ProviderIdentityEnforcement::TABLE)->insert([
            'id' => 1, 'provider' => 'example-provider', 'recorded_at' => now(), 'withdrawn_at' => null,
            'created_at' => now(), 'updated_at' => now(),
        ]);
        $this->travel(30)->seconds();
        $this->assertFalse($this->enforcement()->enabled(), 'Read at most once a minute per process.');

        $this->travel(31)->seconds();
        $this->assertTrue($this->enforcement()->enabled());
    }

    public function test_an_installation_without_the_table_has_no_cutover(): void
    {
        Schema::drop(ProviderIdentityEnforcement::TABLE);
        config(['bherila-auth.provider_identity.enabled' => false]);

        $this->assertFalse($this->enforcement()->enabled());
        $this->artisan('bherila-auth:provider-identity-cutover', ['action' => 'status'])->assertSuccessful();
        config(['bherila-auth.provider_identity.enabled' => true]);
        $this->artisan('bherila-auth:provider-identity-cutover', ['action' => 'record'])->assertFailed();
    }

    public function test_the_check_reads_the_row_and_never_the_schema_catalog(): void
    {
        config(['bherila-auth.provider_identity.enabled' => false]);
        $present = $this->queriesDuring(fn () => $this->assertFalse($this->enforcement()->enabled()));
        Schema::drop(ProviderIdentityEnforcement::TABLE);
        $this->enforcement()->forget();
        $absent = $this->queriesDuring(fn () => $this->assertFalse($this->enforcement()->enabled()));

        foreach ([...$present, ...$absent] as $sql) {
            $this->assertStringNotContainsString('sqlite_master', $sql);
            $this->assertStringNotContainsString('pragma_table', $sql);
            $this->assertStringNotContainsString('information_schema', $sql);
        }
        $this->assertCount(1, $present);
    }

    public function test_a_missing_table_inside_a_transaction_leaves_the_transaction_usable(): void
    {
        Schema::drop(ProviderIdentityEnforcement::TABLE);
        config(['bherila-auth.provider_identity.enabled' => false]);

        DB::transaction(function (): void {
            $this->assertFalse($this->enforcement()->enabled());
            DB::table('users')->insert([
                'name' => 'After the check', 'email' => 'after@example.test', 'password' => 'unused',
            ]);
        });
        $this->assertDatabaseHas('users', ['email' => 'after@example.test']);
    }

    public function test_an_unknown_action_is_refused(): void
    {
        $this->artisan('bherila-auth:provider-identity-cutover', ['action' => 'disable'])->assertFailed();
    }

    /** @return list<string> */
    private function queriesDuring(callable $callback): array
    {
        DB::connection()->flushQueryLog();
        DB::connection()->enableQueryLog();
        try {
            $callback();
        } finally {
            $queries = DB::connection()->getQueryLog();
            DB::connection()->disableQueryLog();
        }

        return array_map(static fn (array $query): string => strtolower((string) $query['query']), $queries);
    }

    private function enforcement(): ProviderIdentityEnforcement
    {
        return app(ProviderIdentityEnforcement::class);
    }

    private function user(): User
    {
        return User::query()->create([
            'name' => 'Example User', 'email' => uniqid('user-', true).'@example.test', 'password' => 'unused',
            'oauth_provider' => 'example-provider', 'oauth_subject' => 'subject-example',
        ]);
    }
}
