<?php

namespace BWH\Auth\Tests\Feature;

use BWH\Auth\AuthServiceProvider;
use BWH\Auth\Http\Middleware\ExpectOAuthResource;
use BWH\Auth\OAuth\Server\AgentOAuthServer;
use BWH\Auth\Testing\AssertsAgentOAuthContract;
use BWH\Auth\Tests\Fixtures\User;
use BWH\Auth\Tests\TestCase;
use Illuminate\Support\Facades\Route;
use Laravel\Passport\ClientRepository;
use Laravel\Passport\Passport;
use Laravel\Passport\PassportServiceProvider;

/** The contract-test trait, used as an application would, and the dynamic-client prune. */
final class AgentOAuthOpsTest extends TestCase
{
    use AssertsAgentOAuthContract;

    private const APP = 'https://app.example.test';

    protected function getPackageProviders($app): array
    {
        return [AuthServiceProvider::class, PassportServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);
        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        $private = '';
        openssl_pkey_export($key, $private);
        $app['config']->set('app.url', self::APP);
        $app['config']->set('passport.private_key', $private);
        $app['config']->set('passport.public_key', openssl_pkey_get_details($key)['key']);
        $app['config']->set('passport.middleware', AgentOAuthServer::passportMiddleware(['web']));
        $app['config']->set('auth.guards.api', ['driver' => 'passport', 'provider' => 'users']);
        $app['config']->set('bherila-auth.oauth_server', AgentOAuthServer::config(['items:read' => 'Read items'], [
            'dynamic_clients' => ['last_used_at_column' => 'last_used_at', 'retention_days' => 30],
        ], self::APP));
    }

    protected function tearDown(): void
    {
        // Passport's scope registry is process-wide; never leak this catalog.
        Passport::tokensCan([]);
        parent::tearDown();
    }

    protected function defineDatabaseMigrations(): void
    {
        $this->loadMigrationsFrom(__DIR__.'/../../vendor/laravel/passport/database/migrations');
        parent::defineDatabaseMigrations();
    }

    protected function setUp(): void
    {
        parent::setUp();
        // The preset completes the Passport side itself.
        AgentOAuthServer::routes();
        Route::get('/api/v1/items', fn () => response()->json(['ok' => true]))->middleware([ExpectOAuthResource::class, 'auth:api']);
    }

    public function test_the_contract_trait_drives_discovery_and_the_full_lifecycle(): void
    {
        $this->assertAgentOAuthDiscovery();
        $user = User::query()->create(['name' => 'Agent', 'email' => 'agent@example.test', 'password' => 'not-used']);
        $tokens = $this->assertAgentOAuthLifecycle($user, 'items:read', '/api/v1/items');
        $this->assertArrayHasKey('access_token', $tokens);
    }

    public function test_prune_removes_only_stale_unused_dynamic_clients(): void
    {
        $repository = app(ClientRepository::class);
        $stale = $repository->createAuthorizationCodeGrantClient('Stale', ['https://c.example.test/cb'], confidential: false);
        $stale->forceFill(['dynamically_registered_at' => now()->subDays(40), 'last_used_at' => null])->save();
        $recent = $repository->createAuthorizationCodeGrantClient('Recent', ['https://c.example.test/cb'], confidential: false);
        $recent->forceFill(['dynamically_registered_at' => now()->subDays(40), 'last_used_at' => now()->subDays(2)])->save();
        $live = $repository->createAuthorizationCodeGrantClient('Live token', ['https://c.example.test/cb'], confidential: false);
        $live->forceFill(['dynamically_registered_at' => now()->subDays(40)])->save();
        Passport::token()->newQuery()->forceCreate([
            'id' => 'live-token', 'user_id' => null, 'client_id' => $live->getKey(), 'name' => null, 'scopes' => '[]', 'revoked' => false, 'expires_at' => now()->addDay(),
        ]);
        $registered = $repository->createAuthorizationCodeGrantClient('Person registered', ['https://c.example.test/cb'], confidential: true);

        $this->artisan('bherila-auth:prune-dynamic-clients', ['--pretend' => true])->expectsOutputToContain('Would prune 1')->assertExitCode(0);
        $this->assertNotNull(Passport::client()->newQuery()->find($stale->getKey()));

        $this->artisan('bherila-auth:prune-dynamic-clients')->expectsOutputToContain('Pruned 1')->assertExitCode(0);
        $this->assertNull(Passport::client()->newQuery()->find($stale->getKey()));
        foreach ([$recent, $live, $registered] as $kept) {
            $this->assertNotNull(Passport::client()->newQuery()->find($kept->getKey()), $kept->name);
        }
        $this->artisan('bherila-auth:prune-dynamic-clients', ['--days' => '0'])->assertExitCode(2);
    }
}
