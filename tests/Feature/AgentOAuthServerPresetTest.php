<?php

namespace BWH\Auth\Tests\Feature;

use BWH\Auth\AuthServiceProvider;
use BWH\Auth\Http\Middleware\EnforceOAuthPkce;
use BWH\Auth\Http\Middleware\EnforceOAuthResourceIndicator;
use BWH\Auth\Http\Middleware\EnsureOAuthServerEnabled;
use BWH\Auth\Http\Middleware\ExpectOAuthResource;
use BWH\Auth\OAuth\Server\AgentOAuthServer;
use BWH\Auth\OAuth\Server\OAuthResourceIndicator;
use BWH\Auth\Tests\Fixtures\User;
use BWH\Auth\Tests\TestCase;
use Illuminate\Support\Facades\Route;
use Laravel\Passport\ClientRepository;
use Laravel\Passport\Passport;
use Laravel\Passport\PassportServiceProvider;

/**
 * The agent-API profile from one call, exercised end to end the way a generic
 * connector uses it: self-registration or a person-registered confidential
 * app, PKCE, and no `resource` parameter anywhere.
 */
final class AgentOAuthServerPresetTest extends TestCase
{
    private const APP = 'https://app.example.test';

    private const REDIRECT = 'https://client.example.test/callback';

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
        $app['config']->set('bherila-auth.oauth_server', AgentOAuthServer::config(
            ['mcp:use' => 'Connect through MCP', 'items:read' => 'Read items', 'items:write' => 'Write items'],
            ['resource_required_scopes' => ['mcp:use']],
            self::APP,
        ));
    }

    protected function defineDatabaseMigrations(): void
    {
        $this->loadMigrationsFrom(__DIR__.'/../../vendor/laravel/passport/database/migrations');
        parent::defineDatabaseMigrations();
    }

    protected function tearDown(): void
    {
        // Passport's scope registry is process-wide; never leak this catalog.
        Passport::tokensCan([]);
        parent::tearDown();
    }

    protected function setUp(): void
    {
        parent::setUp();
        // No Passport setup here: the preset must complete it (scopes, consent view, no device grant).
        AgentOAuthServer::routes();
        Route::get('/api/v1/ping', fn () => response()->json(['ok' => true]))->middleware([ExpectOAuthResource::class, 'auth:api']);
    }

    public function test_the_preset_derives_every_url_from_the_application_and_accepts_overrides(): void
    {
        $config = AgentOAuthServer::config(['a' => 'A'], [
            'token_endpoint_auth_methods' => ['none'],
            'consent' => ['app_name' => 'Example'],
        ], 'https://fork.example.test/');

        $this->assertSame('https://fork.example.test', $config['issuer']);
        $this->assertSame('https://fork.example.test/api/v1', $config['resource']);
        $this->assertSame('https://fork.example.test/oauth/register', $config['registration_endpoint']);
        $this->assertTrue($config['assume_omitted_resource']);
        $this->assertSame(['none'], $config['token_endpoint_auth_methods'], 'An overriding list replaces the preset list');
        $this->assertSame(['app_name' => 'Example'], $config['consent']);
        $this->assertSame([EnsureOAuthServerEnabled::class, EnforceOAuthPkce::class, EnforceOAuthResourceIndicator::class, 'x'], AgentOAuthServer::passportMiddleware(['x']));
    }

    /** RFC 9728: the well-known segment goes before the path of a path-mounted resource. */
    public function test_a_path_mounted_deployment_gets_the_rfc_well_known_url(): void
    {
        $config = AgentOAuthServer::config(['a' => 'A'], [], 'https://fork.example.test/tenant');

        $this->assertSame('https://fork.example.test/tenant/api/v1', $config['resource']);
        $this->assertSame('https://fork.example.test/.well-known/oauth-protected-resource/tenant/api/v1', $config['protected_resource_metadata_url']);
        $this->assertSame('https://h.example.test:8443/.well-known/oauth-authorization-server', AgentOAuthServer::wellKnown('https://h.example.test:8443', 'oauth-authorization-server'));
    }

    /** RFC 9728: the document is served only where its `resource` matches the discovery URL. */
    public function test_protected_resource_metadata_is_served_only_at_the_matching_path(): void
    {
        $this->getJson('/.well-known/oauth-protected-resource/api/v1')->assertOk()->assertJsonPath('resource', self::APP.'/api/v1');
        $this->getJson('/.well-known/oauth-protected-resource')->assertNotFound();
        $this->getJson('/.well-known/oauth-protected-resource/api/v1/mcp')->assertNotFound();
    }

    /** Everything a fresh application needs comes from the preset itself. */
    public function test_the_preset_completes_the_passport_side_on_its_own(): void
    {
        $this->assertFalse(Passport::$deviceCodeGrantEnabled, 'The device grant bypasses the PKCE gate');
        $this->assertNull(Route::getRoutes()->getByName('passport.device'));
        $this->assertTrue(Passport::hasScope('items:read'));
        $this->assertTrue(app()->bound(\Laravel\Passport\Contracts\AuthorizationViewResponse::class));
    }

    public function test_the_metadata_url_follows_an_overridden_resource_and_a_path_issuer(): void
    {
        $config = AgentOAuthServer::config(['a' => 'A'], ['resource' => 'https://app.example.test/agent'], self::APP);
        $this->assertSame('https://app.example.test/.well-known/oauth-protected-resource/agent', $config['protected_resource_metadata_url']);

        $pinned = AgentOAuthServer::config(['a' => 'A'], ['protected_resource_metadata_url' => 'https://x.example.test/meta'], self::APP);
        $this->assertSame('https://x.example.test/meta', $pinned['protected_resource_metadata_url'], 'An explicit URL is kept');

        config(['bherila-auth.oauth_server.issuer' => self::APP.'/tenant']);
        AgentOAuthServer::routes();
        $this->assertNotNull(Route::getRoutes()->match(\Illuminate\Http\Request::create('/.well-known/oauth-authorization-server/tenant')));
    }

    public function test_discovery_advertises_the_profile(): void
    {
        $this->getJson('/.well-known/oauth-authorization-server')->assertOk()
            ->assertJsonPath('issuer', self::APP)
            ->assertJsonPath('registration_endpoint', self::APP.'/oauth/register')
            ->assertJsonPath('token_endpoint_auth_methods_supported', ['none', 'client_secret_basic', 'client_secret_post'])
            ->assertJsonPath('code_challenge_methods_supported', ['S256']);
        $this->getJson('/.well-known/oauth-protected-resource/api/v1')->assertOk()
            ->assertJsonPath('resource', self::APP.'/api/v1');
    }

    public function test_a_self_registered_client_completes_the_flow_without_a_resource_parameter(): void
    {
        $user = User::query()->create(['name' => 'Agent User', 'email' => 'agent@example.test', 'password' => 'not-used']);
        $clientId = $this->postJson('/oauth/register', [
            'client_name' => 'Generic connector',
            'redirect_uris' => [self::REDIRECT],
            'grant_types' => ['authorization_code', 'refresh_token'],
            'response_types' => ['code'],
            'token_endpoint_auth_method' => 'none',
            'scope' => 'mcp:use items:read',
        ])->assertCreated()->assertJsonMissingPath('client_secret')->json('client_id');

        $tokens = $this->codeFlow($user, $clientId, 'mcp:use items:read')->assertOk()->json();
        $this->assertSame(self::APP.'/api/v1', OAuthResourceIndicator::tokenClaims($tokens['access_token'])['resource'] ?? null);
        $this->getJson('/api/v1/ping', ['Authorization' => 'Bearer '.$tokens['access_token']])->assertOk();

        $refreshed = $this->post('/oauth/token', [
            'grant_type' => 'refresh_token', 'client_id' => $clientId, 'refresh_token' => $tokens['refresh_token'],
        ], ['Accept' => 'application/json'])->assertOk()->json();
        $this->assertSame(self::APP.'/api/v1', OAuthResourceIndicator::tokenClaims($refreshed['access_token'])['resource'] ?? null);
    }

    public function test_a_person_registered_confidential_client_authenticates_with_its_secret(): void
    {
        $user = User::query()->create(['name' => 'Agent User', 'email' => 'secret@example.test', 'password' => 'not-used']);
        $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('Registered connector', [self::REDIRECT], confidential: true);
        $client->forceFill(['scopes' => ['items:read']])->save();

        $this->codeFlow($user, (string) $client->getKey(), 'items:read', ['client_secret' => $client->plainSecret])->assertOk();
        $this->codeFlow($user, (string) $client->getKey(), 'items:read', ['client_secret' => 'wrong'])->assertUnauthorized();
    }

    public function test_pkce_is_required_and_a_different_explicit_resource_is_refused(): void
    {
        $user = User::query()->create(['name' => 'Agent User', 'email' => 'strict@example.test', 'password' => 'not-used']);
        $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('Strict', [self::REDIRECT], confidential: false);

        $this->actingAs($user)->get('/oauth/authorize?'.http_build_query([
            'response_type' => 'code', 'client_id' => $client->getKey(), 'redirect_uri' => self::REDIRECT, 'scope' => 'items:read',
        ]))->assertStatus(400);

        $wrong = $this->actingAs($user)->get('/oauth/authorize?'.http_build_query([
            'response_type' => 'code', 'client_id' => $client->getKey(), 'redirect_uri' => self::REDIRECT, 'scope' => 'items:read',
            'code_challenge' => str_repeat('a', 43), 'code_challenge_method' => 'S256', 'resource' => 'https://other.example.test/api/v1',
        ]));
        $this->assertStringContainsString('error=invalid_target', (string) $wrong->headers->get('Location'));
    }

    /** @param array<string, string> $tokenExtras */
    private function codeFlow(User $user, string $clientId, string $scope, array $tokenExtras = []): \Illuminate\Testing\TestResponse
    {
        $verifier = rtrim(strtr(base64_encode(random_bytes(48)), '+/', '-_'), '=');
        $authorize = $this->actingAs($user)->get('/oauth/authorize?'.http_build_query([
            'response_type' => 'code',
            'client_id' => $clientId,
            'redirect_uri' => self::REDIRECT,
            'scope' => $scope,
            'code_challenge' => rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '='),
            'code_challenge_method' => 'S256',
        ]));
        // Passport approves without asking again when these scopes were already granted.
        $approval = $authorize->isRedirect()
            ? $authorize
            : $this->actingAs($user)->post('/oauth/authorize', ['auth_token' => (string) session('authToken')])->assertRedirect();
        parse_str((string) parse_url((string) $approval->headers->get('Location'), PHP_URL_QUERY), $query);
        $this->assertArrayHasKey('code', $query);

        return $this->post('/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => $clientId,
            'redirect_uri' => self::REDIRECT,
            'code' => $query['code'] ?? '',
            'code_verifier' => $verifier,
            ...$tokenExtras,
        ], ['Accept' => 'application/json']);
    }
}
