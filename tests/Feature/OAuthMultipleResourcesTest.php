<?php

namespace BWH\Auth\Tests\Feature;

use BWH\Auth\AuthServiceProvider;
use BWH\Auth\Http\Middleware\ExpectOAuthResource;
use BWH\Auth\OAuth\Server\AgentOAuthServer;
use BWH\Auth\OAuth\Server\OAuthProtectedResource;
use BWH\Auth\OAuth\Server\OAuthResourceIndicator;
use BWH\Auth\Testing\AssertsAgentOAuthContract;
use BWH\Auth\Tests\Fixtures\User;
use BWH\Auth\Tests\TestCase;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Foundation\Exceptions\Handler;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use Laravel\Passport\Passport;
use Laravel\Passport\PassportServiceProvider;

/** Several protected resources, each its own audience, metadata document and scope ceiling. */
final class OAuthMultipleResourcesTest extends TestCase
{
    use AssertsAgentOAuthContract;

    private const APP = 'https://app.example.test';

    private const REDIRECT = 'http://127.0.0.1:3210/callback';

    private User $user;

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
            ['mcp:use' => 'Connect through MCP', 'items:read' => 'Read items', 'reports:read' => 'Read reports'],
            [
                'resources' => [
                    'rest' => ['path' => '/api/v1', 'scopes' => ['items:read', 'reports:read']],
                    'mcp' => ['path' => '/api/v1/mcp', 'scopes' => ['mcp:use', 'items:read']],
                    'mcp_alias' => ['path' => '/mcp', 'scopes' => ['mcp:use', 'items:read']],
                ],
                'assume_omitted_resource' => 'rest',
                'resource_required_scopes' => ['mcp:use'],
                'credentials' => ['enabled' => true, 'token_lifetimes' => ['P30D']],
            ],
            self::APP,
        ));
    }

    protected function tearDown(): void
    {
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
        Passport::tokensCan(config('bherila-auth.oauth_server.scopes'));
        AgentOAuthServer::routes();
        Route::get('/api/v1/items', fn () => response()->json(['ok' => 'rest']))->middleware([ExpectOAuthResource::class.':rest', 'auth:api']);
        Route::post('/api/v1/mcp', fn () => response()->json(['ok' => 'mcp']))->middleware([ExpectOAuthResource::class.':mcp', 'auth:api']);
        Route::post('/mcp', fn () => response()->json(['ok' => 'alias']))->middleware([ExpectOAuthResource::class.':mcp_alias', 'auth:api']);

        $handler = $this->app->make(ExceptionHandler::class);
        if ($handler instanceof Handler) {
            $handler->renderable(fn (AuthenticationException $e, $request) => OAuthProtectedResource::unauthenticated($request));
        }
        $this->user = User::query()->create(['name' => 'Person', 'email' => 'person@example.test', 'password' => 'not-used']);
    }

    private function client(string $scope): string
    {
        return (string) $this->postJson('/oauth/register', [
            'client_name' => 'Example agent',
            'redirect_uris' => [self::REDIRECT],
            'grant_types' => ['authorization_code', 'refresh_token'],
            'response_types' => ['code'],
            'token_endpoint_auth_method' => 'none',
            'scope' => $scope,
        ])->assertCreated()->json('client_id');
    }

    /** @return TestResponse<\Symfony\Component\HttpFoundation\Response> the authorize response (a redirect, with a code or an error) */
    private function authorize(string $client, string $scope, ?string $resource, string $verifier, string $rawResourceQuery = ''): TestResponse
    {
        $query = http_build_query(array_filter([
            'response_type' => 'code', 'client_id' => $client, 'redirect_uri' => self::REDIRECT,
            'scope' => $scope, 'state' => 'example-state', 'resource' => $resource,
            'code_challenge' => rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '='),
            'code_challenge_method' => 'S256',
        ], fn ($value) => $value !== null)).$rawResourceQuery;
        $response = $this->actingAs($this->user, 'web')->get('/oauth/authorize?'.$query);

        return $response->isRedirect()
            ? $response
            : $this->actingAs($this->user, 'web')->post('/oauth/authorize', ['auth_token' => (string) session('authToken')]);
    }

    /** @return array{client: string, tokens: array<string, mixed>} */
    private function connect(string $scope, ?string $resource): array
    {
        $client = $this->client($scope);
        $verifier = str_repeat('v', 64);
        $response = $this->authorize($client, $scope, $resource, $verifier);
        $location = (string) $response->headers->get('Location');
        parse_str((string) parse_url($location, PHP_URL_QUERY), $query);
        $this->assertArrayHasKey('code', $query, $location);
        $tokens = $this->post('/oauth/token', array_filter([
            'grant_type' => 'authorization_code', 'client_id' => $client, 'redirect_uri' => self::REDIRECT,
            'code' => $query['code'], 'code_verifier' => $verifier, 'resource' => $resource,
        ]), ['Accept' => 'application/json'])->assertOk()->json();

        return ['client' => $client, 'tokens' => $tokens];
    }

    private function bearer(string $method, string $path, string $token): TestResponse
    {
        $this->app['auth']->forgetGuards();

        return $this->json($method, $path, [], ['Authorization' => 'Bearer '.$token]);
    }

    public function test_each_resource_has_its_own_document_naming_exactly_that_resource(): void
    {
        foreach ([
            '/.well-known/oauth-protected-resource/api/v1' => [self::APP.'/api/v1', ['items:read', 'reports:read']],
            '/.well-known/oauth-protected-resource/api/v1/mcp' => [self::APP.'/api/v1/mcp', ['mcp:use', 'items:read']],
            '/.well-known/oauth-protected-resource/mcp' => [self::APP.'/mcp', ['mcp:use', 'items:read']],
        ] as $path => [$resource, $scopes]) {
            $this->getJson($path)->assertOk()
                ->assertJsonPath('resource', $resource)
                ->assertJsonPath('scopes_supported', $scopes)
                ->assertJsonPath('authorization_servers', [self::APP]);
        }
        $this->getJson('/.well-known/oauth-protected-resource/api/v1/other')->assertNotFound();
        $this->assertSame(self::APP.'/api/v1', config('bherila-auth.oauth_server.resource'), 'The single key names the default resource');
    }

    public function test_every_endpoint_challenge_leads_to_its_own_resource(): void
    {
        $this->assertProtectedResourceChallenge('GET', '/api/v1/items', self::APP.'/api/v1');
        $this->assertProtectedResourceChallenge('POST', '/api/v1/mcp', self::APP.'/api/v1/mcp');
        $this->assertProtectedResourceChallenge('POST', '/mcp', self::APP.'/mcp');
    }

    public function test_an_omitted_resource_binds_to_the_assumed_one_and_only_works_there(): void
    {
        $token = $this->connect('items:read', null)['tokens']['access_token'];

        $this->bearer('GET', '/api/v1/items', $token)->assertOk();
        $this->bearer('POST', '/api/v1/mcp', $token)->assertUnauthorized();
        $this->bearer('POST', '/mcp', $token)->assertUnauthorized();
    }

    public function test_an_endpoint_and_its_alias_are_separate_audiences(): void
    {
        $mcp = $this->connect('mcp:use items:read', self::APP.'/api/v1/mcp')['tokens']['access_token'];
        $this->bearer('POST', '/api/v1/mcp', $mcp)->assertOk()->assertJsonPath('ok', 'mcp');
        $this->bearer('POST', '/mcp', $mcp)->assertUnauthorized();
        $this->bearer('GET', '/api/v1/items', $mcp)->assertUnauthorized();

        $alias = $this->connect('mcp:use', self::APP.'/mcp')['tokens']['access_token'];
        $this->bearer('POST', '/mcp', $alias)->assertOk()->assertJsonPath('ok', 'alias');
        $this->bearer('POST', '/api/v1/mcp', $alias)->assertUnauthorized();
    }

    public function test_a_resource_admits_only_the_scopes_it_lists_while_shared_scopes_fit_both(): void
    {
        $verifier = str_repeat('v', 64);
        $client = $this->client('mcp:use items:read reports:read');

        // The MCP connection scope stays off REST credentials, and REST-only scopes off MCP ones.
        $this->assertStringContainsString('error=invalid_scope',
            (string) $this->authorize($client, 'mcp:use', null, $verifier)->headers->get('Location'));
        $this->assertStringContainsString('error=invalid_scope',
            (string) $this->authorize($client, 'mcp:use reports:read', self::APP.'/api/v1/mcp', $verifier)->headers->get('Location'));

        // A scope listed under both resources is fine on either.
        $this->bearer('GET', '/api/v1/items', $this->connect('items:read', self::APP.'/api/v1')['tokens']['access_token'])->assertOk();
    }

    public function test_one_credential_names_one_resource(): void
    {
        $client = $this->client('items:read');
        $location = (string) $this->authorize($client, 'items:read', self::APP.'/api/v1', str_repeat('v', 64),
            '&resource='.rawurlencode(self::APP.'/api/v1/mcp'))->headers->get('Location');

        $this->assertStringContainsString('error=invalid_target', $location);
    }

    public function test_a_refresh_stays_on_its_resource(): void
    {
        ['client' => $client, 'tokens' => $tokens] = $this->connect('mcp:use', self::APP.'/api/v1/mcp');

        $this->post('/oauth/token', [
            'grant_type' => 'refresh_token', 'client_id' => $client, 'refresh_token' => $tokens['refresh_token'],
            'resource' => self::APP.'/api/v1',
        ], ['Accept' => 'application/json'])->assertStatus(400);

        $refreshed = $this->post('/oauth/token', [
            'grant_type' => 'refresh_token', 'client_id' => $client, 'refresh_token' => $tokens['refresh_token'],
            'resource' => self::APP.'/api/v1/mcp',
        ], ['Accept' => 'application/json'])->assertOk()->json();
        $this->bearer('POST', '/api/v1/mcp', $refreshed['access_token'])->assertOk();
    }

    public function test_a_tightened_ceiling_stops_existing_grants_from_minting_excluded_scopes(): void
    {
        ['client' => $client, 'tokens' => $tokens] = $this->connect('mcp:use items:read', self::APP.'/api/v1/mcp');
        config(['bherila-auth.oauth_server.resources.mcp.scopes' => ['mcp:use']]);

        $this->post('/oauth/token', [
            'grant_type' => 'refresh_token', 'client_id' => $client, 'refresh_token' => $tokens['refresh_token'],
            'resource' => self::APP.'/api/v1/mcp',
        ], ['Accept' => 'application/json'])->assertStatus(400);
        $this->assertFalse((bool) Passport::refreshToken()->newQuery()->sole()->revoked, 'Refused before the grant consumed it');
        $this->bearer('POST', '/api/v1/mcp', $tokens['access_token'])->assertUnauthorized();
    }

    public function test_personal_tokens_bind_to_the_default_resource_and_its_ceiling(): void
    {
        $issued = $this->actingAs($this->user, 'web')->postJson('/account/api-credentials/tokens', [
            'name' => 'Connector', 'scopes' => ['items:read'], 'lifetime' => 'P30D',
        ])->assertCreated()->json('data.token');
        $this->bearer('GET', '/api/v1/items', $issued)->assertOk();
        $this->assertSame(self::APP.'/api/v1', Passport::token()->newQuery()->sole()->resource_uri);

        // Offered only what the REST resource admits; the MCP connection scope is not.
        $offered = array_column($this->actingAs($this->user, 'web')->getJson('/account/api-credentials')->json('data.token_scopes'), 'id');
        $this->assertSame(['items:read', 'reports:read'], $offered);
        $this->actingAs($this->user, 'web')->postJson('/account/api-credentials/tokens', [
            'name' => 'Connection', 'scopes' => ['mcp:use'], 'lifetime' => 'P30D',
        ])->assertUnprocessable();
    }

    public function test_listed_browser_origins_can_reach_every_oauth_machine_endpoint(): void
    {
        config(['bherila-auth.oauth_server.cors.allowed_origins' => ['https://agent.example.test']]);
        $origin = ['Origin' => 'https://agent.example.test'];

        foreach (['/.well-known/oauth-authorization-server', '/.well-known/oauth-protected-resource/api/v1/mcp', '/oauth/register', '/oauth/token'] as $path) {
            $this->call('OPTIONS', $path, [], [], [], ['HTTP_ORIGIN' => 'https://agent.example.test', 'HTTP_ACCESS_CONTROL_REQUEST_METHOD' => 'POST'])
                ->assertNoContent()
                ->assertHeader('Access-Control-Allow-Origin', 'https://agent.example.test')
                ->assertHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
        }
        $this->getJson('/.well-known/oauth-authorization-server', $origin)->assertOk()
            ->assertHeader('Access-Control-Allow-Origin', 'https://agent.example.test');
        $this->getJson('/.well-known/oauth-protected-resource/api/v1/mcp', $origin)->assertOk()
            ->assertHeader('Access-Control-Allow-Origin', 'https://agent.example.test');
        $this->postJson('/oauth/register', ['client_name' => 'x'], $origin)->assertStatus(400)
            ->assertHeader('Access-Control-Allow-Origin', 'https://agent.example.test');
        $this->postJson('/oauth/token', ['grant_type' => 'authorization_code'], $origin)->assertStatus(400)
            ->assertHeader('Access-Control-Allow-Origin', 'https://agent.example.test');
        $this->assertFalse($this->getJson('/.well-known/oauth-authorization-server', $origin)->headers->has('Access-Control-Allow-Credentials'));
    }

    public function test_unlisted_origins_get_no_cors_headers_and_machines_are_unaffected(): void
    {
        config(['bherila-auth.oauth_server.cors.allowed_origins' => ['https://agent.example.test']]);

        $this->getJson('/.well-known/oauth-authorization-server', ['Origin' => 'https://other.example.test'])->assertOk()
            ->assertHeaderMissing('Access-Control-Allow-Origin');
        $this->call('OPTIONS', '/oauth/token', [], [], [], ['HTTP_ORIGIN' => 'https://other.example.test'])->assertForbidden();
        $this->getJson('/.well-known/oauth-authorization-server')->assertOk()->assertHeaderMissing('Access-Control-Allow-Origin');
        // Cacheable either way, so even the header-less answers vary by Origin.
        $this->assertStringContainsString('Origin', (string) $this->getJson('/.well-known/oauth-authorization-server')->headers->get('Vary'));
        $this->assertStringContainsString('Origin', (string) $this->getJson('/.well-known/oauth-authorization-server', ['Origin' => 'https://other.example.test'])->headers->get('Vary'));

        config(['bherila-auth.oauth_server.cors.allowed_origins' => []]);
        $this->getJson('/.well-known/oauth-authorization-server', ['Origin' => 'https://agent.example.test'])
            ->assertHeaderMissing('Access-Control-Allow-Origin');
    }

    public function test_a_resource_at_the_application_root_is_discovered_where_its_challenge_points(): void
    {
        config(['bherila-auth.oauth_server.resources.root' => ['uri' => self::APP]]);

        $this->assertSame('/.well-known/oauth-protected-resource', AgentOAuthServer::protectedResourceMetadataPath('root'));
        $this->assertSame(self::APP.'/.well-known/oauth-protected-resource', OAuthProtectedResource::metadataUrl('root'));
    }

    public function test_a_resource_without_a_ceiling_publishes_the_whole_catalog(): void
    {
        config(['bherila-auth.oauth_server.protected_resource_scopes' => ['items:read']]);
        config(['bherila-auth.oauth_server.resources.open' => ['path' => '/api/open']]);
        config(['bherila-auth.oauth_server.resources.open.uri' => self::APP.'/api/open']);

        $this->assertSame(['mcp:use', 'items:read', 'reports:read'], OAuthProtectedResource::metadata(null, 'open')['scopes_supported']);
    }

    public function test_misconfigured_resources_fail_loudly(): void
    {
        config(['bherila-auth.oauth_server.resources' => [
            'rest' => ['uri' => self::APP.'/api/v1'], 'copy' => ['uri' => self::APP.'/api/v1'],
        ]]);
        $this->expectExceptionMessage('share an identifier');
        OAuthResourceIndicator::resources();
    }

    public function test_a_malformed_scope_ceiling_fails_instead_of_admitting_everything(): void
    {
        config(['bherila-auth.oauth_server.resources.mcp.scopes' => 'mcp:use']);
        $this->expectExceptionMessage('invalid scope list');
        OAuthResourceIndicator::resources();
    }
}
