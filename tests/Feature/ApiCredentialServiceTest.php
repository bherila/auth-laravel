<?php

namespace BWH\Auth\Tests\Feature;

use BWH\Auth\AuthServiceProvider;
use BWH\Auth\OAuth\Credentials\ApiCredentialService;
use BWH\Auth\OAuth\Server\AgentOAuthServer;
use BWH\Auth\OAuth\Server\OAuthResourceIndicator;
use BWH\Auth\Http\Middleware\ExpectOAuthResource;
use BWH\Auth\Tests\Fixtures\User;
use BWH\Auth\Tests\TestCase;
use Illuminate\Support\Facades\Route;
use Laravel\Passport\Http\Middleware\CheckToken;
use Laravel\Passport\Passport;
use Laravel\Passport\PassportServiceProvider;

/**
 * A person's REST credentials: personal API tokens and OAuth apps.
 *
 * Each must reach the protected API with exactly the permissions chosen, be
 * bound to that resource, travel once in a no-store body, be revocable, stay
 * out of anyone else's reach - and never be mintable by an OAuth credential.
 */
final class ApiCredentialServiceTest extends TestCase
{
    private const APP = 'https://app.example.test';

    private const REDIRECT = 'http://127.0.0.1:3210/callback';

    private const BASE = '/account/api-credentials';

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
            ['mcp:use' => 'Connect through MCP', 'items:read' => 'Read items', 'items:write' => 'Write items', 'admin:all' => 'Administer'],
            [
                'resource_required_scopes' => ['mcp:use'],
                'credentials' => [
                    'enabled' => true,
                    'token_lifetimes' => ['PT4H', 'P30D', 'P90D'],
                    'excluded_scopes' => ['admin:all'],
                ],
            ],
            self::APP,
        ));
        Passport::$deviceCodeGrantEnabled = false;
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
        Passport::defaultScopes([]);
        Passport::authorizationView('bherila-auth::oauth.authorize');
        AgentOAuthServer::routes();
        Route::get('/api/v1/items', fn () => response()->json(['ok' => true]))
            ->middleware([ExpectOAuthResource::class, 'auth:api', CheckToken::using('items:read')]);
        Route::post('/api/v1/mcp', fn () => response()->json(['ok' => true]))
            ->middleware([ExpectOAuthResource::class, 'auth:api', CheckToken::using('mcp:use')]);
        $this->user = User::query()->create(['name' => 'Person', 'email' => 'person@example.test', 'password' => 'not-used']);
    }

    public function test_the_index_offers_only_rest_scopes_and_the_configured_lifetimes(): void
    {
        $data = $this->actingAs($this->user)->getJson(self::BASE)->assertOk()
            ->assertHeader('Cache-Control', 'no-store, private')->json('data');

        $this->assertSame(['items:read', 'items:write'], array_column($data['scopes'], 'id'), 'The MCP connection scope and excluded scopes are not offered');
        $this->assertSame(['PT4H', 'P30D', 'P90D'], $data['token_lifetimes']);
        $this->assertSame(self::BASE.'/tokens', $data['issue_token_href']);
    }

    public function test_a_token_reaches_the_api_with_only_its_scopes_and_stops_when_revoked(): void
    {
        $issued = $this->actingAs($this->user)->postJson(self::BASE.'/tokens', ['name' => 'Connector', 'scopes' => ['items:read'], 'lifetime' => 'PT4H'])
            ->assertCreated()->assertHeader('Cache-Control', 'no-store, private')->json('data');
        $row = Passport::token()->newQuery()->where('user_id', $this->user->id)->sole();
        $this->assertSame(self::APP.'/api/v1', $row->resource_uri);
        $this->assertEqualsWithDelta(now()->addHours(4)->getTimestamp(), $row->expires_at?->getTimestamp(), 60);
        $this->assertStringNotContainsString($issued['token'], json_encode(session()->all(), JSON_THROW_ON_ERROR));

        $this->app['auth']->forgetGuards();
        $this->getJson('/api/v1/items', ['Authorization' => 'Bearer '.$issued['token']])->assertOk();
        $this->postJson('/api/v1/mcp', [], ['Authorization' => 'Bearer '.$issued['token']])->assertForbidden();

        $listed = $this->actingAs($this->user)->getJson(self::BASE)->json('data.tokens');
        $this->assertSame('Connector', $listed[0]['name']);
        $this->assertArrayNotHasKey('token', $listed[0]);
        $this->actingAs($this->user)->deleteJson($listed[0]['revoke_href'])->assertOk();
        $this->app['auth']->forgetGuards();
        $this->getJson('/api/v1/items', ['Authorization' => 'Bearer '.$issued['token']])->assertUnauthorized();
    }

    public function test_unoffered_scopes_and_lifetimes_are_refused(): void
    {
        $this->actingAs($this->user);
        $this->postJson(self::BASE.'/tokens', ['name' => 'x', 'scopes' => ['mcp:use'], 'lifetime' => 'P30D'])->assertJsonValidationErrors('scopes.0');
        $this->postJson(self::BASE.'/tokens', ['name' => 'x', 'scopes' => ['admin:all'], 'lifetime' => 'P30D'])->assertJsonValidationErrors('scopes.0');
        $this->postJson(self::BASE.'/tokens', ['name' => 'x', 'scopes' => ['items:read'], 'lifetime' => 'P10Y'])->assertJsonValidationErrors('lifetime');
        $this->assertSame(0, Passport::token()->newQuery()->count());
    }

    public function test_a_confidential_app_completes_the_code_flow_and_is_held_to_its_ceiling(): void
    {
        $issued = $this->actingAs($this->user)->postJson(self::BASE.'/apps', [
            'name' => 'Connector app', 'redirect_uris' => [self::REDIRECT], 'confidential' => true, 'scopes' => ['items:read'],
        ])->assertCreated()->assertHeader('Cache-Control', 'no-store, private')->json('data');
        $this->assertIsString($issued['client_secret']);
        $client = Passport::client()->newQuery()->findOrFail($issued['client_id']);
        $this->assertFalse($client->firstParty(), 'A person-registered app is never first-party');

        $verifier = rtrim(strtr(base64_encode(random_bytes(48)), '+/', '-_'), '=');
        $query = [
            'client_id' => $issued['client_id'], 'redirect_uri' => self::REDIRECT, 'response_type' => 'code',
            'code_challenge' => rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '='), 'code_challenge_method' => 'S256',
        ];
        // Refused before consent, either as an error redirect or (when the
        // redirect cannot be validated yet) as a 400 body.
        $over = $this->get('/oauth/authorize?'.http_build_query($query + ['scope' => 'items:read items:write']));
        $this->assertTrue(
            str_contains((string) $over->headers->get('Location'), 'error=invalid_scope')
                || ($over->getStatusCode() === 400 && $over->json('error') === 'invalid_scope'),
            'Over-ceiling request was not refused: '.$over->getStatusCode().' '.substr((string) $over->getContent(), 0, 300).' '.$over->headers->get('Location'),
        );

        $this->get('/oauth/authorize?'.http_build_query($query + ['scope' => 'items:read']))->assertOk();
        $approval = $this->post('/oauth/authorize', ['auth_token' => (string) session('authToken')])->assertRedirect();
        parse_str((string) parse_url((string) $approval->headers->get('Location'), PHP_URL_QUERY), $code);
        $tokens = $this->post('/oauth/token', [
            'grant_type' => 'authorization_code', 'client_id' => $issued['client_id'], 'client_secret' => $issued['client_secret'],
            'redirect_uri' => self::REDIRECT, 'code' => $code['code'], 'code_verifier' => $verifier,
        ], ['Accept' => 'application/json'])->assertOk()->json();
        $this->assertSame(self::APP.'/api/v1', OAuthResourceIndicator::tokenClaims($tokens['access_token'])['resource'] ?? null);

        $app = $this->actingAs($this->user)->getJson(self::BASE)->json('data.apps.0');
        $this->assertSame(['items:read'], $app['scopes']);
        $this->actingAs($this->user)->deleteJson($app['delete_href'])->assertOk();
        $this->assertSame(0, Passport::token()->newQuery()->where('client_id', $issued['client_id'])->where('revoked', false)->count());
        $this->assertTrue((bool) $client->fresh()->revoked);
    }

    public function test_unsafe_redirects_are_refused_and_a_public_app_has_no_secret(): void
    {
        $this->actingAs($this->user);
        foreach (['http://app.example.test/cb', 'https://app.example.test/cb#f', 'https://u:p@app.example.test/cb', 'javascript:alert(1)'] as $uri) {
            $this->postJson(self::BASE.'/apps', ['name' => 'Unsafe', 'redirect_uris' => [$uri], 'confidential' => false, 'scopes' => ['items:read']])
                ->assertJsonValidationErrors('credential');
        }
        $this->postJson(self::BASE.'/apps', ['name' => 'Loopback', 'redirect_uris' => ['http://localhost:8080/cb'], 'confidential' => false, 'scopes' => ['items:read']])
            ->assertCreated()->assertJsonPath('data.client_secret', null);
    }

    public function test_another_person_cannot_revoke_or_delete(): void
    {
        $token = $this->actingAs($this->user)->postJson(self::BASE.'/tokens', ['name' => 'Mine', 'scopes' => ['items:read'], 'lifetime' => 'P30D'])->json('data');
        $app = $this->postJson(self::BASE.'/apps', ['name' => 'Mine', 'redirect_uris' => [self::REDIRECT], 'confidential' => false, 'scopes' => ['items:read']])->json('data');
        $row = Passport::token()->newQuery()->where('user_id', $this->user->id)->sole();
        $other = User::query()->create(['name' => 'Other', 'email' => 'other@example.test', 'password' => 'not-used']);

        $this->actingAs($other)->deleteJson(self::BASE."/tokens/{$row->getKey()}")->assertNotFound();
        $this->actingAs($other)->deleteJson(self::BASE."/apps/{$app['client_id']}")->assertNotFound();
        $this->assertFalse((bool) $row->fresh()->revoked);
        $this->assertSame([], $this->actingAs($other)->getJson(self::BASE)->json('data.tokens'));
        $this->assertIsString($token['token']);
    }

    public function test_issuance_stops_while_the_oauth_server_is_off_but_revocation_works(): void
    {
        $this->actingAs($this->user)->postJson(self::BASE.'/tokens', ['name' => 'Before', 'scopes' => ['items:read'], 'lifetime' => 'P30D'])->assertCreated();
        $row = Passport::token()->newQuery()->where('user_id', $this->user->id)->sole();
        config(['bherila-auth.oauth_server.enabled' => false]);

        $this->postJson(self::BASE.'/tokens', ['name' => 'During', 'scopes' => ['items:read'], 'lifetime' => 'P30D'])->assertNotFound();
        $this->postJson(self::BASE.'/apps', ['name' => 'During', 'redirect_uris' => [self::REDIRECT], 'confidential' => false, 'scopes' => ['items:read']])->assertNotFound();
        $data = $this->getJson(self::BASE)->assertOk()->json('data');
        $this->assertNull($data['issue_token_href']);
        $this->deleteJson($data['tokens'][0]['revoke_href'])->assertOk();
        $this->assertTrue((bool) $row->fresh()->revoked);
    }

    public function test_redirect_uri_rules(): void
    {
        $this->assertTrue(ApiCredentialService::validRedirectUri('https://app.example.test/cb'));
        $this->assertTrue(ApiCredentialService::validRedirectUri('http://[::1]:9/cb'));
        $this->assertFalse(ApiCredentialService::validRedirectUri('http://192.0.2.1/cb'));
        $this->assertFalse(ApiCredentialService::validRedirectUri('https://'.str_repeat('a', 2050).'.test'));
    }
}
