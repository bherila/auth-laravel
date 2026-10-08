<?php

namespace BWH\Auth\Tests\Feature;

use BWH\Auth\AuthServiceProvider;
use BWH\Auth\Http\Controllers\OAuthDynamicClientRegistrationController;
use BWH\Auth\Http\Controllers\OAuthTokenIntrospectionController;
use BWH\Auth\Http\Middleware\AppendOAuthAuthorizationResponseIssuer;
use BWH\Auth\Http\Middleware\EnforceOAuthPkce;
use BWH\Auth\Http\Middleware\EnforceOAuthResourceIndicator;
use BWH\Auth\Http\Middleware\ExpectOAuthResource;
use BWH\Auth\OAuth\Server\OAuthResourceIndicator;
use BWH\Auth\OAuth\Server\ResourceAccessTokenRepository;
use BWH\Auth\OAuth\Server\ResourceAuthCodeRepository;
use BWH\Auth\OAuth\Server\ResourceClient;
use BWH\Auth\OAuth\Server\ResourceRefreshTokenRepository;
use BWH\Auth\Tests\Fixtures\ArrayScopesAuthCode;
use BWH\Auth\Tests\Fixtures\CollectionScopesClient;
use BWH\Auth\Tests\Fixtures\CollectionScopesToken;
use BWH\Auth\Tests\Fixtures\FailingDynamicRegistrationClient;
use BWH\Auth\Tests\Fixtures\User;
use BWH\Auth\Tests\TestCase;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Http\Middleware\ConvertEmptyStringsToNull;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Collection;
use Illuminate\Testing\TestResponse;
use Laravel\Passport\AuthCode;
use Laravel\Passport\Bridge\AccessToken;
use Laravel\Passport\Bridge\AccessTokenRepository as PassportAccessTokenRepository;
use Laravel\Passport\Bridge\AuthCodeRepository as PassportAuthCodeRepository;
use Laravel\Passport\Bridge\RefreshTokenRepository as PassportRefreshTokenRepository;
use Laravel\Passport\Client;
use Laravel\Passport\ClientRepository;
use Laravel\Passport\Passport;
use Laravel\Passport\PassportServiceProvider;
use Laravel\Passport\Token;
use PHPUnit\Framework\Attributes\DataProvider;
use ReflectionMethod;
use RuntimeException;

final class OAuthResourceTokenBindingTest extends TestCase
{
    private const ISSUER = 'https://auth.example.test';

    private const RESOURCE = 'https://auth.example.test/mcp';

    protected function getPackageProviders($app): array
    {
        return [AuthServiceProvider::class, PassportServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);

        [$privateKey, $publicKey] = $this->passportKeys();
        $app['config']->set('app.url', self::ISSUER);
        $app['config']->set('passport.private_key', $privateKey);
        $app['config']->set('passport.public_key', $publicKey);
        $app['config']->set('passport.middleware', ['web']);
        $app['config']->set('auth.guards.api', [
            'driver' => 'passport',
            'provider' => 'users',
        ]);
        $app['config']->set('bherila-auth.oauth_server.enabled', true);
        $app['config']->set('bherila-auth.oauth_server.issuer', self::ISSUER);
        $app['config']->set('bherila-auth.oauth_server.resource', self::RESOURCE);
        $app['config']->set('bherila-auth.oauth_server.scopes', [
            'mcp:use' => 'Connect through MCP',
            'identity:read' => 'Read identity',
        ]);
        $app['config']->set('bherila-auth.oauth_server.resource_required_scope', 'mcp:use');
        $app['config']->set('bherila-auth.oauth_server.resource_required_scopes', []);
        $app['config']->set('bherila-auth.oauth_server.dynamic_clients.required_columns', [
            'dynamically_registered_at',
            'scopes',
        ]);
        $app['config']->set('bherila-auth.oauth_server.dynamic_clients.scopes_column', 'scopes');
        $app['config']->set('bherila-auth.oauth_server.dynamic_clients.enforce_registered_scopes', true);
        $app['config']->set('bherila-auth.oauth_server.dynamic_clients.registered_at_column', 'dynamically_registered_at');
        $app['config']->set('bherila-auth.oauth_server.introspection.enabled', true);
        $app['config']->set('bherila-auth.oauth_server.introspection.clients', [[
            'id' => 'mcp-resource-server',
            'secret_hash' => password_hash('introspection-secret', PASSWORD_DEFAULT),
            'resource' => self::RESOURCE,
        ]]);

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

        Passport::tokensCan([
            'mcp:use' => 'Connect through MCP',
            'identity:read' => 'Read identity',
        ]);
        Passport::defaultScopes([]);
        Passport::authorizationView('bherila-auth::oauth.authorize');

        // This also documents the concrete Passport extension points used by the
        // package's opt-in provider.
        $this->assertInstanceOf(ResourceAccessTokenRepository::class, app(PassportAccessTokenRepository::class));
        $this->assertInstanceOf(ResourceAuthCodeRepository::class, app(PassportAuthCodeRepository::class));
        $this->assertInstanceOf(ResourceRefreshTokenRepository::class, app(PassportRefreshTokenRepository::class));

        foreach (['passport.authorizations.authorize', 'passport.authorizations.approve', 'passport.authorizations.deny', 'passport.token'] as $name) {
            $route = Route::getRoutes()->getByName($name);
            if ($route !== null) {
                $route->middleware([
                    EnforceOAuthPkce::class,
                    EnforceOAuthResourceIndicator::class,
                ]);
            }
        }

        Route::get('/mcp', fn () => response()->json(['ok' => true]))
            ->middleware([ExpectOAuthResource::class, 'auth:api']);
        Route::get('/other-api', fn () => response()->json(['ok' => true]))
            ->middleware('auth:api');
        Route::post('/oauth/register', OAuthDynamicClientRegistrationController::class)
            ->middleware(ConvertEmptyStringsToNull::class);
        Route::post('/oauth/introspect', OAuthTokenIntrospectionController::class);
    }

    protected function tearDown(): void
    {
        Passport::useAccessTokenEntity(AccessToken::class);
        Passport::useAuthCodeModel(AuthCode::class);
        Passport::useClientModel(Client::class);
        Passport::useTokenModel(Token::class);

        parent::tearDown();
    }

    public function test_resource_survives_authorization_code_token_and_refresh_lifecycle(): void
    {
        [$user, $client] = $this->userAndPublicClient(['mcp:use']);
        $verifier = str_repeat('v', 43);
        $challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');

        $authorization = $this->actingAs($user)->get('/oauth/authorize?'.http_build_query([
            'response_type' => 'code',
            'client_id' => $client->getKey(),
            'redirect_uri' => 'http://127.0.0.1:1455/callback',
            'scope' => 'mcp:use',
            'resource' => self::RESOURCE,
            'code_challenge' => $challenge,
            'code_challenge_method' => 'S256',
            'state' => 'state-123',
        ]));
        $authorization->assertOk();

        $authToken = session('authToken');
        $this->assertIsString($authToken);
        $approval = $this->actingAs($user)->post('/oauth/authorize', [
            'auth_token' => $authToken,
        ]);
        $approval->assertRedirect();

        parse_str((string) parse_url((string) $approval->headers->get('Location'), PHP_URL_QUERY), $redirectQuery);
        $this->assertArrayHasKey('code', $redirectQuery);

        $token = $this->postJson('/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => $client->getKey(),
            'redirect_uri' => 'http://127.0.0.1:1455/callback',
            'code' => $redirectQuery['code'],
            'code_verifier' => $verifier,
            'resource' => self::RESOURCE,
        ]);
        $token->assertOk();
        $accessToken = (string) $token->json('access_token');
        $refreshToken = (string) $token->json('refresh_token');
        $claims = OAuthResourceIndicator::tokenClaims($accessToken);

        $this->assertContains(self::RESOURCE, $claims['aud'] ?? []);
        $this->assertSame(self::ISSUER, $claims['iss'] ?? null);
        $this->assertSame(self::RESOURCE, $claims['resource'] ?? null);
        $storedToken = Passport::token()->newQuery()->where('client_id', $client->getKey())->firstOrFail();
        $this->assertSame(self::RESOURCE, $storedToken->resource_uri);
        $storedRefreshToken = Passport::refreshToken()->newQuery()
            ->where('access_token_id', $claims['jti'])
            ->firstOrFail();
        $this->assertSame(self::RESOURCE, $storedRefreshToken->resource_uri);

        $this->getJson('/mcp', ['Authorization' => 'Bearer '.$accessToken])->assertOk();

        $refresh = $this->postJson('/oauth/token', [
            'grant_type' => 'refresh_token',
            'client_id' => $client->getKey(),
            'refresh_token' => $refreshToken,
            'resource' => self::RESOURCE,
        ]);
        $refresh->assertOk();
        $refreshedAccessToken = (string) $refresh->json('access_token');
        $refreshedClaims = OAuthResourceIndicator::tokenClaims($refreshedAccessToken);
        $this->assertContains(self::RESOURCE, $refreshedClaims['aud'] ?? []);
        $this->assertSame(self::RESOURCE, $refreshedClaims['resource'] ?? null);
        $this->assertSame(
            self::RESOURCE,
            Passport::token()->newQuery()->whereKey($claims['jti'])->value('resource_uri'),
        );
        $this->assertSame(
            self::RESOURCE,
            Passport::token()->newQuery()->whereKey($refreshedClaims['jti'])->value('resource_uri'),
        );
        $this->assertSame(
            self::RESOURCE,
            Passport::refreshToken()->newQuery()
                ->where('access_token_id', $refreshedClaims['jti'])
                ->value('resource_uri'),
        );
    }

    public function test_refresh_resource_survives_expired_access_token_row_purge(): void
    {
        [$user, $client] = $this->userAndPublicClient(['mcp:use']);
        $token = $this->issueToken($user, $client);
        $refreshToken = (string) $token->json('refresh_token');
        $claims = OAuthResourceIndicator::tokenClaims((string) $token->json('access_token'));
        $accessTokenId = (string) ($claims['jti'] ?? '');

        $this->assertSame(
            self::RESOURCE,
            Passport::refreshToken()->newQuery()
                ->where('access_token_id', $accessTokenId)
                ->value('resource_uri'),
        );

        // Passport may purge an expired access-token row while its longer-lived
        // refresh token is still valid. The refresh credential owns its audience.
        Passport::token()->newQuery()->whereKey($accessTokenId)->delete();
        $this->assertDatabaseMissing('oauth_access_tokens', ['id' => $accessTokenId]);

        $refreshed = $this->postJson('/oauth/token', [
            'grant_type' => 'refresh_token',
            'client_id' => $client->getKey(),
            'refresh_token' => $refreshToken,
            'resource' => self::RESOURCE,
        ])->assertOk();

        $refreshedClaims = OAuthResourceIndicator::tokenClaims((string) $refreshed->json('access_token'));
        $this->assertSame(self::RESOURCE, $refreshedClaims['resource'] ?? null);
        $this->assertContains(self::RESOURCE, $refreshedClaims['aud'] ?? []);
        $this->assertSame(
            self::RESOURCE,
            Passport::refreshToken()->newQuery()
                ->where('access_token_id', $refreshedClaims['jti'])
                ->value('resource_uri'),
        );
    }

    public function test_resource_is_required_and_cannot_be_changed_at_each_grant_boundary(): void
    {
        [$user, $client] = $this->userAndPublicClient(['mcp:use']);
        $verifier = str_repeat('x', 43);
        $challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
        $query = [
            'response_type' => 'code',
            'client_id' => $client->getKey(),
            'redirect_uri' => 'http://127.0.0.1:1455/callback',
            'scope' => 'mcp:use',
            'code_challenge' => $challenge,
            'code_challenge_method' => 'S256',
        ];

        $missingAuthorizationResource = $this->actingAs($user)
            ->get('/oauth/authorize?'.http_build_query($query))
            ->assertRedirect();
        $this->assertStringContainsString(
            'error=invalid_target',
            (string) $missingAuthorizationResource->headers->get('Location'),
        );
        $this->assertStringContainsString(
            'no-store',
            (string) $missingAuthorizationResource->headers->get('Cache-Control'),
        );
        $wrongAuthorizationResource = $this->actingAs($user)
            ->get('/oauth/authorize?'.http_build_query(
                $query + ['resource' => 'https://other.example.test/mcp'],
            ))
            ->assertRedirect();
        $this->assertStringContainsString(
            'error=invalid_target',
            (string) $wrongAuthorizationResource->headers->get('Location'),
        );

        $auth = $this->actingAs($user)->get('/oauth/authorize?'.http_build_query($query + ['resource' => self::RESOURCE]));
        $authToken = (string) session('authToken');
        $approval = $this->actingAs($user)->post('/oauth/authorize', ['auth_token' => $authToken]);
        $approval->assertRedirect();
        parse_str((string) parse_url((string) $approval->headers->get('Location'), PHP_URL_QUERY), $redirectQuery);

        $missingResource = $this->postJson('/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => $client->getKey(),
            'redirect_uri' => 'http://127.0.0.1:1455/callback',
            'code' => $redirectQuery['code'],
            'code_verifier' => $verifier,
        ]);
        $missingResource->assertStatus(400);

        // The failed attempt did not consume the code, so the client can retry
        // with the resource bound to its original authorization request.
        $validToken = $this->postJson('/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => $client->getKey(),
            'redirect_uri' => 'http://127.0.0.1:1455/callback',
            'code' => $redirectQuery['code'],
            'code_verifier' => $verifier,
            'resource' => self::RESOURCE,
        ])->assertOk();
        $refreshToken = (string) $validToken->json('refresh_token');

        $this->postJson('/oauth/token', [
            'grant_type' => 'refresh_token',
            'client_id' => $client->getKey(),
            'refresh_token' => $refreshToken,
            'resource' => 'https://other.example.test/mcp',
        ])->assertStatus(400);

        $this->postJson('/oauth/token', [
            'grant_type' => 'refresh_token',
            'client_id' => $client->getKey(),
            'refresh_token' => $refreshToken,
        ])->assertStatus(400);

        $this->postJson('/oauth/token', [
            'grant_type' => 'refresh_token',
            'client_id' => $client->getKey(),
            'refresh_token' => $refreshToken,
            'resource' => self::RESOURCE,
            'scope' => 'mcp:use identity:read',
        ])->assertStatus(400);

        $this->postJson('/oauth/token', [
            'grant_type' => 'refresh_token',
            'client_id' => $client->getKey(),
            'refresh_token' => $refreshToken,
            'resource' => self::RESOURCE,
        ])->assertOk();

        $this->assertNotNull($auth);
    }

    /**
     * A generic OAuth client never sends RFC 8707 `resource`. With the opt-in,
     * every grant boundary binds its credential to the one configured resource
     * anyway, so the protected routes accept the token instead of refusing it as
     * unbound.
     */
    public function test_an_opted_in_server_binds_every_grant_when_the_client_omits_resource(): void
    {
        config(['bherila-auth.oauth_server.assume_omitted_resource' => true]);
        [$user, $client] = $this->userAndPublicClient(['mcp:use', 'identity:read']);
        $verifier = str_repeat('o', 43);
        $challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');

        $this->actingAs($user)->get('/oauth/authorize?'.http_build_query([
            'response_type' => 'code',
            'client_id' => $client->getKey(),
            'redirect_uri' => 'http://127.0.0.1:1455/callback',
            'scope' => 'mcp:use identity:read',
            'code_challenge' => $challenge,
            'code_challenge_method' => 'S256',
        ]))->assertOk();
        $approval = $this->actingAs($user)->post('/oauth/authorize', ['auth_token' => (string) session('authToken')]);
        $approval->assertRedirect();
        parse_str((string) parse_url((string) $approval->headers->get('Location'), PHP_URL_QUERY), $redirectQuery);
        $this->assertArrayHasKey('code', $redirectQuery);
        $this->assertSame(self::RESOURCE, Passport::authCode()->newQuery()->whereKey(
            Passport::authCode()->newQuery()->where('client_id', $client->getKey())->value('id'),
        )->value('resource_uri'));

        $token = $this->postJson('/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => $client->getKey(),
            'redirect_uri' => 'http://127.0.0.1:1455/callback',
            'code' => $redirectQuery['code'],
            'code_verifier' => $verifier,
        ])->assertOk();
        $claims = OAuthResourceIndicator::tokenClaims((string) $token->json('access_token'));
        $this->assertSame(self::RESOURCE, $claims['resource'] ?? null);
        $this->assertSame(self::RESOURCE, Passport::token()->newQuery()->whereKey($claims['jti'])->value('resource_uri'));
        $this->getJson('/mcp', ['Authorization' => 'Bearer '.$token->json('access_token')])->assertOk();

        $refresh = $this->postJson('/oauth/token', [
            'grant_type' => 'refresh_token',
            'client_id' => $client->getKey(),
            'refresh_token' => (string) $token->json('refresh_token'),
        ])->assertOk();
        $refreshed = OAuthResourceIndicator::tokenClaims((string) $refresh->json('access_token'));
        $this->assertSame(self::RESOURCE, $refreshed['resource'] ?? null);
        $this->getJson('/mcp', ['Authorization' => 'Bearer '.$refresh->json('access_token')])->assertOk();
    }

    /** The assumption fills an omission; it never overrides a different explicit resource. */
    public function test_an_opted_in_server_still_refuses_a_different_explicit_resource(): void
    {
        config(['bherila-auth.oauth_server.assume_omitted_resource' => true]);
        [$user, $client] = $this->userAndPublicClient(['mcp:use']);
        $verifier = str_repeat('p', 43);
        $challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
        $query = [
            'response_type' => 'code',
            'client_id' => $client->getKey(),
            'redirect_uri' => 'http://127.0.0.1:1455/callback',
            'scope' => 'mcp:use',
            'code_challenge' => $challenge,
            'code_challenge_method' => 'S256',
        ];

        $wrong = $this->actingAs($user)
            ->get('/oauth/authorize?'.http_build_query($query + ['resource' => 'https://other.example.test/mcp']))
            ->assertRedirect();
        $this->assertStringContainsString('error=invalid_target', (string) $wrong->headers->get('Location'));

        $this->actingAs($user)->get('/oauth/authorize?'.http_build_query($query))->assertOk();
        $approval = $this->actingAs($user)->post('/oauth/authorize', ['auth_token' => (string) session('authToken')]);
        parse_str((string) parse_url((string) $approval->headers->get('Location'), PHP_URL_QUERY), $redirectQuery);

        $this->postJson('/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => $client->getKey(),
            'redirect_uri' => 'http://127.0.0.1:1455/callback',
            'code' => $redirectQuery['code'],
            'code_verifier' => $verifier,
            'resource' => 'https://other.example.test/mcp',
        ])->assertStatus(400);
    }

    /** Without the opt-in, an omitted resource is still refused where a scope requires one. */
    public function test_the_assumption_is_off_by_default(): void
    {
        $this->assertFalse(OAuthResourceIndicator::assumesOmittedResource());
        $this->assertNull(OAuthResourceIndicator::requestResource(Request::create('/oauth/token', 'POST')));

        config(['bherila-auth.oauth_server.assume_omitted_resource' => true]);
        $this->assertSame(self::RESOURCE, OAuthResourceIndicator::requestResource(Request::create('/oauth/token', 'POST')));
        $this->assertNull(OAuthResourceIndicator::requestResource(Request::create('/oauth/token', 'POST', ['resource' => 'not a url'])));
    }

    /**
     * A client registered by a person (not self-registered) with a stored
     * scope ceiling is held to it at consent, like a self-registered one.
     */
    public function test_a_person_registered_client_is_held_to_its_stored_scope_ceiling(): void
    {
        $user = User::query()->create(['name' => 'Ceiling User', 'email' => 'ceiling@example.test', 'password' => 'not-used']);
        $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('Registered App', ['http://127.0.0.1:1455/callback'], confidential: false);
        $client->forceFill(['scopes' => ['identity:read']])->save();
        $challenge = rtrim(strtr(base64_encode(hash('sha256', str_repeat('c', 43), true)), '+/', '-_'), '=');
        $query = [
            'response_type' => 'code',
            'client_id' => $client->getKey(),
            'redirect_uri' => 'http://127.0.0.1:1455/callback',
            'code_challenge' => $challenge,
            'code_challenge_method' => 'S256',
            'resource' => self::RESOURCE,
        ];

        foreach (['identity:read mcp:use', 'mcp:use'] as $scope) {
            $refused = $this->actingAs($user)->get('/oauth/authorize?'.http_build_query($query + ['scope' => $scope]));
            $refused->assertRedirect();
            $this->assertStringContainsString('error=invalid_scope', (string) $refused->headers->get('Location'), $scope);
        }
        $this->actingAs($user)->get('/oauth/authorize?'.http_build_query($query + ['scope' => 'identity:read']))->assertOk();
    }

    /** A config without the registration-column keys must not switch the ceiling off. */
    public function test_the_ceiling_holds_when_the_column_settings_are_missing(): void
    {
        config(['bherila-auth.oauth_server.dynamic_clients' => ['enabled' => true]]);
        $user = User::query()->create(['name' => 'Default User', 'email' => 'default@example.test', 'password' => 'not-used']);
        $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('Registered App', ['http://127.0.0.1:1455/callback'], confidential: false);
        $client->forceFill(['scopes' => ['identity:read']])->save();
        $challenge = rtrim(strtr(base64_encode(hash('sha256', str_repeat('e', 43), true)), '+/', '-_'), '=');

        $refused = $this->actingAs($user)->get('/oauth/authorize?'.http_build_query([
            'response_type' => 'code',
            'client_id' => $client->getKey(),
            'redirect_uri' => 'http://127.0.0.1:1455/callback',
            'scope' => 'identity:read mcp:use',
            'code_challenge' => $challenge,
            'code_challenge_method' => 'S256',
            'resource' => self::RESOURCE,
        ]));
        $this->assertStringContainsString('error=invalid_scope', (string) $refused->headers->get('Location'));
    }

    public function test_a_person_registered_client_without_stored_scopes_keeps_the_catalog(): void
    {
        $user = User::query()->create(['name' => 'Catalog User', 'email' => 'catalog@example.test', 'password' => 'not-used']);
        $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('Unrestricted App', ['http://127.0.0.1:1455/callback'], confidential: false);
        $challenge = rtrim(strtr(base64_encode(hash('sha256', str_repeat('d', 43), true)), '+/', '-_'), '=');

        $this->actingAs($user)->get('/oauth/authorize?'.http_build_query([
            'response_type' => 'code',
            'client_id' => $client->getKey(),
            'redirect_uri' => 'http://127.0.0.1:1455/callback',
            'scope' => 'identity:read mcp:use',
            'code_challenge' => $challenge,
            'code_challenge_method' => 'S256',
            'resource' => self::RESOURCE,
        ]))->assertOk();
    }

    public function test_a_bound_token_is_rejected_for_a_different_resource_and_for_a_different_issuer(): void
    {
        [$user, $client] = $this->userAndPublicClient(['mcp:use']);
        $token = $this->issueToken($user, $client);
        $serialized = (string) $token->json('access_token');

        $this->getJson('/mcp', ['Authorization' => 'Bearer '.$serialized])->assertOk();
        Auth::forgetGuards();
        $this->getJson('/other-api', ['Authorization' => 'Bearer '.$serialized])->assertUnauthorized();

        config(['bherila-auth.oauth_server.resource' => 'https://other.example.test/mcp']);
        Auth::forgetGuards();
        $this->getJson('/mcp', ['Authorization' => 'Bearer '.$serialized])->assertUnauthorized();

        config(['bherila-auth.oauth_server.resource' => self::RESOURCE]);
        config(['bherila-auth.oauth_server.issuer' => 'https://wrong.example.test']);
        Auth::forgetGuards();
        $this->getJson('/mcp', ['Authorization' => 'Bearer '.$serialized])->assertUnauthorized();
    }

    public function test_revocation_is_enforced_by_the_package_resource_repository(): void
    {
        [$user, $client] = $this->userAndPublicClient(['mcp:use']);
        $token = $this->issueToken($user, $client);
        $serialized = (string) $token->json('access_token');
        $tokenId = (string) (OAuthResourceIndicator::tokenClaims($serialized)['jti'] ?? '');

        Passport::token()->newQuery()->whereKey($tokenId)->update(['revoked' => true]);

        $this->getJson('/mcp', ['Authorization' => 'Bearer '.$serialized])->assertUnauthorized();
    }

    public function test_confidential_resource_server_can_introspect_only_its_bound_resource(): void
    {
        [$user, $client] = $this->userAndPublicClient(['mcp:use']);
        $token = $this->issueToken($user, $client);
        $serialized = (string) $token->json('access_token');

        $active = $this->withHeader(
            'Authorization',
            'Basic '.base64_encode('mcp-resource-server:introspection-secret'),
        )->post('/oauth/introspect', ['token' => $serialized, 'token_type_hint' => 'access_token']);

        $active->assertOk()
            ->assertHeader('Cache-Control', 'no-store, private')
            ->assertJsonPath('active', true)
            ->assertJsonPath('iss', self::ISSUER)
            ->assertJsonPath('sub', (string) $user->getKey())
            ->assertJsonPath('client_id', (string) $client->getKey())
            ->assertJsonPath('scope', 'mcp:use')
            ->assertJsonPath('resource', self::RESOURCE);
        self::assertIsInt($active->json('exp'));
        self::assertIsInt($active->json('iat'));
        self::assertIsInt($active->json('nbf'));
        self::assertContains(self::RESOURCE, $active->json('aud'));

        config(['bherila-auth.oauth_server.introspection.clients.0.resource' => 'HTTPS://AUTH.EXAMPLE.TEST:443/mcp']);
        $this->withHeader(
            'Authorization',
            'Basic '.base64_encode('mcp-resource-server:introspection-secret'),
        )->post('/oauth/introspect', ['token' => $serialized])
            ->assertOk()
            ->assertJsonPath('active', true);

        config(['bherila-auth.oauth_server.introspection.clients.0.resource' => 'https://other.example.test/mcp']);
        $this->withHeader(
            'Authorization',
            'Basic '.base64_encode('mcp-resource-server:introspection-secret'),
        )->post('/oauth/introspect', ['token' => $serialized])
            ->assertOk()
            ->assertExactJson(['active' => false]);
    }

    #[DataProvider('producerTimestampProvider')]
    public function test_introspection_emits_only_representable_whole_second_timestamps(mixed $value, ?int $expected): void
    {
        $timestamp = new ReflectionMethod(OAuthTokenIntrospectionController::class, 'timestamp');

        self::assertSame($expected, $timestamp->invoke(app(OAuthTokenIntrospectionController::class), $value));
    }

    /**
     * `nbf` is published with the opposite rounding, so the endpoint never
     * advertises a token as valid earlier than the instant it was issued for.
     */
    public function test_introspection_rounds_not_before_toward_the_future(): void
    {
        $timestamp = new ReflectionMethod(OAuthTokenIntrospectionController::class, 'timestamp');
        $controller = app(OAuthTokenIntrospectionController::class);

        self::assertSame(1770000001, $timestamp->invoke($controller, 1770000000.75, true));
        self::assertSame(1770000000, $timestamp->invoke($controller, 1770000000.0, true));
        self::assertSame(-1770000000, $timestamp->invoke($controller, -1770000000.75, true));
        self::assertNull($timestamp->invoke($controller, 2 ** 63, true));
    }

    /** @return array<string, array{mixed, ?int}> */
    public static function producerTimestampProvider(): array
    {
        return [
            'integer passes through' => [1770000000, 1770000000],
            'fractional normalizes' => [1770000000.75, 1770000000],
            // Floor, not truncation toward zero: a pre-epoch claim must not be
            // rounded toward the future.
            'negative fractional floors' => [-1770000000.75, -1770000001],
            'nan' => [NAN, null],
            'infinity' => [INF, null],
            'negative infinity' => [-INF, null],
            'string' => ['1770000000', null],
            // -(2 ** 63) is also what an out-of-range literal rounds to, so it
            // must not be emitted as a whole-second claim.
            'lower bound' => [-(2 ** 63), null],
            'upper bound' => [2 ** 63, null],
            'largest representable in range' => [9223372036854774784.0, 9223372036854774784],
        ];
    }

    public function test_introspection_rejects_bad_client_credentials_and_reports_revocation_as_inactive(): void
    {
        [$user, $client] = $this->userAndPublicClient(['mcp:use']);
        $token = $this->issueToken($user, $client);
        $serialized = (string) $token->json('access_token');
        $tokenId = (string) (OAuthResourceIndicator::tokenClaims($serialized)['jti'] ?? '');

        $this->withHeader('Authorization', 'Basic '.base64_encode('mcp-resource-server:wrong'))
            ->post('/oauth/introspect', ['token' => $serialized])
            ->assertUnauthorized()
            ->assertHeader('WWW-Authenticate', 'Basic realm="oauth-introspection"')
            ->assertJsonPath('error', 'invalid_client');

        Passport::token()->newQuery()->whereKey($tokenId)->update(['revoked' => true]);

        $this->withHeader(
            'Authorization',
            'Basic '.base64_encode('mcp-resource-server:introspection-secret'),
        )->post('/oauth/introspect', ['token' => $serialized])
            ->assertOk()
            ->assertExactJson(['active' => false]);
    }

    public function test_introspection_decodes_form_encoded_basic_credentials(): void
    {
        [$user, $client] = $this->userAndPublicClient(['mcp:use']);
        $serialized = (string) $this->issueToken($user, $client)->json('access_token');
        $clientId = 'mcp: resource+server%';
        $clientSecret = 'secret: with+percent%';
        config(['bherila-auth.oauth_server.introspection.clients.0' => [
            'id' => $clientId,
            'secret_hash' => password_hash($clientSecret, PASSWORD_DEFAULT),
            'resource' => self::RESOURCE,
        ]]);

        $this->withHeader(
            'Authorization',
            'Basic '.base64_encode(urlencode($clientId).':'.urlencode($clientSecret)),
        )->post('/oauth/introspect', ['token' => $serialized])
            ->assertOk()
            ->assertJsonPath('active', true);
    }

    public function test_disabling_issuance_keeps_existing_resource_tokens_audience_bound(): void
    {
        [$user, $client] = $this->userAndPublicClient(['mcp:use']);
        $token = $this->issueToken($user, $client);
        $serialized = (string) $token->json('access_token');
        $tokenId = (string) (OAuthResourceIndicator::tokenClaims($serialized)['jti'] ?? '');

        $repository = $this->disabledAccessTokenRepository();
        self::assertInstanceOf(ResourceAccessTokenRepository::class, $repository);
        $originalRequest = app('request');

        try {
            $expected = Request::create('/mcp', server: ['HTTP_AUTHORIZATION' => 'Bearer '.$serialized]);
            OAuthResourceIndicator::expectConfiguredFor($expected);
            app()->instance('request', $expected);
            self::assertFalse($repository->isAccessTokenRevoked($tokenId));

            $other = Request::create('/other-api', server: ['HTTP_AUTHORIZATION' => 'Bearer '.$serialized]);
            app()->instance('request', $other);
            self::assertTrue($repository->isAccessTokenRevoked($tokenId));

            Passport::token()->newQuery()->findOrFail($tokenId)->forceFill([
                'resource_uri' => null,
                'scopes' => ['identity:read'],
            ])->save();
            app()->instance('request', $other);
            self::assertTrue($repository->isAccessTokenRevoked($tokenId));
        } finally {
            app()->instance('request', $originalRequest);
        }
    }

    public function test_disabled_issuance_delegates_only_unbound_tokens_on_unmarked_routes(): void
    {
        [$user, $client] = $this->userAndPublicClient(['identity:read']);
        Passport::token()->forceFill([
            'id' => 'legacy-unbound-token-id',
            'user_id' => $user->getKey(),
            'client_id' => $client->getKey(),
            'scopes' => ['identity:read'],
            'revoked' => false,
            'expires_at' => now()->addHour(),
            'resource_uri' => null,
        ])->save();
        $repository = $this->disabledAccessTokenRepository();
        $originalRequest = app('request');

        try {
            $expected = Request::create('/mcp', server: ['HTTP_AUTHORIZATION' => 'Bearer legacy-unbound-token']);
            OAuthResourceIndicator::expectConfiguredFor($expected);
            app()->instance('request', $expected);
            self::assertTrue($repository->isAccessTokenRevoked('legacy-unbound-token-id'));

            $other = Request::create('/other-api', server: ['HTTP_AUTHORIZATION' => 'Bearer legacy-unbound-token']);
            app()->instance('request', $other);
            DB::connection()->flushQueryLog();
            DB::connection()->enableQueryLog();
            self::assertFalse($repository->isAccessTokenRevoked('legacy-unbound-token-id'));
            $queries = DB::connection()->getQueryLog();
            DB::connection()->disableQueryLog();

            $tokenQueries = array_filter($queries, static fn (array $query): bool => str_contains(
                strtolower((string) ($query['query'] ?? '')),
                'oauth_access_tokens',
            ));
            self::assertCount(1, $tokenQueries);
        } finally {
            DB::connection()->disableQueryLog();
            app()->instance('request', $originalRequest);
        }
    }

    public function test_disabled_issuance_does_not_misclassify_collection_cast_required_scopes_as_unbound(): void
    {
        Passport::useTokenModel(CollectionScopesToken::class);
        [$user, $client] = $this->userAndPublicClient(['mcp:use']);
        Passport::token()->forceFill([
            'id' => 'collection-scope-token-id',
            'user_id' => $user->getKey(),
            'client_id' => $client->getKey(),
            'scopes' => ['mcp:use'],
            'revoked' => false,
            'expires_at' => now()->addHour(),
            'resource_uri' => null,
        ])->save();
        self::assertInstanceOf(Collection::class, Passport::token()->newQuery()
            ->findOrFail('collection-scope-token-id')
            ->getAttribute('scopes'));

        $repository = $this->disabledAccessTokenRepository();
        $originalRequest = app('request');

        try {
            app()->instance('request', Request::create(
                '/other-api',
                server: ['HTTP_AUTHORIZATION' => 'Bearer legacy-unbound-token'],
            ));

            self::assertTrue($repository->isAccessTokenRevoked('collection-scope-token-id'));
        } finally {
            app()->instance('request', $originalRequest);
        }
    }

    public function test_bearer_validation_does_not_query_the_schema_catalog(): void
    {
        [$user, $client] = $this->userAndPublicClient(['mcp:use']);
        $token = $this->issueToken($user, $client);

        DB::connection()->flushQueryLog();
        DB::connection()->enableQueryLog();
        $this->getJson('/mcp', [
            'Authorization' => 'Bearer '.(string) $token->json('access_token'),
        ])->assertOk();
        $queries = DB::connection()->getQueryLog();
        DB::connection()->disableQueryLog();

        $schemaQueries = array_filter($queries, static function (array $query): bool {
            $sql = strtolower((string) ($query['query'] ?? ''));

            return str_contains($sql, 'pragma_table')
                || str_contains($sql, 'information_schema')
                || str_contains($sql, 'pg_catalog');
        });

        self::assertSame([], array_values($schemaQueries));
    }

    public function test_disabling_the_oauth_server_also_disables_authorization_response_issuer_middleware(): void
    {
        config([
            'bherila-auth.oauth_server.enabled' => false,
            'bherila-auth.oauth_server.authorization_response_issuer.enabled' => true,
        ]);

        (new AuthServiceProvider(app()))->boot();

        $route = Route::getRoutes()->getByName('passport.authorizations.authorize');
        self::assertNotNull($route);
        self::assertNotContains(AppendOAuthAuthorizationResponseIssuer::class, $route->gatherMiddleware());
    }

    public function test_passport_generated_authorization_errors_are_not_cacheable(): void
    {
        [$user, $client] = $this->userAndPublicClient(['mcp:use']);

        $response = $this->actingAs($user)->get('/oauth/authorize?'.http_build_query([
            'response_type' => 'token',
            'client_id' => $client->getKey(),
            'redirect_uri' => 'http://127.0.0.1:1455/callback',
            'scope' => 'mcp:use',
            'resource' => self::RESOURCE,
            'code_challenge' => str_repeat('c', 43),
            'code_challenge_method' => 'S256',
            'state' => 'downstream-error-state',
        ]));

        $response->assertBadRequest()
            ->assertJsonPath('error', 'unsupported_grant_type')
            ->assertHeader('Pragma', 'no-cache');
        self::assertStringContainsString('no-store', (string) $response->headers->get('Cache-Control'));
    }

    public function test_prevalidation_errors_use_a_sole_active_redirect_but_not_a_revoked_client(): void
    {
        [$user, $client] = $this->userAndPublicClient(['mcp:use']);
        $query = [
            'response_type' => 'code',
            'client_id' => $client->getKey(),
            'scope' => 'identity:read',
            'resource' => self::RESOURCE,
            'code_challenge' => str_repeat('c', 43),
            'code_challenge_method' => 'S256',
            'state' => 'sole-redirect-state',
        ];

        $active = $this->actingAs($user)->get('/oauth/authorize?'.http_build_query($query));
        $active->assertRedirect();
        self::assertStringStartsWith(
            'http://127.0.0.1:1455/callback?',
            (string) $active->headers->get('Location'),
        );
        self::assertStringContainsString('error=invalid_scope', (string) $active->headers->get('Location'));
        self::assertStringContainsString('state=sole-redirect-state', (string) $active->headers->get('Location'));

        $client->forceFill(['revoked' => true])->save();
        $revoked = $this->actingAs($user)->get('/oauth/authorize?'.http_build_query($query));
        $revoked->assertBadRequest()
            ->assertJsonPath('error', 'invalid_scope')
            ->assertHeaderMissing('Location');
    }

    public function test_collection_cast_registered_scopes_are_enforced_as_a_scope_list(): void
    {
        Schema::table('oauth_clients', static function (Blueprint $table): void {
            $table->json('registered_scopes')->nullable();
        });
        config([
            'bherila-auth.oauth_server.dynamic_clients.required_columns' => [
                'dynamically_registered_at',
                'registered_scopes',
            ],
            'bherila-auth.oauth_server.dynamic_clients.scopes_column' => 'registered_scopes',
        ]);
        Passport::useClientModel(CollectionScopesClient::class);
        $registration = $this->postJson('/oauth/register', [
            'client_name' => 'Collection Scope Client',
            'redirect_uris' => ['https://client.example.test/callback'],
            'scope' => 'mcp:use',
        ])->assertCreated();
        $client = Passport::client()->newQuery()->findOrFail($registration->json('client_id'));
        $user = User::query()->create([
            'name' => 'Collection Scope User',
            'email' => 'collection-scope@example.test',
            'password' => 'not-used',
        ]);

        self::assertInstanceOf(Collection::class, $client->getAttribute('registered_scopes'));
        self::assertSame(['mcp:use'], $client->getAttribute('registered_scopes')->all());
        $this->issueToken($user, $client, 'https://client.example.test/callback')->assertOk();
    }

    public function test_array_cast_auth_code_scopes_are_not_double_encoded(): void
    {
        Passport::useAuthCodeModel(ArrayScopesAuthCode::class);
        [$user, $client] = $this->userAndPublicClient(['mcp:use']);

        $this->issueToken($user, $client)->assertOk();

        $authCode = Passport::authCode()->newQuery()
            ->where('client_id', $client->getKey())
            ->firstOrFail();
        self::assertSame(['mcp:use'], $authCode->getAttribute('scopes'));
        self::assertSame(
            '["mcp:use"]',
            DB::table($authCode->getTable())->where('id', $authCode->getKey())->value('scopes'),
        );
    }

    public function test_dcr_creates_a_public_client_without_a_secret_and_preserves_registered_scope_limits(): void
    {
        $redirectUri = 'http://127.0.0.1:39053/callback/BKj9umzr4ef_';
        $user = User::query()->create([
            'name' => 'DCR User',
            'email' => 'dcr@example.test',
            'password' => 'not-used',
        ]);
        $response = $this->postJson('/oauth/register', [
            'client_name' => 'Codex CLI',
            'redirect_uris' => [$redirectUri],
            'grant_types' => ['authorization_code', 'refresh_token'],
            'response_types' => ['code'],
            'token_endpoint_auth_method' => 'none',
            'scope' => 'mcp:use',
            'software_id' => 'ignored',
        ]);
        $response->assertCreated()
            ->assertJsonPath('client_name', 'Codex CLI')
            ->assertJsonPath('token_endpoint_auth_method', 'none')
            ->assertJsonMissingPath('client_secret');

        $client = Passport::client()->newQuery()->findOrFail($response->json('client_id'));
        $this->assertNull($client->secret);
        $this->assertNotNull($client->dynamically_registered_at);
        $this->assertSame(['mcp:use'], $client->scopes);
        $this->assertSame(
            '["mcp:use"]',
            DB::table($client->getTable())->where('id', $client->getKey())->value('scopes'),
        );
        $this->assertFalse($client->firstParty());
        $this->assertFalse($client->skipsAuthorization($user, Passport::scopesFor(['mcp:use'])));

        $challenge = rtrim(strtr(base64_encode(hash('sha256', str_repeat('p', 43), true)), '+/', '-_'), '=');
        $this->actingAs($user)->get('/oauth/authorize?'.http_build_query([
            'response_type' => 'code',
            'client_id' => $client->getKey(),
            'redirect_uri' => 'http://localhost:39053/callback/BKj9umzr4ef_',
            'scope' => 'mcp:use',
            'resource' => self::RESOURCE,
            'code_challenge' => $challenge,
            'code_challenge_method' => 'S256',
        ]))->assertStatus(401)->assertJsonPath('error', 'invalid_client');

        $authorizationErrorWithoutIssuer = $this->actingAs($user)->get('/oauth/authorize?'.http_build_query([
            'response_type' => 'code',
            'client_id' => $client->getKey(),
            'redirect_uri' => $redirectUri,
            'scope' => 'identity:read',
            'resource' => self::RESOURCE,
            'code_challenge' => $challenge,
            'code_challenge_method' => 'S256',
            'state' => 'state-without-issuer',
        ]));
        $authorizationErrorWithoutIssuer->assertRedirect();
        $this->assertStringContainsString(
            'error=invalid_scope',
            (string) $authorizationErrorWithoutIssuer->headers->get('Location'),
        );
        $this->assertStringContainsString(
            'state=state-without-issuer',
            (string) $authorizationErrorWithoutIssuer->headers->get('Location'),
        );
        $this->assertStringNotContainsString(
            'iss=',
            (string) $authorizationErrorWithoutIssuer->headers->get('Location'),
        );

        config(['bherila-auth.oauth_server.authorization_response_issuer.enabled' => true]);
        $authorizationError = $this->actingAs($user)->get('/oauth/authorize?'.http_build_query([
            'response_type' => 'code',
            'client_id' => $client->getKey(),
            'redirect_uri' => $redirectUri,
            'scope' => 'identity:read',
            'resource' => self::RESOURCE,
            'code_challenge' => $challenge,
            'code_challenge_method' => 'S256',
        ]));
        $authorizationError->assertRedirect();
        $this->assertStringContainsString(
            'error=invalid_scope',
            (string) $authorizationError->headers->get('Location'),
        );
        $this->assertStringContainsString(
            'iss='.rawurlencode(self::ISSUER),
            (string) $authorizationError->headers->get('Location'),
        );
        config(['bherila-auth.oauth_server.authorization_response_issuer.enabled' => false]);

        $token = $this->issueToken($user, $client, $redirectUri);
        $token->assertJsonStructure(['access_token', 'refresh_token']);

        config(['bherila-auth.oauth_server.enabled' => false]);
        $this->postJson('/oauth/register', [
            'client_name' => 'Disabled Client',
            'redirect_uris' => ['https://client.example.test/callback'],
        ])->assertNotFound();
    }

    public function test_dcr_rolls_back_the_client_when_registration_metadata_cannot_be_saved(): void
    {
        $before = Passport::client()->newQuery()->count();
        Passport::useClientModel(FailingDynamicRegistrationClient::class);
        $this->withoutExceptionHandling();
        $failure = null;

        try {
            $this->postJson('/oauth/register', [
                'client_name' => 'Rollback Client',
                'redirect_uris' => ['https://client.example.test/callback'],
                'grant_types' => ['authorization_code', 'refresh_token'],
                'response_types' => ['code'],
                'token_endpoint_auth_method' => 'none',
                'application_type' => 'web',
                'scope' => 'mcp:use',
            ]);
        } catch (RuntimeException $exception) {
            $failure = $exception;
        } finally {
            Passport::useClientModel(ResourceClient::class);
        }

        self::assertInstanceOf(RuntimeException::class, $failure);
        self::assertSame('Synthetic dynamic client metadata failure.', $failure->getMessage());
        self::assertSame($before, Passport::client()->newQuery()->count());
    }

    public function test_dcr_serializes_scopes_for_an_uncast_custom_column(): void
    {
        Schema::table('oauth_clients', static function (Blueprint $table): void {
            $table->text('registered_scopes')->nullable();
        });
        config([
            'bherila-auth.oauth_server.dynamic_clients.required_columns' => [
                'dynamically_registered_at',
                'registered_scopes',
            ],
            'bherila-auth.oauth_server.dynamic_clients.scopes_column' => 'registered_scopes',
        ]);

        $response = $this->postJson('/oauth/register', [
            'client_name' => 'Uncast Scope Client',
            'redirect_uris' => ['https://client.example.test/callback'],
            'scope' => 'mcp:use',
        ])->assertCreated();

        self::assertSame(
            '["mcp:use"]',
            DB::table('oauth_clients')
                ->where('id', $response->json('client_id'))
                ->value('registered_scopes'),
        );
    }

    public function test_hosted_public_registration_completes_the_resource_bound_authorization_flow(): void
    {
        $redirectUri = 'https://chatgpt.com/connector_platform_oauth_redirect';
        $user = User::query()->create([
            'name' => 'Hosted Client User',
            'email' => 'hosted-client@example.test',
            'password' => 'not-used',
        ]);
        $response = $this->postJson('/oauth/register', [
            'client_name' => 'ChatGPT',
            'redirect_uris' => [$redirectUri],
            'grant_types' => ['authorization_code', 'refresh_token'],
            'response_types' => ['code'],
            'token_endpoint_auth_method' => 'none',
            'application_type' => 'web',
            'scope' => 'mcp:use',
        ]);
        $response->assertCreated()
            ->assertJsonPath('client_name', 'ChatGPT')
            ->assertJsonPath('application_type', 'web')
            ->assertJsonPath('token_endpoint_auth_method', 'none')
            ->assertJsonMissingPath('client_secret');

        $client = Passport::client()->newQuery()->findOrFail($response->json('client_id'));
        $this->assertFalse($client->firstParty());

        $token = $this->issueToken($user, $client, $redirectUri)->assertOk();
        $claims = OAuthResourceIndicator::tokenClaims((string) $token->json('access_token'));
        $this->assertSame(self::ISSUER, $claims['iss'] ?? null);
        $this->assertSame(self::RESOURCE, $claims['resource'] ?? null);
        $this->assertContains(self::RESOURCE, $claims['aud'] ?? []);
    }

    public function test_explicit_empty_registration_scope_survives_laravel_input_normalization(): void
    {
        $response = $this->postJson('/oauth/register', [
            'client_name' => 'No Scope Client',
            'redirect_uris' => ['https://client.example.test/callback'],
            'scope' => '',
        ]);

        $response->assertCreated()->assertJsonPath('scope', '');
        $client = Passport::client()->newQuery()->findOrFail($response->json('client_id'));
        $this->assertSame([], $client->scopes);
    }

    /** @return array{User, Client} */
    private function userAndPublicClient(array $scopes): array
    {
        $user = User::query()->create([
            'name' => 'MCP User',
            'email' => 'mcp@example.test',
            'password' => 'not-used',
        ]);
        $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient(
            'Public MCP Client',
            ['http://127.0.0.1:1455/callback'],
            confidential: false,
        );
        $client->forceFill([
            'dynamically_registered_at' => now(),
            'scopes' => $scopes,
        ])->save();

        return [$user, $client->fresh()];
    }

    private function issueToken(
        User $user,
        Client $client,
        string $redirectUri = 'http://127.0.0.1:1455/callback',
    ): TestResponse {
        $verifier = str_repeat('z', 43);
        $challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
        $authorization = $this->actingAs($user)->get('/oauth/authorize?'.http_build_query([
            'response_type' => 'code',
            'client_id' => $client->getKey(),
            'redirect_uri' => $redirectUri,
            'scope' => 'mcp:use',
            'resource' => self::RESOURCE,
            'code_challenge' => $challenge,
            'code_challenge_method' => 'S256',
        ]));
        $authorization->assertOk();
        $approval = $this->actingAs($user)->post('/oauth/authorize', [
            'auth_token' => (string) session('authToken'),
        ]);
        $approval->assertRedirect();
        parse_str((string) parse_url((string) $approval->headers->get('Location'), PHP_URL_QUERY), $redirectQuery);

        return $this->postJson('/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => $client->getKey(),
            'redirect_uri' => $redirectUri,
            'code' => $redirectQuery['code'],
            'code_verifier' => $verifier,
            'resource' => self::RESOURCE,
        ])->assertOk();
    }

    private function disabledAccessTokenRepository(): PassportAccessTokenRepository
    {
        config(['bherila-auth.oauth_server.enabled' => false]);
        app()->forgetInstance(PassportAccessTokenRepository::class);
        app()->bind(
            PassportAccessTokenRepository::class,
            fn (): PassportAccessTokenRepository => new PassportAccessTokenRepository(app('events')),
        );
        (new AuthServiceProvider(app()))->register();

        return app(PassportAccessTokenRepository::class);
    }

    /** @return array{string, string} */
    private function passportKeys(): array
    {
        $key = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
            'private_key_bits' => 2048,
        ]);
        if ($key === false || ! openssl_pkey_export($key, $privateKey)) {
            throw new RuntimeException('Unable to create Passport test keys.');
        }
        $details = openssl_pkey_get_details($key);
        if (! is_array($details) || ! is_string($details['key'] ?? null)) {
            throw new RuntimeException('Unable to read Passport test public key.');
        }

        return [$privateKey, $details['key']];
    }
}
