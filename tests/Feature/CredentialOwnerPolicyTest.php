<?php

namespace BWH\Auth\Tests\Feature;

use BWH\Auth\AuthServiceProvider;
use BWH\Auth\Http\Middleware\ExpectOAuthResource;
use BWH\Auth\OAuth\Server\AgentOAuthServer;
use BWH\Auth\OAuth\Session\ProviderIdentityStatusClient;
use BWH\Auth\Testing\AssertsAgentOAuthContract;
use BWH\Auth\Tests\Fixtures\User;
use BWH\Auth\Tests\TestCase;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Illuminate\Testing\TestResponse;
use Laravel\Passport\Passport;
use Laravel\Passport\PassportServiceProvider;

/** The application's credential-owner policy on every OAuth credential path. */
final class CredentialOwnerPolicyTest extends TestCase
{
    use AssertsAgentOAuthContract;

    private const APP = 'https://app.example.test';

    private const REDIRECT = 'http://127.0.0.1:3210/callback';

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
        $app['config']->set('app.env', 'testing');
        $app['config']->set('passport.private_key', $private);
        $app['config']->set('passport.public_key', openssl_pkey_get_details($key)['key']);
        $app['config']->set('passport.middleware', AgentOAuthServer::passportMiddleware(['web']));
        $app['config']->set('auth.guards.api', ['driver' => 'passport', 'provider' => 'users']);
        $app['config']->set('bherila-auth.oauth_server', AgentOAuthServer::config(['items:read' => 'Read items'], [
            'credentials' => ['enabled' => true, 'token_lifetimes' => ['P30D']],
        ], self::APP));
        $app['config']->set('bherila-auth.oauth_client', [
            'provider' => 'example-provider',
            'base_url' => 'https://identity.example.test',
            'client_id' => 'example-client',
            'client_secret' => 'example-secret',
            'redirect_uri' => self::APP.'/oauth/callback',
            'token_path' => '/oauth/token',
            'identity_path' => '/api/oauth/user',
        ]);
        $app['config']->set('bherila-auth.provider_identity.enabled', false);
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
        Schema::table('users', function (Blueprint $table): void {
            $table->string('oauth_provider')->nullable();
            $table->string('oauth_subject')->nullable();
        });
    }

    protected function setUp(): void
    {
        parent::setUp();
        // Passport's scope registry is process-wide; another test may have left its own.
        Passport::tokensCan(['items:read' => 'Read items']);
        AgentOAuthServer::routes();
        Route::get('/api/v1/items', fn () => response()->json(['ok' => true]))->middleware([ExpectOAuthResource::class, 'auth:api']);
        $this->travelTo(Carbon::parse('2026-01-01T00:00:00Z'));
        Http::preventStrayRequests();
        self::$refused = [];
        $this->app->instance(\BWH\Auth\OAuth\Credentials\CredentialOwnerPolicy::class, new class implements \BWH\Auth\OAuth\Credentials\CredentialOwnerPolicy
        {
            public function mayHoldCredentials(\Illuminate\Contracts\Auth\Authenticatable $owner): bool
            {
                return ! in_array((string) $owner->getAuthIdentifier(), CredentialOwnerPolicyTest::$refused, true);
            }
        });
    }

    /** @var list<string> accounts the application has disabled */
    public static array $refused = [];

    private function disable(User $user): void
    {
        self::$refused[] = (string) $user->getKey();
    }

    private function enable(User $user): void
    {
        self::$refused = array_values(array_diff(self::$refused, [(string) $user->getKey()]));
    }

    private function user(?string $subject = 'subject-example'): User
    {
        return User::query()->create([
            'name' => 'Example User', 'email' => uniqid('user-', true).'@example.test', 'password' => 'unused',
            'oauth_provider' => $subject === null ? null : 'example-provider', 'oauth_subject' => $subject,
        ]);
    }

    private function sessionState(int $generation = 7, string $subject = 'subject-example'): array
    {
        return ['bherila_auth.provider_session' => [
            'context' => app(ProviderIdentityStatusClient::class)->context(),
            'provider' => 'example-provider',
            'subject' => $subject,
            'generation' => $generation,
            'checked_at' => Carbon::now()->getTimestamp(),
            'name' => 'Example User',
            'email' => 'user@example.test',
        ]];
    }

    private function activeStatus(int $generation = 7, string $subject = 'subject-example'): array
    {
        return ['contract_version' => 1, 'active' => true, 'subject' => $subject, 'credential_version' => $generation];
    }

    private function client(): string
    {
        return (string) $this->postJson('/oauth/register', [
            'client_name' => 'Example agent',
            'redirect_uris' => [self::REDIRECT],
            'grant_types' => ['authorization_code', 'refresh_token'],
            'response_types' => ['code'],
            'token_endpoint_auth_method' => 'none',
            'scope' => 'items:read',
        ])->assertCreated()->json('client_id');
    }

    /** @return array{0: string, 1: array<string, mixed>} client id and token response */
    private function connect(User $user, int $generation = 7): array
    {
        $client = $this->client();
        $this->withSession($this->sessionState($generation, (string) $user->oauth_subject));
        $tokens = $this->agentOAuthCodeFlow($user, $client, 'items:read', self::REDIRECT)->assertOk()->json();
        $this->app['auth']->forgetGuards();
        $this->flushSession();

        return [$client, $tokens];
    }

    private function refresh(string $client, string $refreshToken): TestResponse
    {
        $this->app['auth']->forgetGuards();

        return $this->post('/oauth/token', [
            'grant_type' => 'refresh_token', 'client_id' => $client, 'refresh_token' => $refreshToken,
        ], ['Accept' => 'application/json']);
    }

    private function useToken(string $accessToken): TestResponse
    {
        $this->app['auth']->forgetGuards();

        return $this->getJson('/api/v1/items', ['Authorization' => 'Bearer '.$accessToken]);
    }

    public function test_a_disabled_account_cannot_use_or_refresh_and_its_refresh_token_survives(): void
    {
        $user = $this->user();
        [$client, $tokens] = $this->connect($user);
        $this->useToken($tokens['access_token'])->assertOk();

        $this->disable($user);
        $this->useToken($tokens['access_token'])->assertUnauthorized();
        $this->refresh($client, $tokens['refresh_token'])->assertStatus(400)->assertJsonPath('error', 'invalid_grant');
        $this->assertFalse((bool) Passport::refreshToken()->newQuery()->sole()->revoked, 'A refused refresh is not consumed');

        $this->enable($user);
        $this->refresh($client, $tokens['refresh_token'])->assertOk();
    }

    public function test_a_disabled_account_is_issued_nothing(): void
    {
        $user = $this->user();
        $this->disable($user);
        $client = $this->client();

        $this->agentOAuthCodeFlowWithoutAssertions($user, $client)->assertForbidden()->assertJsonPath('error', 'access_denied');
        $this->assertSame(0, Passport::authCode()->newQuery()->count());
        $this->actingAs($user)->postJson('/account/api-credentials/tokens', ['name' => 'x', 'scopes' => ['items:read'], 'lifetime' => 'P30D'])
            ->assertForbidden();
        $this->assertSame(0, Passport::token()->newQuery()->count());
    }

    public function test_a_code_issued_before_the_account_was_disabled_cannot_be_exchanged(): void
    {
        $user = $this->user();
        $client = $this->client();
        $verifier = str_repeat('v', 64);
        $authorize = $this->actingAs($user)->get('/oauth/authorize?'.http_build_query([
            'response_type' => 'code', 'client_id' => $client, 'redirect_uri' => self::REDIRECT,
            'scope' => 'items:read', 'state' => 'example-state',
            'code_challenge' => rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '='),
            'code_challenge_method' => 'S256',
        ]));
        $approval = $authorize->isRedirect() ? $authorize : $this->actingAs($user)->post('/oauth/authorize', ['auth_token' => (string) session('authToken')]);
        parse_str((string) parse_url((string) $approval->headers->get('Location'), PHP_URL_QUERY), $query);

        $this->disable($user);
        $this->post('/oauth/token', [
            'grant_type' => 'authorization_code', 'client_id' => $client, 'redirect_uri' => self::REDIRECT,
            'code' => $query['code'], 'code_verifier' => $verifier,
        ], ['Accept' => 'application/json'])->assertStatus(400);
    }

    public function test_revoking_on_disable_is_durable_across_re_enabling(): void
    {
        $user = $this->user();
        [$client, $tokens] = $this->connect($user);
        [$client2, $tokens2] = $this->connect($user);
        // One grant's access token already purged, as Passport's purge does to expired tokens.
        Passport::token()->newQuery()->whereKey(Passport::refreshToken()->newQuery()->latest('expires_at')->first()->access_token_id)->delete();
        $revoked = [];
        \Illuminate\Support\Facades\Event::listen(\Laravel\Passport\Events\AccessTokenRevoked::class, function ($event) use (&$revoked): void {
            $revoked[] = $event->tokenId;
        });
        $this->disable($user);
        $this->assertSame(1, app(\BWH\Auth\OAuth\Credentials\OAuthCredentialOwners::class)->revokeAll($user));
        $this->assertCount(1, $revoked, 'Each live access token is revoked through the repository');
        $this->assertSame(0, Passport::refreshToken()->newQuery()->where('revoked', false)->count(), 'Including a refresh token whose access token was purged');

        $this->enable($user);
        $this->useToken($tokens['access_token'])->assertUnauthorized();
        $this->refresh($client, $tokens['refresh_token'])->assertStatus(400);
    }

    public function test_a_bound_policy_needs_the_refresh_owner_column(): void
    {
        \Illuminate\Support\Facades\Schema::table('oauth_refresh_tokens', fn ($table) => $table->dropColumn('provider_user_id'));
        $user = $this->user();
        $client = $this->client();

        // Without it a refresh token becomes unusable once its access token is purged, so
        // issuing one fails loudly instead.
        $this->withoutExceptionHandling();
        $this->expectExceptionMessage('provider identity columns are required');
        $this->connect($user);
    }

    /** The authorize and approve steps, without the helper's assertion that a code came back. */
    private function agentOAuthCodeFlowWithoutAssertions(User $user, string $client): TestResponse
    {
        $verifier = str_repeat('v', 64);
        $authorize = $this->actingAs($user)->get('/oauth/authorize?'.http_build_query([
            'response_type' => 'code', 'client_id' => $client, 'redirect_uri' => self::REDIRECT,
            'scope' => 'items:read', 'state' => 'example-state',
            'code_challenge' => rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '='),
            'code_challenge_method' => 'S256',
        ]));

        return $authorize->isRedirect() || $authorize->status() !== 200
            ? $authorize
            : $this->actingAs($user)->post('/oauth/authorize', ['auth_token' => (string) session('authToken')]);
    }
}
