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

/** Provider identity enforcement on the OAuth credentials this application issues. */
final class ProviderIdentityTokensTest extends TestCase
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
        $app['config']->set('bherila-auth.provider_identity.enabled', true);
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

    public function test_credentials_carry_the_authorizing_session_generation_through_exchange_and_refresh(): void
    {
        Http::fake(fn () => Http::response($this->activeStatus()));
        [$client, $tokens] = $this->connect($this->user());

        $code = Passport::authCode()->newQuery()->sole();
        $this->assertSame(['subject-example', 7], [$code->provider_subject, (int) $code->provider_generation]);
        $token = Passport::token()->newQuery()->sole();
        $this->assertSame(['subject-example', 7], [$token->provider_subject, (int) $token->provider_generation]);

        $this->useToken($tokens['access_token'])->assertOk();
        $refreshed = $this->refresh($client, $tokens['refresh_token'])->assertOk()->json();
        $this->useToken($refreshed['access_token'])->assertOk();

        $this->assertSame([7, 7], Passport::token()->newQuery()->pluck('provider_generation')->map(fn ($g) => (int) $g)->all());
        Http::assertSentCount(1 + 1, 'One shared check for use, one fresh check for renewal');
    }

    public function test_a_refresh_token_stays_checkable_after_its_access_token_is_purged(): void
    {
        Http::fake(fn () => Http::response($this->activeStatus()));
        [$client, $tokens] = $this->connect($this->user());
        $refresh = Passport::refreshToken()->newQuery()->sole();
        $this->assertSame(['subject-example', 7], [$refresh->provider_subject, (int) $refresh->provider_generation]);
        Passport::token()->newQuery()->delete();

        $this->refresh($client, $tokens['refresh_token'])->assertOk();
    }

    public function test_a_reset_or_disable_at_the_provider_ends_use_and_renewal(): void
    {
        Http::fake(['*' => Http::sequence()->push($this->activeStatus())->push($this->activeStatus(8))->push($this->activeStatus(8))]);
        [$client, $tokens] = $this->connect($this->user());
        $this->useToken($tokens['access_token'])->assertOk();

        $this->travel(300)->seconds();
        $this->useToken($tokens['access_token'])->assertUnauthorized();
        $this->refresh($client, $tokens['refresh_token'])->assertStatus(400)->assertJsonPath('error', 'invalid_grant');
    }

    public function test_an_unavailable_provider_is_retryable_and_never_consumes_the_refresh_token(): void
    {
        Http::fake(['*' => Http::sequence()->pushStatus(503)->pushStatus(503)->push($this->activeStatus())]);
        [$client, $tokens] = $this->connect($this->user());

        $this->useToken($tokens['access_token'])->assertStatus(503)->assertHeader('Retry-After', '30');
        $this->refresh($client, $tokens['refresh_token'])->assertStatus(503);
        $this->assertFalse((bool) Passport::refreshToken()->newQuery()->sole()->revoked);

        $this->refresh($client, $tokens['refresh_token'])->assertOk();
    }

    public function test_credentials_issued_before_enforcement_are_retired_not_upgraded(): void
    {
        Http::fake(fn () => Http::response($this->activeStatus()));
        config(['bherila-auth.provider_identity.enabled' => false]);
        [$client, $tokens] = $this->connect($this->user());
        Passport::token()->newQuery()->update(['provider_subject' => null, 'provider_generation' => null]);
        Passport::refreshToken()->newQuery()->update(['provider_subject' => null, 'provider_generation' => null, 'provider_user_id' => null]);

        config(['bherila-auth.provider_identity.enabled' => true]);
        $this->useToken($tokens['access_token'])->assertUnauthorized();
        $this->refresh($client, $tokens['refresh_token'])->assertStatus(400);
        Http::assertNothingSent();
    }

    public function test_credentials_issued_while_enforcement_is_off_are_stamped_so_enabling_it_keeps_them(): void
    {
        Http::fake(fn () => Http::response($this->activeStatus()));
        config(['bherila-auth.provider_identity.enabled' => false]);
        [, $tokens] = $this->connect($this->user());
        Http::assertNothingSent();

        config(['bherila-auth.provider_identity.enabled' => true]);
        $this->useToken($tokens['access_token'])->assertOk();
    }

    public function test_a_token_cannot_follow_its_account_to_a_different_provider_subject(): void
    {
        Http::fake(fn ($request) => Http::response($this->activeStatus(7, $request['subject'])));
        $user = $this->user();
        [, $tokens] = $this->connect($user);
        $user->forceFill(['oauth_subject' => 'subject-other'])->save();

        $this->useToken($tokens['access_token'])->assertUnauthorized();
    }

    public function test_a_token_stops_when_its_account_loses_the_provider_binding(): void
    {
        Http::fake(fn () => Http::response($this->activeStatus()));
        $user = $this->user();
        [$client, $tokens] = $this->connect($user);
        $user->forceFill(['oauth_provider' => null, 'oauth_subject' => null])->save();

        $this->useToken($tokens['access_token'])->assertUnauthorized();
        $this->refresh($client, $tokens['refresh_token'])->assertStatus(400);
    }

    public function test_authorization_without_a_verified_session_issues_no_code(): void
    {
        Http::fake();
        $user = $this->user();
        $client = $this->client();

        $this->agentOAuthCodeFlowWithoutAssertions($user, $client)->assertUnauthorized();
        $this->assertSame(0, Passport::authCode()->newQuery()->count());
    }

    public function test_unbound_accounts_are_left_to_the_application(): void
    {
        Http::fake();
        [$client, $tokens] = $this->connect($this->user(null));
        $this->useToken($tokens['access_token'])->assertOk();
        $this->refresh($client, $tokens['refresh_token'])->assertOk();
        Http::assertNothingSent();
    }

    public function test_personal_tokens_take_the_issuing_session_generation_and_need_one(): void
    {
        Http::fake(fn () => Http::response($this->activeStatus()));
        $user = $this->user();
        $issued = $this->actingAs($user)->withSession($this->sessionState())
            ->postJson('/account/api-credentials/tokens', ['name' => 'Connector', 'scopes' => ['items:read'], 'lifetime' => 'P30D'])
            ->assertCreated()->json('data.token');
        $row = Passport::token()->newQuery()->sole();
        $this->assertSame(['subject-example', 7], [$row->provider_subject, (int) $row->provider_generation]);
        $this->useToken($issued)->assertOk();

        $this->flushSession();
        $this->actingAs($user)->postJson('/account/api-credentials/tokens', ['name' => 'Unverified', 'scopes' => ['items:read'], 'lifetime' => 'P30D'])
            ->assertUnauthorized();
        $this->assertSame(1, Passport::token()->newQuery()->count());
    }

    public function test_applications_can_check_freshly_before_a_privileged_operation(): void
    {
        Http::fake(['*' => Http::sequence()->push($this->activeStatus())->push(['contract_version' => 1, 'active' => false])]);
        $user = $this->user();
        $this->connect($user);
        $token = (string) Passport::token()->newQuery()->sole()->getKey();
        $tokens = app(\BWH\Auth\OAuth\Server\ProviderIdentityTokens::class);

        $this->assertTrue($tokens->verifyUser($user, $token));
        $this->assertFalse($tokens->verifyUser($user, $token), 'A fresh check sees the disable at once');
        $this->assertFalse($tokens->verifyUser($this->user('subject-other'), $token), 'Another person\'s token is never theirs');
    }

    public function test_the_transient_token_cookie_route_is_refused(): void
    {
        $this->actingAs($this->user())->post('/oauth/token/refresh')->assertNotFound();
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
