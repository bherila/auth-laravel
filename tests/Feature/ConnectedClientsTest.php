<?php

namespace BWH\Auth\Tests\Feature;

use BWH\Auth\AuthServiceProvider;
use BWH\Auth\Http\Middleware\ExpectOAuthResource;
use BWH\Auth\OAuth\Credentials\ApiCredentialService;
use BWH\Auth\OAuth\Server\AgentOAuthServer;
use BWH\Auth\OAuth\Server\ProviderIdentityTokens;
use BWH\Auth\Testing\AssertsAgentOAuthContract;
use BWH\Auth\Tests\Fixtures\User;
use BWH\Auth\Tests\TestCase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use Laravel\Passport\ClientRepository;
use Laravel\Passport\Events\AccessTokenRevoked;
use Laravel\Passport\Http\Middleware\CheckToken;
use Laravel\Passport\Passport;
use Laravel\Passport\PassportServiceProvider;

/**
 * Connected OAuth clients: every client holding a person's live grants, dynamic
 * (self-registered) agents included, and a disconnect that revokes only that
 * person's grants, at once, without deleting the registration.
 */
final class ConnectedClientsTest extends TestCase
{
    use AssertsAgentOAuthContract;

    private const string APP = 'https://app.example.test';

    private const string REDIRECT = 'http://127.0.0.1:3210/callback';

    private const string BASE = '/account/api-credentials';

    private User $user;

    private User $other;

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
            [
                'resource_required_scopes' => ['mcp:use'],
                'credentials' => ['enabled' => true, 'token_lifetimes' => ['P30D']],
            ],
            self::APP,
        ));
        // As the package defaults merge in under an application's configuration at boot.
        $app['config']->set('bherila-auth.oauth_server.dynamic_clients', (require __DIR__.'/../../config/bherila-auth.php')['oauth_server']['dynamic_clients']);
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
        $this->other = User::query()->create(['name' => 'Other', 'email' => 'other@example.test', 'password' => 'not-used']);
    }

    public function test_every_kind_of_client_is_listed_with_its_grant_and_never_a_secret(): void
    {
        $agent = $this->registerDynamicClient('Agent');
        $this->agentOAuthCodeFlow($this->user, $agent, 'mcp:use', self::REDIRECT)->assertOk();

        $app = $this->actingAs($this->user)->postJson(self::BASE.'/apps', [
            'name' => 'My app', 'redirect_uris' => [self::REDIRECT], 'confidential' => true, 'scopes' => ['items:read'],
        ])->assertCreated()->json('data');
        $this->agentOAuthCodeFlow($this->user, $app['client_id'], 'items:read', self::REDIRECT, ['client_secret' => $app['client_secret']])->assertOk();

        $firstParty = app(ClientRepository::class)->createAuthorizationCodeGrantClient('Provisioned', [self::REDIRECT], confidential: true);
        $this->forceToken('first-party-token', $this->user, (string) $firstParty->getKey(), ['items:read', 'items:write']);

        // A personal API token rides the personal-access client, which is managed token by token.
        $this->actingAs($this->user)->postJson(self::BASE.'/tokens', ['name' => 'Key', 'scopes' => ['items:read'], 'lifetime' => 'P30D'])->assertCreated();

        $response = $this->actingAs($this->user)->getJson(self::BASE.'/connections')->assertOk()
            ->assertHeader('Cache-Control', 'no-store, private');
        $listed = collect($response->json('data'))->keyBy('id');

        $this->assertEqualsCanonicalizing([$agent, $app['client_id'], (string) $firstParty->getKey()], $listed->keys()->all());
        $this->assertSame('dynamic', $listed[$agent]['kind']);
        $this->assertSame('Agent', $listed[$agent]['name']);
        $this->assertSame(['mcp:use'], $listed[$agent]['scopes']);
        $this->assertSame([self::REDIRECT], $listed[$agent]['redirect_uris']);
        $this->assertNotNull($listed[$agent]['created_at']);
        $this->assertNotNull($listed[$agent]['last_issued_at']);
        $this->assertSame(self::BASE.'/connections/'.$agent, $listed[$agent]['revoke_href']);
        $this->assertSame('user_registered', $listed[$app['client_id']]['kind']);
        $this->assertSame(['items:read'], $listed[$app['client_id']]['scopes']);
        $this->assertSame('first_party', $listed[(string) $firstParty->getKey()]['kind']);
        $this->assertSame(['items:read', 'items:write'], $listed[(string) $firstParty->getKey()]['scopes']);
        $this->assertSame(['id', 'name', 'kind', 'scopes', 'redirect_uris', 'created_at', 'last_issued_at', 'revoke_href'], array_keys($listed[$agent]));

        $body = (string) $response->getContent();
        $this->assertStringNotContainsString('secret', $body);
        $this->assertStringNotContainsString((string) $app['client_secret'], $body);
        $this->assertStringNotContainsString((string) Passport::client()->newQuery()->findOrFail($app['client_id'])->getRawOriginal('secret'), $body);

        // The personal-access client cannot be disconnected wholesale; its tokens are revoked one by one.
        $personal = Passport::token()->newQuery()->where('user_id', $this->user->id)->where('name', 'like', 'api-token: %')->sole();
        $this->actingAs($this->user)->deleteJson(self::BASE.'/connections/'.$personal->client_id)->assertOk()
            ->assertJsonPath('data.revoked_access_tokens', 0);
        $this->assertFalse((bool) $personal->fresh()->revoked);
    }

    public function test_disconnecting_ends_the_persons_access_at_once_and_spares_everyone_else(): void
    {
        $agent = $this->registerDynamicClient('Shared agent');
        $mine = $this->agentOAuthCodeFlow($this->user, $agent, 'mcp:use', self::REDIRECT)->assertOk()->json();
        $theirs = $this->agentOAuthCodeFlow($this->other, $agent, 'mcp:use', self::REDIRECT)->assertOk()->json();
        $this->assertBearer($mine['access_token'], 200);

        Event::fake([AccessTokenRevoked::class]);
        $this->actingAs($this->user)->deleteJson(self::BASE.'/connections/'.$agent)->assertOk()
            ->assertHeader('Cache-Control', 'no-store, private')
            ->assertJsonPath('data', ['revoked' => true, 'revoked_access_tokens' => 1]);
        Event::assertDispatchedTimes(AccessTokenRevoked::class, 1);

        // Verification refuses the revoked access token and the refresh token on the next request.
        $this->assertBearer($mine['access_token'], 401);
        $this->refresh($agent, $mine['refresh_token'])->assertStatus(400)->assertJsonPath('error', 'invalid_grant');
        $this->assertSame([], $this->actingAs($this->user)->getJson(self::BASE.'/connections')->json('data'));

        // Another person's grant to the same client, and the registration itself, are untouched.
        $this->assertBearer($theirs['access_token'], 200);
        $this->assertSame([$agent], array_column($this->actingAs($this->other)->getJson(self::BASE.'/connections')->json('data'), 'id'));
        $client = Passport::client()->newQuery()->findOrFail($agent);
        $this->assertFalse((bool) $client->revoked);
        $this->refresh($agent, $theirs['refresh_token'])->assertOk();

        // Idempotent; the person can connect the same client again.
        $this->actingAs($this->user)->deleteJson(self::BASE.'/connections/'.$agent)->assertOk()
            ->assertJsonPath('data.revoked_access_tokens', 0);
        $again = $this->agentOAuthCodeFlow($this->user, $agent, 'mcp:use', self::REDIRECT)->assertOk()->json();
        $this->assertBearer($again['access_token'], 200);
    }

    public function test_only_the_owner_can_list_or_disconnect_their_grants(): void
    {
        $agent = $this->registerDynamicClient('Agent');
        $mine = $this->agentOAuthCodeFlow($this->user, $agent, 'mcp:use', self::REDIRECT)->assertOk()->json();

        // Another signed-in person sees nothing of it, and "disconnecting" it touches only their own (absent) grants.
        $this->assertSame([], $this->actingAs($this->other)->getJson(self::BASE.'/connections')->assertOk()->json('data'));
        $this->actingAs($this->other)->deleteJson(self::BASE.'/connections/'.$agent)->assertOk()
            ->assertJsonPath('data.revoked_access_tokens', 0);
        $this->assertSame(0, Passport::token()->newQuery()->where('revoked', true)->count());
        $this->assertSame(0, Passport::refreshToken()->newQuery()->where('revoked', true)->count());
        $this->assertBearer($mine['access_token'], 200);

        // An unknown client is the same no-op, with nothing written.
        $this->actingAs($this->other)->deleteJson(self::BASE.'/connections/00000000-0000-4000-8000-000000000000')->assertOk()
            ->assertJsonPath('data.revoked_access_tokens', 0);

        // Not signed in: refused before anything is read or revoked.
        $this->app['auth']->forgetGuards();
        auth()->guard('web')->logout();
        $this->getJson(self::BASE.'/connections')->assertUnauthorized();
        $this->deleteJson(self::BASE.'/connections/'.$agent)->assertUnauthorized();
        $this->assertBearer($mine['access_token'], 200);

        // A bearer token, even the person's own, is not a session: no credential can manage another.
        $this->app['auth']->forgetGuards();
        $this->deleteJson(self::BASE.'/connections/'.$agent, [], ['Authorization' => 'Bearer '.$mine['access_token']])->assertUnauthorized();
        $this->assertBearer($mine['access_token'], 200);
    }

    public function test_a_refresh_token_outliving_its_purged_access_row_is_listed_and_revoked(): void
    {
        $agent = $this->registerDynamicClient('Long-lived agent');
        $mine = $this->agentOAuthCodeFlow($this->user, $agent, 'mcp:use', self::REDIRECT)->assertOk()->json();
        $access = Passport::token()->newQuery()->where('user_id', $this->user->id)->where('client_id', $agent)->sole();
        $refresh = Passport::refreshToken()->newQuery()->where('access_token_id', $access->getKey())->sole();
        $theirs = $this->agentOAuthCodeFlow($this->other, $agent, 'mcp:use', self::REDIRECT)->assertOk()->json();
        $theirAccess = Passport::token()->newQuery()->where('user_id', $this->other->id)->sole();
        $theirRefresh = Passport::refreshToken()->newQuery()->where('access_token_id', $theirAccess->getKey())->sole();
        $access->delete();
        $theirAccess->delete();

        $listed = $this->actingAs($this->user)->getJson(self::BASE.'/connections')->json('data');
        $this->assertSame([$agent], array_column($listed, 'id'));
        $this->assertSame([], $listed[0]['scopes'], 'Scopes are not guessed once the access row is gone');

        $this->actingAs($this->user)->deleteJson(self::BASE.'/connections/'.$agent)->assertOk()
            ->assertJsonPath('data.revoked_access_tokens', 0);
        $this->assertTrue((bool) $refresh->fresh()->revoked);
        $this->assertFalse((bool) $theirRefresh->fresh()->revoked, "Another person's orphaned refresh token survives");
        $this->refresh($agent, $mine['refresh_token'])->assertStatus(400)->assertJsonPath('error', 'invalid_grant');
        $this->refresh($agent, $theirs['refresh_token'])->assertOk();
    }

    public function test_an_owner_record_disagreeing_with_a_linked_access_row_is_not_taken(): void
    {
        $agent = $this->registerDynamicClient('Shared agent');
        $this->agentOAuthCodeFlow($this->user, $agent, 'mcp:use', self::REDIRECT)->assertOk();
        $theirs = $this->agentOAuthCodeFlow($this->other, $agent, 'mcp:use', self::REDIRECT)->assertOk()->json();
        $theirAccess = Passport::token()->newQuery()->where('user_id', $this->other->id)->sole();
        $theirRefresh = Passport::refreshToken()->newQuery()->where('access_token_id', $theirAccess->getKey())->sole();
        // Inconsistent records: their refresh token claims this person, but its live access row is theirs.
        $theirRefresh->forceFill([ProviderIdentityTokens::OWNER_COLUMN => (string) $this->user->id])->save();

        $this->actingAs($this->user)->deleteJson(self::BASE.'/connections/'.$agent)->assertOk();

        $this->assertFalse((bool) $theirRefresh->fresh()->revoked, 'The linked access row names its owner');
        $this->refresh($agent, $theirs['refresh_token'])->assertOk();
    }

    public function test_expired_revoked_and_revoked_client_grants_are_not_listed(): void
    {
        $repository = app(ClientRepository::class);
        $expired = $repository->createAuthorizationCodeGrantClient('Expired', [self::REDIRECT], confidential: false);
        $this->forceToken('expired-token', $this->user, (string) $expired->getKey(), ['items:read'], expiresAt: now()->subMinute());
        $revoked = $repository->createAuthorizationCodeGrantClient('Revoked token', [self::REDIRECT], confidential: false);
        $this->forceToken('revoked-token', $this->user, (string) $revoked->getKey(), ['items:read'], revoked: true);
        $gone = $repository->createAuthorizationCodeGrantClient('Revoked client', [self::REDIRECT], confidential: false);
        $this->forceToken('gone-token', $this->user, (string) $gone->getKey(), ['items:read']);
        $gone->forceFill(['revoked' => true])->save();
        $live = $repository->createAuthorizationCodeGrantClient('Live', [self::REDIRECT], confidential: false);
        $this->forceToken('live-token', $this->user, (string) $live->getKey(), ['items:read']);
        $this->forceToken('their-token', $this->other, (string) $expired->getKey(), ['items:read']);

        $this->assertSame([(string) $live->getKey()], array_column(app(ApiCredentialService::class)->connectedClients($this->user), 'id'));
    }

    public function test_disconnecting_revokes_pending_authorization_codes(): void
    {
        $agent = $this->registerDynamicClient('Agent');
        $code = fn (User $user, string $id): bool => (bool) Passport::authCode()->newQuery()->forceCreate([
            'id' => $id, 'user_id' => $user->id, 'client_id' => $agent, 'scopes' => '["mcp:use"]', 'revoked' => false, 'expires_at' => now()->addMinutes(5),
        ]);
        $code($this->user, 'mine');
        $code($this->other, 'theirs');

        app(ApiCredentialService::class)->disconnectClient($this->user, $agent);

        $this->assertTrue((bool) Passport::authCode()->newQuery()->findOrFail('mine')->revoked);
        $this->assertFalse((bool) Passport::authCode()->newQuery()->findOrFail('theirs')->revoked);
    }

    public function test_with_durable_revocation_it_raises_the_owner_client_barrier_only(): void
    {
        config(['bherila-auth.oauth_server.revocation.enabled' => true]);
        $agent = $this->registerDynamicClient('Agent');
        $sibling = $this->registerDynamicClient('Sibling agent');
        $mine = $this->agentOAuthCodeFlow($this->user, $agent, 'mcp:use', self::REDIRECT)->assertOk()->json();
        $myOther = $this->agentOAuthCodeFlow($this->user, $sibling, 'mcp:use', self::REDIRECT)->assertOk()->json();
        $theirs = $this->agentOAuthCodeFlow($this->other, $agent, 'mcp:use', self::REDIRECT)->assertOk()->json();

        $this->actingAs($this->user)->deleteJson(self::BASE.'/connections/'.$agent)->assertOk()
            ->assertJsonPath('data.revoked_access_tokens', 1);

        $this->assertBearer($mine['access_token'], 401);
        $this->refresh($agent, $mine['refresh_token'])->assertStatus(400)->assertJsonPath('error', 'invalid_grant');
        $this->assertSame(1, DB::table('oauth_credential_lineages')->where('revoked', true)->count());
        $this->refresh($sibling, $myOther['refresh_token'])->assertOk();
        $this->refresh($agent, $theirs['refresh_token'])->assertOk();

        // A fresh authorization after the barrier connects again.
        $again = $this->agentOAuthCodeFlow($this->user, $agent, 'mcp:use', self::REDIRECT)->assertOk()->json();
        $this->assertBearer($again['access_token'], 200);
    }

    private function registerDynamicClient(string $name): string
    {
        $this->app['auth']->forgetGuards();

        return (string) $this->postJson('/oauth/register', [
            'client_name' => $name,
            'redirect_uris' => [self::REDIRECT],
            'grant_types' => ['authorization_code', 'refresh_token'],
            'response_types' => ['code'],
            'token_endpoint_auth_method' => 'none',
            'scope' => 'mcp:use',
        ])->assertCreated()->json('client_id');
    }

    /** @param list<string> $scopes */
    private function forceToken(string $id, User $user, string $clientId, array $scopes, bool $revoked = false, ?\DateTimeInterface $expiresAt = null): void
    {
        Passport::token()->newQuery()->forceCreate([
            'id' => $id, 'user_id' => $user->id, 'client_id' => $clientId, 'name' => null,
            'scopes' => $scopes, 'revoked' => $revoked, 'expires_at' => $expiresAt ?? now()->addDay(),
        ]);
    }

    private function assertBearer(string $token, int $status): void
    {
        $this->app['auth']->forgetGuards();
        $this->postJson('/api/v1/mcp', [], ['Authorization' => 'Bearer '.$token])->assertStatus($status);
        $this->app['auth']->forgetGuards();
    }

    /** @return TestResponse<\Symfony\Component\HttpFoundation\Response> */
    private function refresh(string $clientId, string $refreshToken): TestResponse
    {
        $this->app['auth']->forgetGuards();

        return $this->post('/oauth/token', [
            'grant_type' => 'refresh_token', 'client_id' => $clientId, 'refresh_token' => $refreshToken,
        ], ['Accept' => 'application/json']);
    }
}
