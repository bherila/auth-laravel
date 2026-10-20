<?php

namespace BWH\Auth\Tests\Feature;

use BWH\Auth\AuthServiceProvider;
use BWH\Auth\Http\Middleware\EnforceOAuthPkce;
use BWH\Auth\Http\Middleware\EnforceOAuthResourceIndicator;
use BWH\Auth\Http\Middleware\ExpectOAuthResource;
use BWH\Auth\OAuth\Credentials\OAuthCredentialOwners;
use BWH\Auth\OAuth\Server\CredentialLineages;
use BWH\Auth\OAuth\Server\OAuthResourceIndicator;
use BWH\Auth\OAuth\Server\ResourceAuthCodeRepository;
use BWH\Auth\OAuth\Server\ResourceRefreshTokenRepository;
use BWH\Auth\Tests\Fixtures\User;
use BWH\Auth\Tests\TestCase;
use Closure;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Illuminate\Testing\TestResponse;
use Laravel\Passport\Bridge\AccessToken;
use Laravel\Passport\Bridge\AccessTokenRepository;
use Laravel\Passport\Bridge\AuthCodeRepository;
use Laravel\Passport\Bridge\Client as BridgeClient;
use Laravel\Passport\Bridge\RefreshTokenRepository;
use Laravel\Passport\Bridge\Scope;
use Laravel\Passport\Client;
use Laravel\Passport\ClientRepository;
use Laravel\Passport\Events\AccessTokenCreated;
use Laravel\Passport\Passport;
use Laravel\Passport\PassportServiceProvider;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\Entities\AuthCodeEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use PHPUnit\Framework\Attributes\DataProvider;
use RuntimeException;

final class OAuthCredentialLineagesTest extends TestCase
{
    private const string RESOURCE = 'https://auth.example.test/api';

    private const string CALLBACK = 'https://client.example.test/callback';

    private const string VERIFIER = 'synthetic-verifier-0000000000000000000000000000000';

    protected function getPackageProviders($app): array
    {
        return [AuthServiceProvider::class, PassportServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
        if ($key === false || ! openssl_pkey_export($key, $private)) {
            throw new RuntimeException('Unable to create synthetic OAuth test key.');
        }
        $app['config']->set('passport.private_key', $private);
        $app['config']->set('passport.public_key', openssl_pkey_get_details($key)['key']);
        $app['config']->set('auth.guards.api', ['driver' => 'passport', 'provider' => 'users']);
        $app['config']->set('bherila-auth.oauth_server.enabled', true);
        $app['config']->set('bherila-auth.oauth_server.revocation.enabled', true);
        $app['config']->set('bherila-auth.oauth_server.issuer', 'https://auth.example.test');
        $app['config']->set('bherila-auth.oauth_server.resource', self::RESOURCE);
        $app['config']->set('bherila-auth.oauth_server.scopes', ['mcp:use' => 'Synthetic API']);
        $app['config']->set('bherila-auth.oauth_server.resource_required_scope', 'mcp:use');
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
        Passport::tokensCan(['mcp:use' => 'Synthetic API']);
        Passport::defaultScopes([]);
        Passport::authorizationView('bherila-auth::oauth.authorize');
        foreach (['passport.authorizations.authorize', 'passport.authorizations.approve', 'passport.token'] as $name) {
            Route::getRoutes()->getByName($name)?->middleware([EnforceOAuthPkce::class, EnforceOAuthResourceIndicator::class]);
        }
        Route::get('/synthetic-api', fn () => response()->json(['ok' => true]))->middleware([ExpectOAuthResource::class, 'auth:api']);
    }

    protected function tearDown(): void
    {
        Passport::useAccessTokenEntity(AccessToken::class);
        Passport::useClientModel(Client::class);
        parent::tearDown();
    }

    public function test_existing_auth_code_allocation_overrides_remain_compatible_with_the_guard_disabled(): void
    {
        config(['bherila-auth.oauth_server.revocation.enabled' => false]);
        $repository = new class extends ResourceAuthCodeRepository
        {
            public bool $allocated = false;

            public function getNewAuthCode(): AuthCodeEntityInterface
            {
                $this->allocated = true;

                return parent::getNewAuthCode();
            }
        };
        $this->assertInstanceOf(AuthCodeEntityInterface::class, $repository->getNewAuthCode());
        $this->assertTrue($repository->allocated);
    }

    public function test_rotations_and_purge_keep_one_durable_connection_without_revoking_siblings(): void
    {
        [$user, $client] = $this->userAndClient();
        $first = $this->exchange($client, $this->authorize($user, $client))->assertOk();
        $sibling = $this->exchange($client, $this->authorize($user, $client))->assertOk();
        $oldId = $this->id($first);
        $rotated = $this->refresh($client, $first)->assertOk();
        $newId = $this->id($rotated);
        $this->assertSame($this->lineageFor($oldId), $this->lineageFor($newId));
        $this->assertNotSame($this->lineageFor($oldId), $this->lineageFor($this->id($sibling)));
        Passport::token()->newQuery()->whereKey($oldId)->update(['expires_at' => now()->subDays(32)]);
        $this->artisan('passport:purge', ['--expired' => true, '--hours' => 744])->assertSuccessful();
        $this->assertNull(Passport::token()->newQuery()->find($oldId));
        $this->travel(1)->days();
        $family = app(CredentialLineages::class)->revokingConnection($user->id, $oldId, function (array $ids): array {
            Passport::refreshToken()->newQuery()->whereIn('access_token_id', $ids)->update(['revoked' => true]);
            foreach ($ids as $id) {
                app(AccessTokenRepository::class)->revokeAccessToken($id);
            }

            return $ids;
        });
        $this->assertContains($newId, $family);
        $this->refresh($client, $rotated)->assertStatus(400)->assertJsonPath('error', 'invalid_grant');
        $this->refresh($client, $sibling)->assertOk();
        $this->assertSame(2, DB::table('oauth_credential_lineages')->count());
        $this->assertSame(1, DB::table('oauth_credential_lineages')->where('revoked', true)->count());
    }

    public static function grantRaces(): array
    {
        return ['code exchange' => ['code'], 'refresh rotation' => ['refresh']];
    }

    #[DataProvider('grantRaces')]
    public function test_revocation_after_parent_validation_refuses_persistence_without_a_time_window(string $grant): void
    {
        [$user, $client] = $this->userAndClient();
        $code = $this->authorize($user, $client);
        $initial = $grant === 'refresh' ? $this->exchange($client, $code)->assertOk() : null;
        $raced = false;
        $race = function () use ($user, &$raced): void {
            if ($raced) {
                return;
            }
            $raced = true;
            app(OAuthCredentialOwners::class)->revokeAll($user);
            // The old fence lasted 120 seconds. An already validated grant can
            // stall arbitrarily long; advancing time must never lift a barrier.
            $this->travel(1)->days();
        };
        if ($grant === 'refresh') {
            app()->bind(RefreshTokenRepository::class, fn () => new class(app('events'), $race) extends ResourceRefreshTokenRepository
            {
                public function __construct(Dispatcher $events, private Closure $race)
                {
                    parent::__construct($events);
                }

                protected function isApplicationRefreshTokenRevoked(string $tokenId): bool
                {
                    ($this->race)();

                    return false;
                }
            });
        } else {
            app()->bind(AuthCodeRepository::class, fn () => new class($race) extends ResourceAuthCodeRepository
            {
                public function __construct(private Closure $race) {}

                protected function isApplicationAuthCodeRevoked(string $codeId): bool
                {
                    ($this->race)();

                    return false;
                }
            });
        }
        app()->forgetInstance(AuthorizationServer::class);
        Route::getRoutes()->getByName('passport.token')?->flushController();
        $response = $initial === null ? $this->exchange($client, $code) : $this->refresh($client, $initial);
        $response->assertStatus(400)->assertJsonPath('error', 'invalid_grant');
        $this->assertTrue($raced);
        $this->assertSame(0, Passport::token()->newQuery()->where('revoked', false)->count());
        $this->assertSame(0, Passport::refreshToken()->newQuery()->where('revoked', false)->count());
        // A fresh authorization after revocation is a new, legitimate connection.
        $this->exchange($client, $this->authorize($user, $client))->assertOk();
    }

    public function test_an_exchange_cannot_fall_back_to_a_new_lineage_when_its_validated_parent_context_is_missing(): void
    {
        [$user, $client] = $this->userAndClient();
        $first = $this->exchange($client, $this->authorize($user, $client))->assertOk();
        app()->bind(RefreshTokenRepository::class, fn () => new class(app('events')) extends ResourceRefreshTokenRepository
        {
            protected function isApplicationRefreshTokenRevoked(string $tokenId): bool
            {
                // Model a custom/old repository losing the carried parent.
                app(CredentialLineages::class)->begin(request());

                return false;
            }
        });
        app()->forgetInstance(AuthorizationServer::class);
        Route::getRoutes()->getByName('passport.token')?->flushController();
        $this->refresh($client, $first)->assertStatus(400)->assertJsonPath('error', 'invalid_grant');
        $this->assertSame(1, Passport::token()->newQuery()->count());
    }

    public function test_revocation_between_access_and_refresh_persistence_leaves_no_live_child(): void
    {
        [$user, $client] = $this->userAndClient();
        $first = $this->exchange($client, $this->authorize($user, $client))->assertOk();
        $childId = null;
        app('events')->listen(AccessTokenCreated::class, function (AccessTokenCreated $event) use ($user, &$childId): void {
            $childId = $event->tokenId;
            app(OAuthCredentialOwners::class)->revokeAll($user);
        });
        $this->refresh($client, $first)->assertStatus(400)->assertJsonPath('error', 'invalid_grant');
        $this->assertNotNull($childId);
        $this->assertTrue((bool) Passport::token()->newQuery()->findOrFail($childId)->revoked);
        $this->assertSame(0, Passport::refreshToken()->newQuery()->where('access_token_id', $childId)->count());
        $this->assertSame(0, Passport::token()->newQuery()->where('revoked', false)->count());
    }

    public static function issuanceBoundaries(): array
    {
        return ['access entity' => ['access', false], 'code entity' => ['code', false],
            'access request' => ['access', true], 'code request' => ['code', true]];
    }

    #[DataProvider('issuanceBoundaries')]
    public function test_new_credentials_cannot_adopt_a_revocation_after_their_issuance_boundary(string $kind, bool $beforeEntity): void
    {
        [$user, $client] = $this->userAndClient();
        $request = Request::create('/oauth/token', 'POST', ['resource' => self::RESOURCE]);
        $this->app->instance('request', $request);
        if ($beforeEntity) {
            app(CredentialLineages::class)->begin($request);
            app(OAuthCredentialOwners::class)->revokeAll($user);
        }
        if ($kind === 'access') {
            $repository = app(AccessTokenRepository::class);
            $entity = $repository->getNewToken(new BridgeClient((string) $client->id), [new Scope('mcp:use')], (string) $user->id);
        } else {
            $repository = app(AuthCodeRepository::class);
            $entity = $repository->getNewAuthCode();
            $entity->setClient(new BridgeClient((string) $client->id));
            $entity->setUserIdentifier((string) $user->id);
            $entity->addScope(new Scope('mcp:use'));
        }
        $entity->setIdentifier(str_repeat('a', 80));
        $entity->setExpiryDateTime(now()->addHour()->toDateTimeImmutable());
        if (! $beforeEntity) {
            app(OAuthCredentialOwners::class)->revokeAll($user);
        }
        $this->travel(1)->days();
        try {
            if ($kind === 'access') {
                $repository->persistNewAccessToken($entity);
            } else {
                $repository->persistNewAuthCode($entity);
            }
            $this->fail('An issuance boundary must not adopt a later revocation sequence.');
        } catch (OAuthServerException $error) {
            $this->assertSame('invalid_grant', $error->getErrorType());
        }
        $this->assertSame(0, Passport::token()->newQuery()->count());
        $this->assertSame(0, Passport::authCode()->newQuery()->count());
        $this->assertSame(0, DB::table('oauth_credential_members')->count());
    }

    public function test_a_legacy_refresh_is_adopted_after_its_access_row_is_purged_and_keeps_its_family(): void
    {
        [$user, $client] = $this->userAndClient();
        config(['bherila-auth.oauth_server.revocation.enabled' => false]);
        $first = $this->exchange($client, $this->authorize($user, $client))->assertOk();
        $old = $this->id($first);
        $this->assertSame(0, DB::table('oauth_credential_members')->count());
        Passport::token()->newQuery()->whereKey($old)->update(['expires_at' => now()->subDays(32)]);
        $this->artisan('passport:purge', ['--expired' => true, '--hours' => 744])->assertSuccessful();
        $this->registerLegacyCutover();
        config(['bherila-auth.oauth_server.revocation.enabled' => true]);
        $rotated = $this->refresh($client, $first)->assertOk();
        $this->assertSame($this->lineageFor($old), $this->lineageFor($this->id($rotated)));
        // The durable lineage alone refuses a refresh, even without updating its row.
        app(CredentialLineages::class)->revokingConnection($user->id, $old, fn () => null);
        $this->refresh($client, $rotated)->assertStatus(400)->assertJsonPath('error', 'invalid_grant');
    }

    public function test_legacy_credentials_never_adopt_a_new_owner_barrier(): void
    {
        [$user, $client] = $this->userAndClient();
        config(['bherila-auth.oauth_server.revocation.enabled' => false]);
        $first = $this->exchange($client, $this->authorize($user, $client))->assertOk();
        $this->registerLegacyCutover();
        config(['bherila-auth.oauth_server.revocation.enabled' => true]);
        // Intentionally leave Passport rows untouched to prove the durable
        // barrier, rather than Passport's revoked flag, refuses adoption.
        app(CredentialLineages::class)->revokingOwner($user->id, null, fn () => null);
        $this->refresh($client, $first)->assertStatus(400)->assertJsonPath('error', 'invalid_grant');
        $this->assertSame(1, Passport::token()->newQuery()->count());
    }

    public function test_unattributed_legacy_refreshes_cannot_bypass_the_guard_with_provider_checks_off(): void
    {
        [$user, $client] = $this->userAndClient();
        config(['bherila-auth.oauth_server.revocation.enabled' => false, 'bherila-auth.provider_identity.enabled' => false]);
        $first = $this->exchange($client, $this->authorize($user, $client))->assertOk();
        Passport::refreshToken()->newQuery()->update(['provider_user_id' => null, 'client_id' => null]);
        Passport::token()->newQuery()->delete();
        config(['bherila-auth.oauth_server.revocation.enabled' => true]);
        $this->refresh($client, $first)->assertStatus(400)->assertJsonPath('error', 'invalid_grant');
        $this->assertSame(0, Passport::token()->newQuery()->count());
        $this->assertSame(0, DB::table('oauth_credential_members')->count());
    }

    public function test_a_late_untracked_rotation_from_an_old_writer_is_refused_and_migration_replay_does_not_enroll_it(): void
    {
        [$user, $client] = $this->userAndClient();
        $first = $this->exchange($client, $this->authorize($user, $client))->assertOk();
        app(CredentialLineages::class)->revokingConnection($user->id, $this->id($first), fn () => null);
        // An old process cannot see the durable lineage barrier. Its late
        // writes are not registered and must never be adopted by the new code.
        config(['bherila-auth.oauth_server.revocation.enabled' => false]);
        $untracked = $this->refresh($client, $first)->assertOk();
        config(['bherila-auth.oauth_server.revocation.enabled' => true]);
        $migration = require __DIR__.'/../../database/migrations/2026_10_20_230000_create_oauth_credential_lineages.php';
        $migration->up();
        $this->assertTrue(app(CredentialLineages::class)->revoked(Passport::token()->newQuery()->findOrFail($this->id($untracked))));
        $this->refresh($client, $untracked)->assertStatus(400)->assertJsonPath('error', 'invalid_grant');
        $this->assertSame(3, DB::table('oauth_credential_members')->count());
    }

    public function test_migrated_legacy_siblings_remain_independent(): void
    {
        [$user, $client] = $this->userAndClient();
        config(['bherila-auth.oauth_server.revocation.enabled' => false]);
        $first = $this->exchange($client, $this->authorize($user, $client))->assertOk();
        $sibling = $this->exchange($client, $this->authorize($user, $client))->assertOk();
        $this->registerLegacyCutover();
        config(['bherila-auth.oauth_server.revocation.enabled' => true]);
        app(CredentialLineages::class)->revokingConnection($user->id, $this->id($first), fn () => null);
        $this->refresh($client, $first)->assertStatus(400);
        $this->refresh($client, $sibling)->assertOk();
    }

    public function test_the_cutover_registers_multiple_batches_with_attributable_orphan_refreshes(): void
    {
        [$user, $client] = $this->userAndClient();
        $access = [];
        $refreshes = [];
        for ($i = 1; $i <= 205; $i++) {
            $id = str_pad(dechex($i), 80, '0', STR_PAD_LEFT);
            $access[] = ['id' => $id, 'user_id' => $user->id, 'client_id' => $client->id, 'scopes' => '[]', 'revoked' => false, 'expires_at' => now()->addHour()];
            $refreshes[] = ['id' => $id, 'access_token_id' => $id, 'provider_user_id' => (string) $user->id, 'client_id' => $client->id, 'revoked' => false, 'expires_at' => now()->addDay()];
        }
        foreach (array_chunk($access, 100) as $batch) {
            DB::table('oauth_access_tokens')->insert($batch);
        }
        foreach (array_chunk($refreshes, 100) as $batch) {
            DB::table('oauth_refresh_tokens')->insert($batch);
        }
        Passport::token()->newQuery()->whereKey($access[0]['id'])->delete();
        $this->registerLegacyCutover();
        $this->assertSame(205, DB::table('oauth_credential_lineages')->count());
        $this->assertSame(410, DB::table('oauth_credential_members')->count());
        $this->assertSame($this->lineageFor($access[0]['id']), DB::table('oauth_credential_members')->where('kind', 'refresh')->where('credential_id', $access[0]['id'])->value('lineage_id'));
    }

    public function test_a_connection_cannot_be_revoked_under_another_owner(): void
    {
        [$user, $client] = $this->userAndClient();
        [$other] = $this->userAndClient('other@example.test');
        $first = $this->exchange($client, $this->authorize($user, $client))->assertOk();
        try {
            app(CredentialLineages::class)->revokingConnection($other->id, $this->id($first), function (): void {
                $this->fail('A foreign connection must not reach the revocation callback.');
            });
            $this->fail('A foreign lineage must be refused.');
        } catch (OAuthServerException $error) {
            $this->assertSame('invalid_grant', $error->getErrorType());
        }
        $this->refresh($client, $first)->assertOk();
        $this->assertSame(0, DB::table('oauth_credential_lineages')->where('revoked', true)->count());
    }

    public function test_client_scoped_barriers_preserve_other_clients_and_other_owners(): void
    {
        [$user, $client] = $this->userAndClient();
        [$other, $otherClient] = $this->userAndClient('other@example.test');
        $target = $this->exchange($client, $this->authorize($user, $client))->assertOk();
        $sibling = $this->exchange($otherClient, $this->authorize($user, $otherClient))->assertOk();
        $otherOwner = $this->exchange($client, $this->authorize($other, $client))->assertOk();
        app(CredentialLineages::class)->revokingOwner($user->id, (string) $client->id, function () use ($user, $client): void {
            $ids = Passport::token()->newQuery()->where('user_id', $user->id)->where('client_id', $client->id)->pluck('id');
            Passport::refreshToken()->newQuery()->whereIn('access_token_id', $ids)->update(['revoked' => true]);
            Passport::token()->newQuery()->whereKey($ids)->update(['revoked' => true]);
            Passport::authCode()->newQuery()->where('user_id', $user->id)->where('client_id', $client->id)->update(['revoked' => true]);
        });
        $this->refresh($client, $target)->assertStatus(400);
        $this->refresh($otherClient, $sibling)->assertOk();
        $this->refresh($client, $otherOwner)->assertOk();
        $this->exchange($client, $this->authorize($user, $client))->assertOk();
    }

    public function test_a_failed_revocation_rolls_back_the_barrier_and_credential_rows_together(): void
    {
        [$user, $client] = $this->userAndClient();
        $first = $this->exchange($client, $this->authorize($user, $client))->assertOk();
        try {
            app(CredentialLineages::class)->revokingOwner($user->id, null, function () use ($user): void {
                Passport::token()->newQuery()->where('user_id', $user->id)->update(['revoked' => true]);
                throw new RuntimeException('Synthetic rollback');
            });
            $this->fail('The synthetic failure must propagate.');
        } catch (RuntimeException $error) {
            $this->assertSame('Synthetic rollback', $error->getMessage());
        }
        $this->assertSame(0, DB::table('oauth_credential_lineages')->where('revoked', true)->count());
        $this->refresh($client, $first)->assertOk();
    }

    /** Model the actual one-time migration with credentials already present. */
    private function registerLegacyCutover(): void
    {
        Schema::drop('oauth_credential_members');
        Schema::drop('oauth_credential_lineages');
        Schema::drop('oauth_credential_revocations');
        $migration = require __DIR__.'/../../database/migrations/2026_10_20_230000_create_oauth_credential_lineages.php';
        $migration->up();
    }

    private function userAndClient(string $email = 'lineage@example.test'): array
    {
        $user = User::query()->create(['name' => 'Synthetic lineage', 'email' => $email, 'password' => 'unused']);
        $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('Synthetic client', [self::CALLBACK], confidential: false);

        return [$user, $client];
    }

    private function authorize(User $user, Client $client): string
    {
        $challenge = rtrim(strtr(base64_encode(hash('sha256', self::VERIFIER, true)), '+/', '-_'), '=');
        $authorization = $this->actingAs($user)->get('/oauth/authorize?'.http_build_query([
            'response_type' => 'code', 'client_id' => $client->id, 'redirect_uri' => self::CALLBACK,
            'scope' => 'mcp:use', 'resource' => self::RESOURCE, 'code_challenge' => $challenge, 'code_challenge_method' => 'S256',
        ]));
        if ($authorization->getStatusCode() === 302) {
            $approval = $authorization;
        } else {
            $authorization->assertOk();
            $approval = $this->actingAs($user)->post('/oauth/authorize', ['auth_token' => session('authToken')])->assertRedirect();
        }
        parse_str((string) parse_url((string) $approval->headers->get('Location'), PHP_URL_QUERY), $query);

        return $query['code'];
    }

    private function exchange(Client $client, string $code): TestResponse
    {
        return $this->postJson('/oauth/token', ['grant_type' => 'authorization_code', 'client_id' => $client->id,
            'redirect_uri' => self::CALLBACK, 'code' => $code, 'code_verifier' => self::VERIFIER, 'resource' => self::RESOURCE]);
    }

    private function refresh(Client $client, TestResponse $tokens): TestResponse
    {
        return $this->postJson('/oauth/token', ['grant_type' => 'refresh_token', 'client_id' => $client->id,
            'refresh_token' => $tokens->json('refresh_token'), 'resource' => self::RESOURCE]);
    }

    private function id(TestResponse $tokens): string
    {
        return OAuthResourceIndicator::tokenClaims($tokens->json('access_token'))['jti'];
    }

    private function lineageFor(string $id): string
    {
        return DB::table('oauth_credential_members')->where('credential_id', $id)->where('kind', 'access')->value('lineage_id');
    }
}
