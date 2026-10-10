<?php

namespace BWH\Auth\Tests\Feature;

use BWH\Auth\AuthServiceProvider;
use BWH\Auth\OAuth\Credentials\ApiCredentialService;
use BWH\Auth\OAuth\Server\AgentOAuthServer;
use BWH\Auth\OAuth\Server\OAuthResourceIndicator;
use BWH\Auth\Http\Middleware\ExpectOAuthResource;
use BWH\Auth\Tests\Fixtures\User;
use BWH\Auth\Tests\TestCase;
use Illuminate\Support\Arr;
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

    /** A custom scopes column without an array cast stores the ceiling as JSON and still enforces it. */
    public function test_an_uncast_scopes_column_stores_and_enforces_the_ceiling(): void
    {
        \Illuminate\Support\Facades\Schema::table('oauth_clients', static function (\Illuminate\Database\Schema\Blueprint $table): void {
            $table->text('registered_scopes')->nullable();
        });
        config(['bherila-auth.oauth_server.dynamic_clients.scopes_column' => 'registered_scopes']);

        $app = $this->actingAs($this->user)->postJson(self::BASE.'/apps', [
            'name' => 'Uncast', 'redirect_uris' => [self::REDIRECT], 'confidential' => false, 'scopes' => ['items:read'],
        ])->assertCreated()->json('data');

        $this->assertSame('["items:read"]', \Illuminate\Support\Facades\DB::table('oauth_clients')->where('id', $app['client_id'])->value('registered_scopes'));
        $this->assertSame(['items:read'], $this->getJson(self::BASE)->json('data.apps.0.scopes'));
    }

    /** A valid but noncanonical resource setting still issues (no 500, no orphaned token). */
    public function test_a_noncanonical_resource_setting_still_issues_a_token(): void
    {
        config(['bherila-auth.oauth_server.resource' => 'HTTPS://APP.EXAMPLE.TEST:443/api/v1']);

        $this->actingAs($this->user)->postJson(self::BASE.'/tokens', ['name' => 'Canonical', 'scopes' => ['items:read'], 'lifetime' => 'P30D'])
            ->assertCreated();
        $this->assertSame(1, Passport::token()->newQuery()->where('user_id', $this->user->id)->count());
    }

    /** Revocation goes through Passport so its AccessTokenRevoked listeners hear about it. */
    public function test_revoking_and_deleting_dispatch_passport_revocation_events(): void
    {
        $this->actingAs($this->user)->postJson(self::BASE.'/tokens', ['name' => 'Evented', 'scopes' => ['items:read'], 'lifetime' => 'P30D'])->assertCreated();
        $token = Passport::token()->newQuery()->where('user_id', $this->user->id)->sole();
        $app = $this->postJson(self::BASE.'/apps', ['name' => 'Evented app', 'redirect_uris' => [self::REDIRECT], 'confidential' => false, 'scopes' => ['items:read']])->json('data');
        Passport::token()->newQuery()->forceCreate([
            'id' => 'app-token', 'user_id' => $this->user->id, 'client_id' => $app['client_id'], 'name' => null, 'scopes' => '[]', 'revoked' => false, 'expires_at' => now()->addDay(),
        ]);
        \Illuminate\Support\Facades\Event::fake([\Laravel\Passport\Events\AccessTokenRevoked::class]);

        $this->deleteJson(self::BASE.'/tokens/'.$token->getKey())->assertOk();
        $this->deleteJson(self::BASE.'/apps/'.$app['client_id'])->assertOk();

        \Illuminate\Support\Facades\Event::assertDispatched(\Laravel\Passport\Events\AccessTokenRevoked::class, fn ($event) => $event->tokenId === (string) $token->getKey());
        \Illuminate\Support\Facades\Event::assertDispatched(\Laravel\Passport\Events\AccessTokenRevoked::class, fn ($event) => $event->tokenId === 'app-token');
        $this->assertTrue((bool) Passport::token()->newQuery()->findOrFail('app-token')->revoked);
    }

    /** SQL wildcards in the prefix must not make this service claim tokens it never issued. */
    public function test_a_wildcard_in_the_prefix_does_not_claim_other_tokens(): void
    {
        config(['bherila-auth.oauth_server.credentials.token_name_prefix' => 'api_token_']);
        $client = app(\Laravel\Passport\ClientRepository::class)->createPersonalAccessGrantClient('Other issuer', 'users');
        Passport::token()->newQuery()->forceCreate([
            'id' => 'foreign', 'user_id' => $this->user->id, 'client_id' => $client->getKey(), 'name' => 'apiXtokenYother', 'scopes' => '[]', 'revoked' => false, 'expires_at' => now()->addDay(),
        ]);

        $this->assertSame([], $this->actingAs($this->user)->getJson(self::BASE)->json('data.tokens'));
        $this->deleteJson(self::BASE.'/tokens/foreign')->assertNotFound();
        $this->assertFalse((bool) Passport::token()->newQuery()->findOrFail('foreign')->revoked);
    }

    /** Passport stores the auth identifier as the token owner, which need not be the primary key. */
    public function test_an_owner_with_a_non_key_auth_identifier_can_issue_list_and_revoke(): void
    {
        $person = new class extends User
        {
            public function getAuthIdentifierName(): string
            {
                return 'email';
            }
        };
        $person = $person->newQuery()->create(['name' => 'By email', 'email' => 'by-email@example.test', 'password' => 'not-used']);

        $this->actingAs($person)->postJson(self::BASE.'/tokens', ['name' => 'Mine', 'scopes' => ['items:read'], 'lifetime' => 'P30D'])->assertCreated();
        $listed = $this->getJson(self::BASE)->json('data.tokens');
        $this->assertCount(1, $listed);
        $this->deleteJson($listed[0]['revoke_href'])->assertOk();
    }

    /** Installations that kept Passport's legacy user_id column list and delete their apps too. */
    public function test_apps_work_on_the_legacy_user_id_client_schema(): void
    {
        \Illuminate\Support\Facades\Schema::table('oauth_clients', static function (\Illuminate\Database\Schema\Blueprint $table): void {
            $table->unsignedBigInteger('user_id')->nullable();
        });

        $app = $this->actingAs($this->user)->postJson(self::BASE.'/apps', [
            'name' => 'Legacy', 'redirect_uris' => [self::REDIRECT], 'confidential' => false, 'scopes' => ['items:read'],
        ])->assertCreated()->json('data');
        $this->assertSame((string) $this->user->id, (string) Passport::client()->newQuery()->findOrFail($app['client_id'])->user_id);

        $listed = $this->getJson(self::BASE)->assertOk()->json('data.apps');
        $this->assertSame($app['client_id'], $listed[0]['id']);
        $this->deleteJson($listed[0]['delete_href'])->assertOk();
    }

    /**
     * The connection-scope opt-in is off by default, and with the default the
     * index, the refusals and the issued token are exactly what they were before
     * the option existed (simulated by removing its keys from the config).
     */
    public function test_by_default_no_personal_token_carries_a_connection_scope_and_nothing_changes(): void
    {
        $defaults = require __DIR__.'/../../config/bherila-auth.php';
        $this->assertSame([], $defaults['oauth_server']['credentials']['personal_token_connection_scopes']);
        $now = now()->toImmutable();
        $longest = max(array_map(static fn (string $spec) => $now->add(new \DateInterval($spec)), $defaults['oauth_server']['credentials']['token_lifetimes']));
        $this->assertLessThan($longest, $now->add(new \DateInterval($defaults['oauth_server']['credentials']['personal_token_connection_max_lifetime'])), 'The default connection cap is shorter than the longest default lifetime');

        $this->actingAs($this->user);
        foreach (['PT4H', 'P30D', 'P90D'] as $lifetime) {
            $this->postJson(self::BASE.'/tokens', ['name' => 'x', 'scopes' => ['mcp:use', 'items:read'], 'lifetime' => $lifetime])->assertJsonValidationErrors('scopes.0');
        }
        $this->assertSame(0, Passport::token()->newQuery()->count());
        $this->postJson(self::BASE.'/apps', ['name' => 'x', 'redirect_uris' => [self::REDIRECT], 'confidential' => false, 'scopes' => ['mcp:use']])->assertJsonValidationErrors('scopes.0');

        $withDefault = $this->postJson(self::BASE.'/tokens', ['name' => 'Default', 'scopes' => ['items:read'], 'lifetime' => 'P90D'])->assertCreated()->json('data.token');
        $index = $this->getJson(self::BASE)->assertOk();
        $this->assertSame(['scopes', 'token_lifetimes', 'issue_token_href', 'register_app_href', 'tokens', 'apps'], array_keys($index->json('data')));
        $this->assertSame(['id', 'name', 'scopes', 'created_at', 'expires_at', 'revoke_href'], array_keys($index->json('data.tokens.0')));

        // The same configuration as it was before the option existed.
        config(['bherila-auth.oauth_server.credentials' => \Illuminate\Support\Arr::except(
            config('bherila-auth.oauth_server.credentials'),
            ['personal_token_connection_scopes', 'personal_token_connection_max_lifetime'],
        )]);
        $this->assertSame($index->getContent(), $this->getJson(self::BASE)->assertOk()->getContent());
        $before = $this->postJson(self::BASE.'/tokens', ['name' => 'Before', 'scopes' => ['items:read'], 'lifetime' => 'P90D'])->assertCreated()->json('data.token');
        $this->postJson(self::BASE.'/tokens', ['name' => 'x', 'scopes' => ['mcp:use'], 'lifetime' => 'PT4H'])->assertJsonValidationErrors('scopes.0');

        $shape = static function (string $token): array {
            $claims = OAuthResourceIndicator::tokenClaims($token);
            $row = Passport::token()->newQuery()->findOrFail($claims['jti']);

            return [
                'claims' => array_keys($claims),
                'aud' => array_slice((array) $claims['aud'], 1),
                'resource' => $claims['resource'],
                'scopes' => $claims['scopes'],
                'lifetime' => (int) round($claims['exp'] - $claims['iat']),
                'row' => Arr::except($row->getAttributes(), ['id', 'name', 'created_at', 'updated_at', 'expires_at']),
            ];
        };
        $this->assertSame($shape($before), $shape($withDefault));
    }

    public function test_an_opted_in_token_carries_the_connection_scope_bound_to_the_resource(): void
    {
        config(['bherila-auth.oauth_server.credentials.personal_token_connection_scopes' => ['mcp:use']]);
        $this->actingAs($this->user);

        $index = $this->getJson(self::BASE)->assertOk()->assertHeader('Cache-Control', 'no-store, private')->json('data');
        $this->assertSame(['items:read', 'items:write'], array_column($index['scopes'], 'id'), 'OAuth apps are still offered no connection scope');
        $this->assertSame([['id' => 'mcp:use', 'description' => 'Connect through MCP']], $index['token_connection_scopes']);
        $this->assertSame(['PT4H', 'P30D'], $index['connection_token_lifetimes'], 'Only lifetimes under the default P30D cap');

        $issued = $this->postJson(self::BASE.'/tokens', ['name' => 'Static MCP key', 'scopes' => ['mcp:use', 'items:read'], 'lifetime' => 'P30D'])
            ->assertCreated()->assertHeader('Cache-Control', 'no-store, private')->json('data');
        $this->assertStringNotContainsString($issued['token'], json_encode(session()->all(), JSON_THROW_ON_ERROR));
        $row = Passport::token()->newQuery()->where('user_id', $this->user->id)->sole();
        $this->assertSame(['mcp:use', 'items:read'], $row->scopes);
        $this->assertSame(self::APP.'/api/v1', $row->resource_uri);
        $claims = OAuthResourceIndicator::tokenClaims($issued['token']);
        $this->assertSame(self::APP.'/api/v1', $claims['resource'] ?? null);
        $this->assertContains(self::APP.'/api/v1', (array) $claims['aud']);
        $this->assertEqualsWithDelta(now()->addDays(30)->getTimestamp(), $row->expires_at?->getTimestamp(), 60);

        $this->postJson(self::BASE.'/tokens', ['name' => 'Plain', 'scopes' => ['items:read'], 'lifetime' => 'P90D'])->assertCreated();
        $listed = collect($this->getJson(self::BASE)->json('data.tokens'))->keyBy('name');
        $this->assertTrue($listed['Static MCP key']['connection']);
        $this->assertFalse($listed['Plain']['connection']);

        $this->postJson(self::BASE.'/apps', ['name' => 'x', 'redirect_uris' => [self::REDIRECT], 'confidential' => false, 'scopes' => ['mcp:use']])
            ->assertJsonValidationErrors('scopes.0');

        $this->app['auth']->forgetGuards();
        $this->postJson('/api/v1/mcp', [], ['Authorization' => 'Bearer '.$issued['token']])->assertOk();
        $this->app['auth']->forgetGuards();
        $this->getJson('/api/v1/items', ['Authorization' => 'Bearer '.$issued['token']])->assertOk();

        $this->actingAs($this->user)->deleteJson($listed['Static MCP key']['revoke_href'])->assertOk();
        $this->app['auth']->forgetGuards();
        $this->postJson('/api/v1/mcp', [], ['Authorization' => 'Bearer '.$issued['token']])->assertUnauthorized();
    }

    /** Only listed connection scopes, and only ones the catalog has and exclusions allow. */
    public function test_connection_scopes_are_held_to_the_list_the_catalog_and_the_exclusions(): void
    {
        config([
            'bherila-auth.oauth_server.resource_required_scopes' => ['mcp:use', 'admin:all', 'ghost:use', 'items:write'],
            'bherila-auth.oauth_server.credentials.personal_token_connection_scopes' => ['mcp:use', 'admin:all', 'ghost:use', 'items:read'],
        ]);
        $this->actingAs($this->user);

        $index = $this->getJson(self::BASE)->assertOk()->json('data');
        $this->assertSame(['mcp:use'], array_column($index['token_connection_scopes'], 'id'), 'Excluded (admin:all), uncatalogued (ghost:use), unlisted (items:write) and non-connection (items:read) entries are not connection scopes on offer');
        $this->assertSame(['items:read'], array_column($index['scopes'], 'id'));

        foreach (['admin:all', 'ghost:use', 'items:write'] as $scope) {
            $this->postJson(self::BASE.'/tokens', ['name' => 'x', 'scopes' => [$scope], 'lifetime' => 'PT4H'])->assertJsonValidationErrors('scopes.0');
        }
        $this->assertSame(0, Passport::token()->newQuery()->count());
        $this->assertSame(['mcp:use' => 'Connect through MCP'], app(ApiCredentialService::class)->connectionScopes());
    }

    public function test_a_token_carrying_a_connection_scope_is_held_to_the_lifetime_cap(): void
    {
        config(['bherila-auth.oauth_server.credentials.personal_token_connection_scopes' => ['mcp:use']]);
        $this->actingAs($this->user);

        $this->postJson(self::BASE.'/tokens', ['name' => 'Too long', 'scopes' => ['mcp:use'], 'lifetime' => 'P90D'])->assertJsonValidationErrors('credential');
        $this->assertSame(0, Passport::token()->newQuery()->count());
        $this->postJson(self::BASE.'/tokens', ['name' => 'REST only', 'scopes' => ['items:read'], 'lifetime' => 'P90D'])->assertCreated();

        config(['bherila-auth.oauth_server.credentials.personal_token_connection_max_lifetime' => 'PT4H']);
        $this->assertSame(['PT4H'], $this->getJson(self::BASE)->json('data.connection_token_lifetimes'));
        $this->postJson(self::BASE.'/tokens', ['name' => 'Too long', 'scopes' => ['mcp:use'], 'lifetime' => 'P30D'])->assertJsonValidationErrors('credential');
        $this->postJson(self::BASE.'/tokens', ['name' => 'Short', 'scopes' => ['mcp:use'], 'lifetime' => 'PT4H'])->assertCreated();
        $short = Passport::token()->newQuery()->where('name', 'api-token: Short')->sole();
        $this->assertEqualsWithDelta(now()->addHours(4)->getTimestamp(), $short->expires_at?->getTimestamp(), 60);

        // An unusable cap fails closed: nothing to offer, nothing issued.
        config(['bherila-auth.oauth_server.credentials.personal_token_connection_max_lifetime' => 'not-a-duration']);
        $index = $this->getJson(self::BASE)->json('data');
        $this->assertSame([], $index['token_connection_scopes']);
        $this->assertSame([], $index['connection_token_lifetimes']);
        $this->postJson(self::BASE.'/tokens', ['name' => 'x', 'scopes' => ['mcp:use'], 'lifetime' => 'PT4H'])->assertJsonValidationErrors('scopes.0');
        $this->assertSame(2, Passport::token()->newQuery()->count());
    }

    /**
     * Once opted in, the cap holds even for a connection scope a custom
     * GrantableScopes binding already offered; without the opt-in such a
     * binding behaves as it always did.
     */
    public function test_the_cap_covers_a_connection_scope_a_custom_binding_offers_only_once_opted_in(): void
    {
        $this->app->instance(\BWH\Auth\OAuth\Credentials\GrantableScopes::class, new class implements \BWH\Auth\OAuth\Credentials\GrantableScopes
        {
            public function scopes(): array
            {
                return ['mcp:use' => 'Connect', 'items:read' => 'Read items'];
            }
        });
        $this->actingAs($this->user);

        $this->postJson(self::BASE.'/tokens', ['name' => 'Legacy', 'scopes' => ['mcp:use'], 'lifetime' => 'P90D'])->assertCreated();
        $this->assertArrayNotHasKey('connection', $this->getJson(self::BASE)->json('data.tokens.0'));

        config(['bherila-auth.oauth_server.credentials.personal_token_connection_scopes' => ['mcp:use']]);
        $this->postJson(self::BASE.'/tokens', ['name' => 'Capped', 'scopes' => ['mcp:use'], 'lifetime' => 'P90D'])->assertJsonValidationErrors('credential');
        $this->assertTrue($this->getJson(self::BASE)->json('data.tokens.0.connection'));
        $this->assertSame(1, Passport::token()->newQuery()->count());
    }

    /** Bound like an OAuth access token: accepted only where the route expects its resource. */
    public function test_a_connection_token_is_accepted_only_for_its_bound_resource(): void
    {
        Route::post('/api/unmarked/mcp', fn () => response()->json(['ok' => true]))
            ->middleware(['auth:api', CheckToken::using('mcp:use')]);
        config(['bherila-auth.oauth_server.credentials.personal_token_connection_scopes' => ['mcp:use']]);
        $token = $this->actingAs($this->user)->postJson(self::BASE.'/tokens', ['name' => 'MCP', 'scopes' => ['mcp:use'], 'lifetime' => 'PT4H'])
            ->assertCreated()->json('data.token');

        $this->app['auth']->forgetGuards();
        $this->postJson('/api/v1/mcp', [], ['Authorization' => 'Bearer '.$token])->assertOk();
        $this->app['auth']->forgetGuards();
        $this->postJson('/api/unmarked/mcp', [], ['Authorization' => 'Bearer '.$token])->assertUnauthorized();

        // The route now expects another resource; the token stays bound to its own.
        config(['bherila-auth.oauth_server.resource' => 'https://other.example.test/api/v1']);
        $this->app['auth']->forgetGuards();
        $this->postJson('/api/v1/mcp', [], ['Authorization' => 'Bearer '.$token])->assertUnauthorized();
    }

    public function test_an_opted_in_token_without_the_connection_scope_is_refused_at_the_connection_endpoint(): void
    {
        config(['bherila-auth.oauth_server.credentials.personal_token_connection_scopes' => ['mcp:use']]);
        $token = $this->actingAs($this->user)->postJson(self::BASE.'/tokens', ['name' => 'REST', 'scopes' => ['items:read'], 'lifetime' => 'PT4H'])
            ->assertCreated()->json('data.token');
        $this->assertSame(['items:read'], Passport::token()->newQuery()->sole()->scopes);

        $this->app['auth']->forgetGuards();
        $this->postJson('/api/v1/mcp', [], ['Authorization' => 'Bearer '.$token])->assertForbidden();
        $this->app['auth']->forgetGuards();
        $this->getJson('/api/v1/items', ['Authorization' => 'Bearer '.$token])->assertOk();
    }

    public function test_redirect_uri_rules(): void
    {
        $this->assertTrue(ApiCredentialService::validRedirectUri('https://app.example.test/cb'));
        $this->assertTrue(ApiCredentialService::validRedirectUri('http://[::1]:9/cb'));
        $this->assertFalse(ApiCredentialService::validRedirectUri('http://192.0.2.1/cb'));
        $this->assertFalse(ApiCredentialService::validRedirectUri('https://'.str_repeat('a', 2050).'.test'));
    }
}
