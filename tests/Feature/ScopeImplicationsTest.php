<?php

namespace BWH\Auth\Tests\Feature;

use BWH\Auth\AuthServiceProvider;
use BWH\Auth\OAuth\Credentials\ApiCredentialService;
use BWH\Auth\OAuth\Credentials\DeclaresScopeImplications;
use BWH\Auth\OAuth\Credentials\ScopeGroup;
use BWH\Auth\OAuth\Credentials\ScopePresentation;
use BWH\Auth\OAuth\Credentials\ScopePreset;
use BWH\Auth\OAuth\Credentials\UngroupedScopePresentation;
use BWH\Auth\OAuth\Server\AgentOAuthServer;
use BWH\Auth\Tests\Fixtures\User;
use BWH\Auth\Tests\TestCase;
use Illuminate\Http\Request;
use Laravel\Passport\Passport;
use Laravel\Passport\PassportServiceProvider;
use LogicException;

/** Declared scope implications: presentation only, validated, and closed over what each surface offers. */
final class ScopeImplicationsTest extends TestCase
{
    private const APP = 'https://app.example.test';

    private const BASE = '/account/api-credentials';

    private const CATALOG = [
        'mcp:use' => 'Connect through MCP',
        'identity:read' => 'Read your identity',
        'time:read' => 'Read time',
        'time:write' => 'Log time',
        'reports:read' => 'Read reports',
        'billing:deliver' => 'Send invoices & move money',
    ];

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
            self::CATALOG,
            [
                'resource_required_scopes' => ['mcp:use'],
                'credentials' => ['enabled' => true, 'token_lifetimes' => ['P30D']],
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
        $this->user = User::query()->create(['name' => 'Person', 'email' => 'person@example.test', 'password' => 'not-used']);
    }

    /**
     * @param  array<string, list<string>>  $implications
     * @param  list<ScopeGroup>  $groups
     * @param  list<ScopePreset>  $presets
     */
    private function bind(array $implications, array $groups = [], array $presets = []): void
    {
        $this->app->instance(ScopePresentation::class, new class($implications, $groups, $presets) implements DeclaresScopeImplications, ScopePresentation
        {
            public function __construct(private readonly array $implications, private readonly array $groups, private readonly array $presets) {}

            public function implications(): array
            {
                return $this->implications;
            }

            public function groups(): array
            {
                return $this->groups;
            }

            public function presets(): array
            {
                return $this->presets;
            }
        });
    }

    /** @return list<ScopeGroup> */
    private function standardGroups(): array
    {
        return [
            new ScopeGroup('time', 'Time', ['time:write', 'time:read']),
            new ScopeGroup('admin', 'Admin', ['billing:deliver'], sensitive: true),
        ];
    }

    private function service(): ApiCredentialService
    {
        return $this->app->make(ApiCredentialService::class);
    }

    private function assertInvalid(string $needle): void
    {
        try {
            $this->service()->scopeImplications(['time:read' => 'x']);
            $this->fail('Expected a LogicException naming '.$needle);
        } catch (LogicException $e) {
            $this->assertStringContainsString($needle, $e->getMessage());
        }
    }

    public function test_without_the_interface_every_payload_is_unchanged(): void
    {
        $data = $this->actingAs($this->user)->getJson(self::BASE)->assertOk()->json('data');
        $this->assertArrayNotHasKey('scope_implications', $data);
        $this->assertArrayNotHasKey('token_scope_implications', $data);
        $this->assertSame([], $this->service()->scopeImplications(['time:read' => 'x']));

        // A presentation that does not implement the interface has none.
        $this->app->instance(ScopePresentation::class, new class implements ScopePresentation
        {
            public function groups(): array
            {
                return [new ScopeGroup('time', 'Time', ['time:read'])];
            }

            public function presets(): array
            {
                return [];
            }
        });
        $data = $this->actingAs($this->user)->getJson(self::BASE)->assertOk()->json('data');
        $this->assertArrayHasKey('scope_groups', $data);
        $this->assertArrayNotHasKey('scope_implications', $data);

        // An implementation declaring nothing emits nothing.
        $this->bind([], $this->standardGroups());
        $data = $this->actingAs($this->user)->getJson(self::BASE)->assertOk()->json('data');
        $this->assertArrayNotHasKey('scope_implications', $data);
    }

    public function test_values_are_the_transitive_closure_in_catalog_order(): void
    {
        $this->bind(['billing:deliver' => ['time:write'], 'time:write' => ['time:read'], 'time:read' => ['identity:read']]);
        $offered = array_fill_keys(array_keys(self::CATALOG), 'x');

        $this->assertSame([
            'time:read' => ['identity:read'],
            'time:write' => ['identity:read', 'time:read'],
            'billing:deliver' => ['identity:read', 'time:read', 'time:write'],
        ], $this->service()->scopeImplications($offered));
        $this->assertSame(['time:read', 'time:write', 'billing:deliver'], array_keys($this->service()->scopeImplications($offered)));
    }

    public function test_an_implication_reaches_through_a_scope_this_surface_does_not_offer(): void
    {
        $this->bind(['time:write' => ['time:read'], 'time:read' => ['identity:read']]);

        $this->assertSame(
            ['time:write' => ['identity:read']],
            $this->service()->scopeImplications(['time:write' => 'w', 'identity:read' => 'i']),
        );
    }

    public function test_entries_are_restricted_to_the_offered_scopes_and_empty_ones_dropped(): void
    {
        $this->bind(['time:write' => ['time:read', 'identity:read'], 'reports:read' => ['time:read']]);

        $this->assertSame(['time:write' => ['time:read']], $this->service()->scopeImplications(['time:write' => 'w', 'time:read' => 'r']));
        $this->assertSame([], $this->service()->scopeImplications(['time:write' => 'w']), 'No offered requirement: dropped');
        $this->assertSame([], $this->service()->scopeImplications(['time:read' => 'r']), 'Key not offered: dropped');
    }

    public function test_the_index_emits_scope_implications_and_token_ones_only_beside_token_scopes(): void
    {
        $this->bind(['time:write' => ['time:read'], 'reports:read' => ['time:read']], $this->standardGroups());

        $data = $this->actingAs($this->user)->getJson(self::BASE)->assertOk()->json('data');
        $this->assertSame(['time:write' => ['time:read'], 'reports:read' => ['time:read']], $data['scope_implications']);
        $this->assertArrayNotHasKey('token_scopes', $data);
        $this->assertArrayNotHasKey('token_scope_implications', $data);

        config(['bherila-auth.oauth_server' => AgentOAuthServer::config(self::CATALOG, [
            'resources' => [
                'rest' => ['path' => '/api/v1', 'scopes' => ['time:read', 'time:write', 'identity:read']],
                'mcp' => ['path' => '/api/v1/mcp', 'scopes' => ['mcp:use', 'time:read']],
            ],
            'assume_omitted_resource' => 'rest',
            'resource_required_scopes' => ['mcp:use'],
            'credentials' => ['enabled' => true, 'token_lifetimes' => ['P30D']],
        ], self::APP)]);
        $data = $this->actingAs($this->user)->getJson(self::BASE)->assertOk()->json('data');
        $this->assertArrayHasKey('token_scopes', $data);
        $this->assertSame(['time:write' => ['time:read']], $data['token_scope_implications'], 'reports:read is not a token scope');
        $this->assertArrayHasKey('reports:read', $data['scope_implications']);
    }

    public function test_the_implications_work_without_groups_or_presets_and_ids_are_strings(): void
    {
        $this->bind(['time:write' => ['time:read']]);
        $data = $this->actingAs($this->user)->getJson(self::BASE)->assertOk()->json('data');
        $this->assertSame(['time:write' => ['time:read']], $data['scope_implications']);
        $this->assertArrayNotHasKey('scope_groups', $data);

        config(['bherila-auth.oauth_server.scopes' => ['100', '200', 'time:read']]);
        $this->bind(['200' => ['100']]);
        $result = $this->service()->scopeImplications(['100' => 'a', '200' => 'b']);
        $this->assertSame([['200' => ['100']]], [$result]);
        $this->assertSame('100', $result['200'][0]);
        $this->assertSame('200', (string) array_key_first($result));
    }

    public function test_numeric_ids_still_serialize_as_an_object_and_a_deep_shared_graph_is_fast(): void
    {
        config(['bherila-auth.oauth_server.scopes' => ['0', '1']]);
        $this->bind(['0' => ['1']]);
        $this->actingAs($this->user)->getJson(self::BASE)->assertOk();
        $this->assertStringContainsString('"scope_implications":{"0":["1"]}', $this->getJson(self::BASE)->getContent());

        $ids = array_map(static fn (int $i): string => 's'.str_pad((string) $i, 2, '0', STR_PAD_LEFT), range(0, 39));
        config(['bherila-auth.oauth_server.scopes' => $ids]);
        $map = [];
        foreach ($ids as $i => $id) {
            if ($i < 39) {
                $map[$id] = array_slice($ids, $i + 1, 2);
            }
        }
        $this->bind($map);
        $started = microtime(true);
        $result = $this->service()->scopeImplications(array_fill_keys($ids, 'x'));
        $this->assertLessThan(2.0, microtime(true) - $started);
        $this->assertCount(39, $result);
        $this->assertSame(array_slice($ids, 1), $result['s00']);
    }

    public function test_an_unknown_key_or_requirement_is_named(): void
    {
        $this->bind(['ghost:key' => ['time:read']]);
        $this->assertInvalid('ghost:key');
        $this->bind(['time:write' => ['ghost:need']]);
        $this->assertInvalid('ghost:need');
    }

    public function test_a_scope_requiring_itself_is_named(): void
    {
        $this->bind(['time:write' => ['time:write']]);
        $this->assertInvalid('time:write');
    }

    public function test_a_cycle_is_named(): void
    {
        $this->bind(['time:write' => ['time:read'], 'time:read' => ['reports:read'], 'reports:read' => ['time:write']]);
        $this->assertInvalid('implication cycle');
        $this->assertInvalid('reports:read');
    }

    public function test_a_routine_scope_cannot_require_a_sensitive_one(): void
    {
        $this->bind(['time:write' => ['billing:deliver']], $this->standardGroups());
        $this->assertInvalid('time:write');
        $this->assertInvalid('billing:deliver');
    }

    public function test_a_sensitive_scope_may_require_a_routine_or_sensitive_one(): void
    {
        $this->bind(['billing:deliver' => ['time:read']], $this->standardGroups());
        $this->assertSame(['billing:deliver' => ['time:read']], $this->service()->scopeImplications(['billing:deliver' => 'b', 'time:read' => 'r']));
    }

    public function test_a_preset_must_be_closed_under_implications(): void
    {
        $this->bind(
            ['time:write' => ['time:read'], 'time:read' => ['identity:read']],
            $this->standardGroups(),
            [new ScopePreset('writer', 'Writer', 'Log time', ['time:write', 'time:read'])],
        );
        $this->assertInvalid('writer');
        $this->assertInvalid('identity:read');

        $this->bind(
            ['time:write' => ['time:read'], 'time:read' => ['identity:read']],
            $this->standardGroups(),
            [new ScopePreset('writer', 'Writer', 'Log time', ['time:write', 'time:read', 'identity:read'])],
        );
        $this->assertSame(['time:read' => ['identity:read'], 'time:write' => ['identity:read', 'time:read']], $this->service()->scopeImplications(array_fill_keys(array_keys(self::CATALOG), 'x')));
    }

    public function test_the_store_endpoints_neither_add_implied_scopes_nor_reject_a_missing_requirement(): void
    {
        $this->bind(['time:write' => ['time:read']], $this->standardGroups());
        $this->actingAs($this->user);

        $this->postJson(self::BASE.'/tokens', ['name' => 'x', 'scopes' => ['time:write'], 'lifetime' => 'P30D'])->assertCreated();
        $app = $this->postJson(self::BASE.'/apps', ['name' => 'x', 'redirect_uris' => ['http://127.0.0.1:3210/cb'], 'confidential' => true, 'scopes' => ['time:write']])->assertCreated();
        $this->assertStringNotContainsString('time:read', json_encode($app->json()));

        $listed = $this->getJson(self::BASE)->assertOk()->json('data.tokens');
        $this->assertSame(['time:write'], $listed[0]['scopes']);
    }
}
