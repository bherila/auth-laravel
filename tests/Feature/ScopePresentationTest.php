<?php

namespace BWH\Auth\Tests\Feature;

use BWH\Auth\AuthServiceProvider;
use BWH\Auth\OAuth\Credentials\ApiCredentialService;
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

/** Optional scope groups, sensitive groups and presets: presentation only. */
final class ScopePresentationTest extends TestCase
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
     * @param  list<ScopeGroup>  $groups
     * @param  list<ScopePreset>  $presets
     */
    private function bind(array $groups, array $presets = []): void
    {
        $this->app->instance(ScopePresentation::class, new class($groups, $presets) implements ScopePresentation
        {
            public function __construct(private readonly array $groups, private readonly array $presets) {}

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
            new ScopeGroup('admin', 'Admin', ['billing:deliver'], sensitive: true, description: 'Send to clients, move money'),
            new ScopeGroup('empty_here', 'Elsewhere', ['reports:read']),
        ];
    }

    private function service(): ApiCredentialService
    {
        return $this->app->make(ApiCredentialService::class);
    }

    private function assertInvalid(string $needle): void
    {
        try {
            $this->service()->scopeGroups(['time:read' => 'x']);
            $this->service()->scopePresets(['time:read' => 'x']);
            $this->fail('Expected a LogicException naming '.$needle);
        } catch (LogicException $e) {
            $this->assertStringContainsString($needle, $e->getMessage());
        }
    }

    public function test_the_default_binding_is_a_no_op(): void
    {
        $this->assertInstanceOf(UngroupedScopePresentation::class, $this->app->make(ScopePresentation::class));
        $data = $this->actingAs($this->user)->getJson(self::BASE)->assertOk()->json('data');
        foreach (['scope_groups', 'scope_presets', 'token_scope_groups', 'token_scope_presets'] as $key) {
            $this->assertArrayNotHasKey($key, $data);
        }
        $this->assertSame([], $this->service()->scopeGroups(['time:read' => 'x']));
        $this->assertSame([], $this->service()->scopePresets(['time:read' => 'x']));
    }

    public function test_groups_are_resolved_per_surface_in_declared_order_with_the_rest_in_other(): void
    {
        $this->bind($this->standardGroups());
        $offered = ['identity:read' => 'i', 'time:read' => 't', 'time:write' => 'w', 'billing:deliver' => 'b'];

        $groups = $this->service()->scopeGroups($offered);

        $this->assertSame(['time', 'admin', 'other'], array_column($groups, 'id'), 'Empty groups are dropped');
        $this->assertSame(['time:write', 'time:read'], $groups[0]['scopes'], 'Declared order is kept');
        $this->assertSame(['id' => 'admin', 'label' => 'Admin', 'description' => 'Send to clients, move money', 'sensitive' => true, 'scopes' => ['billing:deliver']], $groups[1]);
        $this->assertSame(['id' => 'other', 'label' => 'Other permissions', 'description' => null, 'sensitive' => false, 'scopes' => ['identity:read']], $groups[2]);
        $all = array_merge(...array_column($groups, 'scopes'));
        sort($all);
        $expected = array_keys($offered);
        sort($expected);
        $this->assertSame($expected, $all, 'Every offered scope appears exactly once');
    }

    public function test_the_other_group_uses_the_configured_label_and_no_other_group_when_all_are_grouped(): void
    {
        config(['bherila-auth.oauth_server.consent.ungrouped_label' => 'Everything else']);
        $this->bind($this->standardGroups());
        $groups = $this->service()->scopeGroups(['identity:read' => 'i']);
        $this->assertSame('Everything else', $groups[0]['label']);

        $this->assertSame(['time'], array_column($this->service()->scopeGroups(['time:read' => 'x']), 'id'));
    }

    public function test_a_preset_is_offered_only_where_every_one_of_its_scopes_is_offered(): void
    {
        $this->bind($this->standardGroups(), [new ScopePreset('time_logging', 'Time logging', 'Log your own time', ['identity:read', 'time:read', 'time:write'])]);

        $this->assertSame([], $this->service()->scopePresets(['time:read' => 'r', 'time:write' => 'w']));
        $presets = $this->service()->scopePresets(['identity:read' => 'i', 'time:read' => 'r', 'time:write' => 'w']);
        $this->assertSame([['id' => 'time_logging', 'label' => 'Time logging', 'description' => 'Log your own time', 'scopes' => ['identity:read', 'time:read', 'time:write']]], $presets);
    }

    public function test_the_index_adds_keys_only_when_bound_and_token_keys_only_with_token_scopes(): void
    {
        $this->bind($this->standardGroups(), [new ScopePreset('time_logging', 'Time logging', 'Log your own time', ['time:read', 'time:write'])]);

        $data = $this->actingAs($this->user)->getJson(self::BASE)->assertOk()->json('data');
        $this->assertSame(['time', 'admin', 'empty_here', 'other'], array_column($data['scope_groups'], 'id'));
        $this->assertSame(['time_logging'], array_column($data['scope_presets'], 'id'));
        $this->assertArrayNotHasKey('token_scopes', $data);
        $this->assertArrayNotHasKey('token_scope_groups', $data);
        $this->assertArrayNotHasKey('token_scope_presets', $data);
        $this->assertArrayNotHasKey('mcp:use', array_flip(array_merge(...array_column($data['scope_groups'], 'scopes'))));

        config(['bherila-auth.oauth_server' => AgentOAuthServer::config(self::CATALOG, [
            'resources' => [
                'rest' => ['path' => '/api/v1', 'scopes' => ['time:read', 'time:write', 'identity:read']],
                'mcp' => ['path' => '/api/v1/mcp', 'scopes' => ['mcp:use', 'time:read']],
            ],
            'assume_omitted_resource' => 'rest',
            'resource_required_scopes' => ['mcp:use'],
            'credentials' => ['enabled' => true, 'token_lifetimes' => ['P30D']],
        ], self::APP)]);
        $this->bind($this->standardGroups(), [
            new ScopePreset('time_logging', 'Time logging', 'Log your own time', ['time:read', 'time:write']),
            new ScopePreset('reporting', 'Reporting', 'Read reports', ['time:read', 'reports:read']),
        ]);
        $data = $this->actingAs($this->user)->getJson(self::BASE)->assertOk()->json('data');
        $this->assertSame(['time_logging', 'reporting'], array_column($data['scope_presets'], 'id'));
        $this->assertSame(['time_logging'], array_column($data['token_scope_presets'], 'id'), 'Not offered on the token surface: reports:read');
        $this->assertSame(['time', 'other'], array_column($data['token_scope_groups'], 'id'));
        $this->assertSame(['identity:read'], $data['token_scope_groups'][1]['scopes']);
        $this->assertArrayNotHasKey('token_connection_scopes', $data);
    }

    public function test_a_preset_or_group_id_is_refused_as_a_scope_and_explicit_scopes_still_work(): void
    {
        $this->bind($this->standardGroups(), [new ScopePreset('time_logging', 'Time logging', 'Log time', ['time:read', 'time:write'])]);
        $this->actingAs($this->user);

        foreach (['time_logging', 'time', 'other'] as $id) {
            $this->postJson(self::BASE.'/tokens', ['name' => 'x', 'scopes' => [$id], 'lifetime' => 'P30D'])->assertStatus(422)->assertJsonValidationErrors('scopes.0');
            $this->postJson(self::BASE.'/apps', ['name' => 'x', 'redirect_uris' => ['http://127.0.0.1:3210/cb'], 'confidential' => true, 'scopes' => [$id]])->assertStatus(422)->assertJsonValidationErrors('scopes.0');
        }
        $this->postJson(self::BASE.'/tokens', ['name' => 'x', 'scopes' => ['time:read', 'time:write'], 'lifetime' => 'P30D'])->assertCreated();
        $this->postJson(self::BASE.'/apps', ['name' => 'x', 'redirect_uris' => ['http://127.0.0.1:3210/cb'], 'confidential' => true, 'scopes' => ['time:read']])->assertCreated();
    }

    public function test_an_unknown_catalog_scope_in_a_group_or_preset_is_named(): void
    {
        $this->bind([new ScopeGroup('g', 'G', ['nope:scope'])]);
        $this->assertInvalid('nope:scope');
        $this->bind([], [new ScopePreset('p', 'P', 'd', ['ghost:scope'])]);
        $this->assertInvalid('ghost:scope');
    }

    public function test_a_scope_in_two_groups_is_named(): void
    {
        $this->bind([new ScopeGroup('a', 'A', ['time:read']), new ScopeGroup('b', 'B', ['time:read'])]);
        $this->assertInvalid('time:read');
    }

    public function test_duplicate_or_malformed_ids_are_named(): void
    {
        $this->bind([new ScopeGroup('dup', 'A', ['time:read']), new ScopeGroup('dup', 'B', ['time:write'])]);
        $this->assertInvalid('dup');
        $this->bind([new ScopeGroup('Bad-Id', 'A', ['time:read'])]);
        $this->assertInvalid('Bad-Id');
        $this->bind([], [new ScopePreset('same', 'A', 'd', ['time:read']), new ScopePreset('same', 'B', 'd', ['time:write'])]);
        $this->assertInvalid('same');
        $this->bind([], [new ScopePreset('Bad Preset', 'A', 'd', ['time:read'])]);
        $this->assertInvalid('Bad Preset');
    }

    public function test_an_empty_preset_is_named(): void
    {
        $this->bind([], [new ScopePreset('hollow', 'H', 'd', [])]);
        $this->assertInvalid('hollow');
    }

    public function test_a_preset_cannot_contain_a_sensitive_scope(): void
    {
        $this->bind($this->standardGroups(), [new ScopePreset('risky', 'R', 'd', ['time:read', 'billing:deliver'])]);
        $this->assertInvalid('risky');
        $this->assertInvalid('billing:deliver');
    }

    /** @param list<string> $ids */
    private function consent(array $ids, string $clientName = 'Example Agent'): string
    {
        $scopes = array_map(static fn (string $id): object => new class($id, self::CATALOG[$id])
        {
            public function __construct(public string $id, public string $description) {}
        }, $ids);
        $client = new class($clientName)
        {
            public function __construct(public string $name) {}

            public function getAttribute(string $key): mixed
            {
                return null;
            }
        };
        $html = view('bherila-auth::oauth.authorize', [
            'client' => $client,
            'scopes' => $scopes,
            'request' => Request::create('/oauth/authorize'),
            'user' => $this->user,
            'authToken' => 'fixed-auth-token',
        ])->render();

        return (string) preg_replace('/name="_token" value="[^"]*"/', 'name="_token" value="TOKEN"', $html);
    }

    public function test_the_consent_markup_is_byte_for_byte_unchanged_without_a_presentation(): void
    {
        $html = $this->consent(['identity:read', 'time:read']);
        $this->assertSame(file_get_contents(__DIR__.'/../Fixtures/consent-default.html'), $html);
        $this->assertStringNotContainsString('scope-group', $html);

        $this->bind([], [new ScopePreset('p', 'P', 'd', ['time:read'])]);
        $this->assertSame($html, $this->consent(['identity:read', 'time:read']), 'Presets alone do not change the consent page');
    }

    public function test_the_consent_screen_renders_grouped_sections_in_order_with_only_requested_scopes(): void
    {
        $this->bind($this->standardGroups());
        $html = $this->consent(['identity:read', 'time:read', 'time:write', 'billing:deliver']);

        $this->assertSame(3, substr_count($html, '<section class="scope-group'));
        $time = strpos($html, '<h3>Time</h3>');
        $admin = strpos($html, '<h3>Admin</h3>');
        $other = strpos($html, '<h3>Other permissions</h3>');
        $this->assertTrue($time < $admin && $admin < $other);
        $this->assertLessThan(strpos($html, 'Read time'), strpos($html, 'Log time'), 'Declared order within a group');
        $this->assertStringNotContainsString('Read reports', $html);
        $this->assertStringNotContainsString('<h3>Elsewhere</h3>', $html);
        $this->assertStringContainsString('<p>Send to clients, move money</p>', $html);
        $this->assertStringContainsString('<section class="scope-group sensitive">', $html);
        $this->assertSame(1, substr_count($html, 'These permissions allow sensitive actions. Only approve them if you need them.'));
        $this->assertStringContainsString('Send invoices &amp; move money', $html);
    }

    public function test_a_requested_scope_without_an_id_falls_back_to_the_flat_list_rather_than_vanishing(): void
    {
        $this->bind($this->standardGroups());
        $client = new class
        {
            public string $name = 'Example Agent';

            public function getAttribute(string $key): mixed
            {
                return null;
            }
        };
        $scopes = [
            new class
            {
                public string $id = 'time:read';

                public string $description = 'Read time';
            },
            new class
            {
                public string $description = 'A scope the page can only describe';
            },
        ];

        $html = view('bherila-auth::oauth.authorize', [
            'client' => $client,
            'scopes' => $scopes,
            'request' => Request::create('/oauth/authorize'),
            'user' => $this->user,
            'authToken' => 'fixed-auth-token',
        ])->render();

        $this->assertStringNotContainsString('scope-group', $html);
        $this->assertStringContainsString('Read time', $html);
        $this->assertStringContainsString('A scope the page can only describe', $html);
    }

    public function test_a_group_without_the_sensitive_flag_shows_no_warning(): void
    {
        $this->bind($this->standardGroups());
        $html = $this->consent(['time:read']);
        $this->assertStringNotContainsString('sensitive actions', $html);
        $this->assertStringNotContainsString('scope-group sensitive"', $html);
    }

    public function test_consent_labels_descriptions_and_notice_are_escaped(): void
    {
        config(['bherila-auth.oauth_server.consent.sensitive_notice' => 'Careful <b>:client</b>']);
        $this->bind([
            new ScopeGroup('time', '<script>alert(1)</script>', ['time:read'], sensitive: true, description: '<img src=x onerror=alert(2)>'),
        ]);
        $html = $this->consent(['time:read']);

        $this->assertStringNotContainsString('<script>alert(1)</script>', $html);
        $this->assertStringNotContainsString('<img src=x', $html);
        $this->assertStringNotContainsString('<b>', $html);
        $this->assertStringContainsString('&lt;script&gt;alert(1)&lt;/script&gt;', $html);
        $this->assertStringContainsString('Careful &lt;b&gt;Example Agent&lt;/b&gt;', $html);
    }
}
