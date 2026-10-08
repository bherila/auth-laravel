<?php

namespace BWH\Auth\Tests\Feature;

use BWH\Auth\Console\CheckCloudflareRangesCommand;
use BWH\Auth\Http\TrustedProxies;
use BWH\Auth\Tests\TestCase;
use Illuminate\Http\Middleware\TrustProxies;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

/**
 * The client address behind a CDN, and only behind it.
 *
 * Untrusted, every caller looks like an edge address and shares one rate-limit
 * budget. Trusted too broadly, an origin that answers direct connections lets
 * anyone forge their address. These pin the line between the two.
 */
class TrustedProxiesTest extends TestCase
{
    private bool $apply = true;

    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);
        $app['config']->set('bherila-auth.trusted_proxies.apply', $this->apply);
    }

    protected function setUp(): void
    {
        parent::setUp();
        Route::get('/whoami', fn (Request $request) => response()->json([
            'ip' => $request->ip(),
            'secure' => $request->isSecure(),
            'host' => $request->getHost(),
            'port' => $request->getPort(),
        ]));
        Route::post('/limited', fn () => response()->json(['ok' => true]))->middleware('throttle:2,1');
    }

    protected function tearDown(): void
    {
        TrustProxies::flushState();
        CheckCloudflareRangesCommand::$fetcher = null;
        parent::tearDown();
    }

    public function test_settings_resolve_to_what_trust_proxies_accepts(): void
    {
        $this->assertNull(TrustedProxies::resolve(null));
        $this->assertNull(TrustedProxies::resolve('  '));
        $this->assertSame('*', TrustedProxies::resolve('*'));
        $this->assertSame(TrustedProxies::CLOUDFLARE, TrustedProxies::resolve('cloudflare'));
        $this->assertSame(['10.0.0.1', '192.0.2.0/24'], TrustedProxies::resolve(' 10.0.0.1, 192.0.2.0/24 ,'));
        $this->assertSame(['10.0.0.1', '173.245.48.0/20'], TrustedProxies::resolve('10.0.0.1,cloudflare', ['173.245.48.0/20']));
    }

    public function test_a_cloudflare_edge_forwards_the_client_address(): void
    {
        $this->withServerVariables(['REMOTE_ADDR' => '104.16.1.2', 'HTTP_X_FORWARDED_FOR' => '198.51.100.7', 'HTTP_X_FORWARDED_PROTO' => 'https'])
            ->getJson('/whoami')->assertOk()->assertJsonPath('ip', '198.51.100.7')->assertJsonPath('secure', true);
        $this->withServerVariables(['REMOTE_ADDR' => '2606:4700::1234', 'HTTP_X_FORWARDED_FOR' => '2001:db8::9'])
            ->getJson('/whoami')->assertOk()->assertJsonPath('ip', '2001:db8::9');
    }

    /** The edge appends what it saw; that rightmost value is the client, never what the client wrote. */
    public function test_a_client_supplied_chain_resolves_to_the_address_the_edge_appended(): void
    {
        $this->withServerVariables(['REMOTE_ADDR' => '172.64.9.9', 'HTTP_X_FORWARDED_FOR' => '192.0.2.1, 192.0.2.2, 198.51.100.7'])
            ->getJson('/whoami')->assertOk()->assertJsonPath('ip', '198.51.100.7');
    }

    public function test_a_direct_connection_cannot_spoof_its_address_or_scheme(): void
    {
        $this->withServerVariables([
            'REMOTE_ADDR' => '203.0.113.5',
            'HTTP_X_FORWARDED_FOR' => '198.51.100.7',
            'HTTP_CF_CONNECTING_IP' => '198.51.100.7',
            'HTTP_X_FORWARDED_PROTO' => 'https',
        ])->getJson('/whoami')->assertOk()->assertJsonPath('ip', '203.0.113.5')->assertJsonPath('secure', false);
    }

    public function test_the_forwarded_host_is_never_trusted(): void
    {
        $this->withServerVariables(['REMOTE_ADDR' => '104.16.1.2', 'HTTP_X_FORWARDED_FOR' => '198.51.100.7', 'HTTP_X_FORWARDED_HOST' => 'evil.example.test'])
            ->getJson('/whoami')->assertOk()->assertJsonPath('host', 'localhost');
    }

    /** Cloudflare passes a client-supplied X-Forwarded-Port through, so it is never trusted. */
    public function test_the_forwarded_port_is_never_trusted(): void
    {
        $this->withServerVariables(['REMOTE_ADDR' => '104.16.1.2', 'HTTP_X_FORWARDED_FOR' => '198.51.100.7', 'HTTP_X_FORWARDED_PROTO' => 'https', 'HTTP_X_FORWARDED_PORT' => '8443', 'SERVER_PORT' => '443'])
            ->getJson('/whoami')->assertJsonPath('port', 443);
    }

    public function test_throttles_key_on_the_client_behind_the_edge_and_on_the_peer_otherwise(): void
    {
        foreach (['198.51.100.7', '198.51.100.7', '198.51.100.8'] as $client) {
            $this->withServerVariables(['REMOTE_ADDR' => '172.64.9.9', 'HTTP_X_FORWARDED_FOR' => $client])->postJson('/limited')->assertOk();
        }
        $this->withServerVariables(['REMOTE_ADDR' => '172.64.9.9', 'HTTP_X_FORWARDED_FOR' => '198.51.100.7'])->postJson('/limited')->assertTooManyRequests();
        $this->withServerVariables(['REMOTE_ADDR' => '172.64.9.9', 'HTTP_X_FORWARDED_FOR' => '198.51.100.8'])->postJson('/limited')->assertOk();

        foreach (['192.0.2.10', '192.0.2.11'] as $forged) {
            $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.5', 'HTTP_X_FORWARDED_FOR' => $forged])->postJson('/limited')->assertOk();
        }
        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.5', 'HTTP_X_FORWARDED_FOR' => '192.0.2.12'])->postJson('/limited')->assertTooManyRequests();
    }

    /** An empty setting trusts nothing, even over a `*` configured elsewhere. */
    public function test_an_empty_setting_clears_trust_configured_elsewhere(): void
    {
        TrustProxies::at('*');
        config(['bherila-auth.trusted_proxies.trusted' => '']);
        TrustedProxies::apply();

        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.5', 'HTTP_X_FORWARDED_FOR' => '198.51.100.7'])
            ->getJson('/whoami')->assertJsonPath('ip', '203.0.113.5');
    }

    public function test_a_configured_list_replaces_the_shipped_ranges(): void
    {
        config(['bherila-auth.trusted_proxies.cloudflare' => ['10.9.0.0/16']]);
        TrustProxies::flushState();
        TrustedProxies::apply();

        $this->withServerVariables(['REMOTE_ADDR' => '10.9.1.1', 'HTTP_X_FORWARDED_FOR' => '198.51.100.7'])
            ->getJson('/whoami')->assertJsonPath('ip', '198.51.100.7');
        $this->withServerVariables(['REMOTE_ADDR' => '104.16.1.2', 'HTTP_X_FORWARDED_FOR' => '198.51.100.7'])
            ->getJson('/whoami')->assertJsonPath('ip', '104.16.1.2');
    }

    public function test_the_drift_check_passes_on_a_match_and_reports_additions_and_removals(): void
    {
        $v4 = array_values(array_filter(TrustedProxies::CLOUDFLARE, static fn (string $r): bool => ! str_contains($r, ':')));
        $v6 = array_values(array_filter(TrustedProxies::CLOUDFLARE, static fn (string $r): bool => str_contains($r, ':')));
        CheckCloudflareRangesCommand::$fetcher = static fn (string $url): string => implode("\n", str_ends_with($url, 'v4') ? $v4 : $v6);
        $this->artisan('bherila-auth:check-cloudflare-ranges')->assertExitCode(0);

        CheckCloudflareRangesCommand::$fetcher = static fn (string $url): string => implode("\n", str_ends_with($url, 'v4') ? [...array_slice($v4, 1), '198.18.0.0/15'] : $v6);
        $this->artisan('bherila-auth:check-cloudflare-ranges')
            ->expectsOutputToContain('add:    198.18.0.0/15')
            ->expectsOutputToContain('remove: '.$v4[0])
            ->assertExitCode(1);

        CheckCloudflareRangesCommand::$fetcher = static fn (string $url): bool => false;
        $this->artisan('bherila-auth:check-cloudflare-ranges')->assertExitCode(2);
    }
}
