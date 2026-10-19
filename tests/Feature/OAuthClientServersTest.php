<?php

namespace BWH\Auth\Tests\Feature;

use BWH\Auth\OAuth\OAuthCallbackRejected;
use BWH\Auth\OAuth\OAuthClient;
use BWH\Auth\OAuth\OAuthTokenRequestFailed;
use BWH\Auth\Tests\TestCase;
use Illuminate\Auth\GenericUser;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Client\Request as ClientRequest;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use Symfony\Component\HttpKernel\Exception\HttpException;

/**
 * An application that is a client of several authorization servers: the sign-in provider
 * (the legacy single-provider settings) plus named servers whose APIs it calls for a person.
 */
class OAuthClientServersTest extends TestCase
{
    private const string SVC = 'https://svc.example.test';

    private const string PHR = 'https://phr.example.test';

    protected function setUp(): void
    {
        parent::setUp();

        config(['bherila-auth.oauth_client' => [
            'provider' => 'bherila',
            'base_url' => 'https://identity.example.test',
            'client_id' => 'sign-in-client',
            'client_secret' => 'sign-in-secret',
            'redirect_uri' => 'https://pf.example.test/oauth/callback',
            'scope' => 'identity:read',
            'authorize_path' => '/oauth/authorize',
            'token_path' => '/oauth/token',
            'identity_path' => '/api/oauth/user',
            'end_session_path' => '/oauth/end-session',
            'servers' => [
                'svc' => [
                    'issuer' => self::SVC,
                    'client_id' => 'pf-at-svc',
                    'client_secret' => 'svc-secret',
                    'redirect_uri' => 'https://pf.example.test/connections/svc/callback',
                    'scope' => 'finance:read identity:read',
                    'resource' => self::SVC.'/api/v1',
                    'authorization_response_iss' => 'required',
                ],
                'phr' => [
                    'issuer' => self::PHR,
                    'client_id' => 'pf-at-phr',
                    'client_secret' => 'phr-secret',
                    'redirect_uri' => 'https://pf.example.test/connections/phr/callback',
                    'scope' => 'billing:read identity:read',
                    'resource' => self::PHR.'/api/v1',
                    'authorization_response_iss' => 'required',
                ],
            ],
        ]]);

        Route::middleware('web')->group(function (): void {
            foreach (['svc', 'phr'] as $server) {
                Route::get("/connections/{$server}/start", fn (Request $request, OAuthClient $client) => $client->forServer($server)->redirect($request));
                Route::get("/connections/{$server}/callback", fn (Request $request, OAuthClient $client) => self::tokens($client->forServer($server), $request));
            }

            // A route that hands a response to the svc client although it is not svc's callback.
            Route::get('/connections/elsewhere', fn (Request $request, OAuthClient $client) => self::tokens($client->forServer('svc'), $request));
        });
    }

    private static function tokens(OAuthClient $client, Request $request): JsonResponse
    {
        try {
            $tokens = $client->tokensFromCallback($request);
        } catch (OAuthCallbackRejected $rejected) {
            return response()->json([
                'rejected' => $rejected->reason->value,
                'provider_error' => $rejected->providerError,
            ], $rejected->getStatusCode());
        }

        return response()->json([
            'server' => $tokens->server,
            'issuer' => $tokens->issuer,
            'resource' => $tokens->resource,
            'access_token' => $tokens->accessToken,
            'refresh_token' => $tokens->refreshToken,
            'scopes' => $tokens->scopes,
        ]);
    }

    private function fakeServers(): void
    {
        Http::fake([
            self::SVC.'/oauth/token' => Http::response([
                'token_type' => 'Bearer',
                'access_token' => 'svc-access',
                'refresh_token' => 'svc-refresh',
                'expires_in' => 900,
                'scope' => 'finance:read identity:read',
            ]),
            self::PHR.'/oauth/token' => Http::response([
                'token_type' => 'Bearer',
                'access_token' => 'phr-access',
                'refresh_token' => 'phr-refresh',
                'expires_in' => 900,
            ]),
        ]);
    }

    /** @return array<string, string> */
    private function startFlow(string $server): array
    {
        $response = $this->get("/connections/{$server}/start");
        $response->assertRedirect();
        parse_str((string) parse_url((string) $response->headers->get('Location'), PHP_URL_QUERY), $query);

        return $query;
    }

    /** @param  array<string, string>  $parameters */
    private function respond(string $server, array $parameters): TestResponse
    {
        return $this->get("/connections/{$server}/callback?".http_build_query($parameters));
    }

    private function assertNoTokenRequest(): void
    {
        Http::assertNotSent(fn (ClientRequest $request): bool => str_ends_with($request->url(), '/oauth/token'));
    }

    public function test_each_server_redirects_from_its_own_configuration(): void
    {
        $response = $this->get('/connections/svc/start');

        $response->assertRedirectContains(self::SVC.'/oauth/authorize?');
        parse_str((string) parse_url((string) $response->headers->get('Location'), PHP_URL_QUERY), $query);
        $this->assertSame('pf-at-svc', $query['client_id']);
        $this->assertSame('https://pf.example.test/connections/svc/callback', $query['redirect_uri']);
        $this->assertSame('code', $query['response_type']);
        $this->assertSame('finance:read identity:read', $query['scope']);
        $this->assertSame(self::SVC.'/api/v1', $query['resource']);
        $this->assertSame('S256', $query['code_challenge_method']);
        $this->assertGreaterThanOrEqual(40, strlen($query['state']));

        // The sign-in flow's single pending state is left alone.
        $response->assertSessionMissing('oauth.login.state');
        $response->assertSessionMissing('oauth.login.code_verifier');
    }

    public function test_a_bound_flow_exchanges_the_code_at_the_configured_token_endpoint(): void
    {
        $this->fakeServers();
        $query = $this->startFlow('svc');

        $this->respond('svc', ['code' => 'svc-code', 'state' => $query['state'], 'iss' => self::SVC])
            ->assertOk()
            ->assertExactJson([
                'server' => 'svc',
                'issuer' => self::SVC,
                'resource' => self::SVC.'/api/v1',
                'access_token' => 'svc-access',
                'refresh_token' => 'svc-refresh',
                'scopes' => ['finance:read', 'identity:read'],
            ]);

        Http::assertSentCount(1);
        Http::assertSent(function (ClientRequest $request): bool {
            return $request->url() === self::SVC.'/oauth/token'
                && $request['grant_type'] === 'authorization_code'
                && $request['client_id'] === 'pf-at-svc'
                && $request['client_secret'] === 'svc-secret'
                && $request['redirect_uri'] === 'https://pf.example.test/connections/svc/callback'
                && $request['resource'] === self::SVC.'/api/v1'
                && $request['code'] === 'svc-code'
                && is_string($request['code_verifier']) && strlen($request['code_verifier']) >= 43;
        });
    }

    public function test_the_verifier_sent_matches_the_challenge_of_the_same_flow(): void
    {
        $this->fakeServers();
        $query = $this->startFlow('svc');

        $this->respond('svc', ['code' => 'svc-code', 'state' => $query['state'], 'iss' => self::SVC])->assertOk();

        Http::assertSent(fn (ClientRequest $request): bool => rtrim(strtr(base64_encode(hash('sha256', (string) $request['code_verifier'], true)), '+/', '-_'), '=') === $query['code_challenge']);
    }

    public function test_a_wrong_issuer_is_rejected_before_the_code_is_exchanged(): void
    {
        $this->fakeServers();
        $query = $this->startFlow('svc');

        $this->respond('svc', ['code' => 'svc-code', 'state' => $query['state'], 'iss' => self::PHR])
            ->assertForbidden()
            ->assertJsonPath('rejected', 'issuer_mismatch');

        $this->assertNoTokenRequest();
    }

    public function test_the_issuer_must_match_exactly(): void
    {
        $this->fakeServers();

        foreach ([self::SVC.'/', strtoupper(self::SVC), self::SVC.' ', 'svc.example.test'] as $near) {
            $query = $this->startFlow('svc');

            $this->respond('svc', ['code' => 'svc-code', 'state' => $query['state'], 'iss' => $near])
                ->assertForbidden()
                ->assertJsonPath('rejected', 'issuer_mismatch');
        }

        $this->assertNoTokenRequest();
    }

    public function test_an_issuer_sent_as_an_array_is_rejected(): void
    {
        $this->fakeServers();
        $query = $this->startFlow('svc');

        $this->get('/connections/svc/callback?code=c&state='.urlencode($query['state']).'&iss[]='.urlencode(self::SVC))
            ->assertForbidden()
            ->assertJsonPath('rejected', 'issuer_mismatch');

        $this->assertNoTokenRequest();
    }

    public function test_a_missing_issuer_is_rejected_when_the_server_is_configured_to_send_it(): void
    {
        $this->fakeServers();
        $query = $this->startFlow('svc');

        $this->respond('svc', ['code' => 'svc-code', 'state' => $query['state']])
            ->assertForbidden()
            ->assertJsonPath('rejected', 'issuer_missing');

        $this->assertNoTokenRequest();
    }

    public function test_a_missing_issuer_is_rejected_when_the_server_advertises_rfc_9207(): void
    {
        config(['bherila-auth.oauth_client.servers.svc.authorization_response_iss' => 'advertised']);
        Http::fake([
            self::SVC.'/.well-known/oauth-authorization-server' => Http::response([
                'issuer' => self::SVC,
                'authorization_response_iss_parameter_supported' => true,
            ]),
            self::SVC.'/oauth/token' => Http::response(['access_token' => 'svc-access', 'token_type' => 'Bearer']),
        ]);
        $query = $this->startFlow('svc');

        $this->respond('svc', ['code' => 'svc-code', 'state' => $query['state']])
            ->assertForbidden()
            ->assertJsonPath('rejected', 'issuer_missing');

        $this->assertNoTokenRequest();
    }

    public function test_a_server_that_does_not_advertise_rfc_9207_may_omit_the_issuer(): void
    {
        config(['bherila-auth.oauth_client.servers.svc.authorization_response_iss' => 'advertised']);
        Http::fake([
            self::SVC.'/.well-known/oauth-authorization-server' => Http::response(['issuer' => self::SVC]),
            self::SVC.'/oauth/token' => Http::response(['access_token' => 'svc-access', 'token_type' => 'Bearer']),
        ]);

        $query = $this->startFlow('svc');
        $this->respond('svc', ['code' => 'svc-code', 'state' => $query['state']])->assertOk();

        // But an issuer it does send must still be the right one.
        $query = $this->startFlow('svc');
        $this->respond('svc', ['code' => 'svc-code', 'state' => $query['state'], 'iss' => self::PHR])
            ->assertForbidden()
            ->assertJsonPath('rejected', 'issuer_mismatch');
    }

    public function test_metadata_is_read_from_the_configured_issuer_and_its_endpoints_are_ignored(): void
    {
        config(['bherila-auth.oauth_client.servers.svc.authorization_response_iss' => 'advertised']);
        Http::fake([
            self::SVC.'/.well-known/oauth-authorization-server' => Http::response([
                'issuer' => self::SVC,
                'authorization_endpoint' => 'https://attacker.example.test/authorize',
                'token_endpoint' => 'https://attacker.example.test/token',
                'authorization_response_iss_parameter_supported' => true,
            ]),
            self::SVC.'/oauth/token' => Http::response(['access_token' => 'svc-access', 'token_type' => 'Bearer']),
        ]);

        $start = $this->get('/connections/svc/start');
        $start->assertRedirectContains(self::SVC.'/oauth/authorize?');
        parse_str((string) parse_url((string) $start->headers->get('Location'), PHP_URL_QUERY), $query);

        $this->respond('svc', ['code' => 'svc-code', 'state' => $query['state'], 'iss' => self::SVC])->assertOk();

        Http::assertNotSent(fn (ClientRequest $request): bool => str_contains($request->url(), 'attacker'));
        Http::assertSent(fn (ClientRequest $request): bool => $request->url() === self::SVC.'/oauth/token');
    }

    public function test_metadata_naming_another_issuer_fails_closed(): void
    {
        config(['bherila-auth.oauth_client.servers.svc.authorization_response_iss' => 'advertised']);
        Http::fake([
            self::SVC.'/.well-known/oauth-authorization-server' => Http::response(['issuer' => self::PHR]),
        ]);

        $this->get('/connections/svc/start')->assertStatus(503);
        $this->assertSame([], session('oauth.flows', []));
    }

    public function test_unavailable_metadata_fails_closed(): void
    {
        config(['bherila-auth.oauth_client.servers.svc.authorization_response_iss' => 'advertised']);
        Http::fake([
            self::SVC.'/.well-known/oauth-authorization-server' => Http::response('down', 500),
        ]);

        $this->get('/connections/svc/start')->assertStatus(503);
    }

    public function test_metadata_is_cached_between_flows(): void
    {
        config(['bherila-auth.oauth_client.servers.svc.authorization_response_iss' => 'advertised']);
        Http::fake([
            self::SVC.'/.well-known/oauth-authorization-server' => Http::response([
                'issuer' => self::SVC,
                'authorization_response_iss_parameter_supported' => true,
            ]),
        ]);

        $this->get('/connections/svc/start')->assertRedirect();
        $this->get('/connections/svc/start')->assertRedirect();

        Http::assertSentCount(1);
    }

    public function test_a_path_issuer_reads_metadata_at_the_rfc_8414_location(): void
    {
        config([
            'bherila-auth.oauth_client.servers.svc.issuer' => self::SVC.'/tenant',
            'bherila-auth.oauth_client.servers.svc.authorization_response_iss' => 'advertised',
        ]);
        Http::fake([
            self::SVC.'/.well-known/oauth-authorization-server/tenant' => Http::response([
                'issuer' => self::SVC.'/tenant',
                'authorization_response_iss_parameter_supported' => true,
            ]),
        ]);

        $this->get('/connections/svc/start')->assertRedirectContains(self::SVC.'/tenant/oauth/authorize?');
        Cache::flush();
    }

    public function test_a_response_for_another_server_is_rejected_at_this_servers_callback(): void
    {
        $this->fakeServers();
        $phr = $this->startFlow('phr');

        // PHR's response (with PHR's own, correct issuer) delivered to SVC's callback.
        $this->respond('svc', ['code' => 'phr-code', 'state' => $phr['state'], 'iss' => self::PHR])
            ->assertForbidden()
            ->assertJsonPath('rejected', 'server_mismatch');

        // The flow is spent: it cannot then be completed where it belonged either.
        $this->respond('phr', ['code' => 'phr-code', 'state' => $phr['state'], 'iss' => self::PHR])
            ->assertForbidden()
            ->assertJsonPath('rejected', 'state_mismatch');

        $this->assertNoTokenRequest();
    }

    public function test_a_response_delivered_to_a_route_that_is_not_the_servers_callback_is_rejected(): void
    {
        $this->fakeServers();
        $query = $this->startFlow('svc');

        $this->get('/connections/elsewhere?'.http_build_query(['code' => 'c', 'state' => $query['state'], 'iss' => self::SVC]))
            ->assertForbidden()
            ->assertJsonPath('rejected', 'callback_mismatch');

        $this->assertNoTokenRequest();
    }

    public function test_a_replayed_state_is_rejected(): void
    {
        $this->fakeServers();
        $query = $this->startFlow('svc');
        $parameters = ['code' => 'svc-code', 'state' => $query['state'], 'iss' => self::SVC];

        $this->respond('svc', $parameters)->assertOk();
        $this->respond('svc', $parameters)->assertForbidden()->assertJsonPath('rejected', 'state_mismatch');

        Http::assertSentCount(1);
    }

    public function test_an_unknown_or_missing_state_is_rejected(): void
    {
        $this->fakeServers();
        $this->startFlow('svc');

        $this->respond('svc', ['code' => 'c', 'state' => 'not-the-state', 'iss' => self::SVC])
            ->assertForbidden()->assertJsonPath('rejected', 'state_mismatch');
        $this->respond('svc', ['code' => 'c', 'iss' => self::SVC])
            ->assertForbidden()->assertJsonPath('rejected', 'state_mismatch');
        $this->get('/connections/svc/callback?code=c&state[]=x')
            ->assertForbidden()->assertJsonPath('rejected', 'state_mismatch');

        $this->assertNoTokenRequest();
    }

    public function test_a_failed_check_spends_the_flow(): void
    {
        $this->fakeServers();
        $query = $this->startFlow('svc');

        $this->respond('svc', ['code' => 'c', 'state' => $query['state'], 'iss' => self::PHR])->assertForbidden();
        $this->respond('svc', ['code' => 'c', 'state' => $query['state'], 'iss' => self::SVC])
            ->assertForbidden()->assertJsonPath('rejected', 'state_mismatch');

        $this->assertNoTokenRequest();
    }

    public function test_a_flow_started_in_another_session_is_rejected(): void
    {
        $this->fakeServers();
        $query = $this->startFlow('svc');

        // The victim's browser has its own session; the attacker's state is not in it.
        $this->flushSession();

        $this->respond('svc', ['code' => 'attacker-code', 'state' => $query['state'], 'iss' => self::SVC])
            ->assertForbidden()
            ->assertJsonPath('rejected', 'state_mismatch');

        $this->assertNoTokenRequest();
    }

    public function test_a_flow_is_bound_to_the_user_who_started_it(): void
    {
        $this->fakeServers();
        $this->actingAs(new GenericUser(['id' => 7]));
        $query = $this->startFlow('svc');

        $this->actingAs(new GenericUser(['id' => 8]));
        $this->respond('svc', ['code' => 'c', 'state' => $query['state'], 'iss' => self::SVC])
            ->assertForbidden()
            ->assertJsonPath('rejected', 'user_mismatch');

        $this->assertNoTokenRequest();
    }

    public function test_a_flow_started_signed_in_is_not_completed_signed_out(): void
    {
        $this->fakeServers();
        $this->actingAs(new GenericUser(['id' => 7]));
        $query = $this->startFlow('svc');

        $this->app['auth']->guard()->forgetUser();
        $this->respond('svc', ['code' => 'c', 'state' => $query['state'], 'iss' => self::SVC])
            ->assertForbidden()
            ->assertJsonPath('rejected', 'user_mismatch');
    }

    public function test_the_same_user_completes_the_flow(): void
    {
        $this->fakeServers();
        $this->actingAs(new GenericUser(['id' => 7]));
        $query = $this->startFlow('svc');

        $this->respond('svc', ['code' => 'c', 'state' => $query['state'], 'iss' => self::SVC])->assertOk();
    }

    public function test_an_expired_flow_is_rejected(): void
    {
        $this->fakeServers();
        $query = $this->startFlow('svc');

        $this->travel(31)->minutes();

        $this->respond('svc', ['code' => 'c', 'state' => $query['state'], 'iss' => self::SVC])
            ->assertForbidden()
            ->assertJsonPath('rejected', 'expired');

        $this->assertNoTokenRequest();
    }

    public function test_a_flow_whose_server_configuration_changed_is_rejected(): void
    {
        $this->fakeServers();
        $query = $this->startFlow('svc');

        config(['bherila-auth.oauth_client.servers.svc.resource' => self::SVC.'/api/v2']);

        $this->respond('svc', ['code' => 'c', 'state' => $query['state'], 'iss' => self::SVC])
            ->assertForbidden()
            ->assertJsonPath('rejected', 'server_mismatch');

        $this->assertNoTokenRequest();
    }

    public function test_an_error_response_is_reported_after_the_issuer_is_checked(): void
    {
        $this->fakeServers();

        $query = $this->startFlow('svc');
        $this->respond('svc', ['error' => 'access_denied', 'state' => $query['state'], 'iss' => self::SVC])
            ->assertForbidden()
            ->assertJsonPath('rejected', 'authorization_denied')
            ->assertJsonPath('provider_error', 'access_denied');

        $query = $this->startFlow('svc');
        $this->respond('svc', ['error' => 'access_denied', 'state' => $query['state'], 'iss' => self::PHR])
            ->assertForbidden()
            ->assertJsonPath('rejected', 'issuer_mismatch');

        // RFC 6749 error = 1*NQSCHAR: printable ASCII except '"' and '\\'. Bounded in length.
        foreach (['Vendor-Error.2' => 'Vendor-Error.2', 'bad"quote' => null, 'back\\slash' => null,
            "caf\u{e9}" => null, "tab\there" => null, str_repeat('a', 65) => null, str_repeat('a', 64) => str_repeat('a', 64)] as $error => $kept) {
            $query = $this->startFlow('svc');
            $this->respond('svc', ['error' => (string) $error, 'state' => $query['state'], 'iss' => self::SVC])
                ->assertForbidden()
                ->assertJsonPath('rejected', 'authorization_denied')
                ->assertJsonPath('provider_error', $kept);
        }

        $this->assertNoTokenRequest();
    }

    public function test_a_missing_code_is_rejected(): void
    {
        $this->fakeServers();
        $query = $this->startFlow('svc');

        $this->respond('svc', ['state' => $query['state'], 'iss' => self::SVC])
            ->assertForbidden()
            ->assertJsonPath('rejected', 'code_missing');

        $this->assertNoTokenRequest();
    }

    public function test_flows_to_several_servers_can_be_pending_at_once(): void
    {
        $this->fakeServers();
        $svc = $this->startFlow('svc');
        $phr = $this->startFlow('phr');

        $this->respond('phr', ['code' => 'phr-code', 'state' => $phr['state'], 'iss' => self::PHR])
            ->assertOk()->assertJsonPath('access_token', 'phr-access');
        $this->respond('svc', ['code' => 'svc-code', 'state' => $svc['state'], 'iss' => self::SVC])
            ->assertOk()->assertJsonPath('access_token', 'svc-access');
    }

    public function test_pending_flows_per_session_are_bounded(): void
    {
        for ($i = 0; $i < 20; $i++) {
            $this->startFlow('svc');
        }

        $this->assertLessThanOrEqual(10, count(session('oauth.flows')));
    }

    public function test_a_rejected_token_exchange_is_a_bad_gateway(): void
    {
        Http::fake([self::SVC.'/oauth/token' => Http::response(['error' => 'invalid_grant'], 400)]);
        $query = $this->startFlow('svc');

        $this->withoutExceptionHandling();
        try {
            $this->respond('svc', ['code' => 'c', 'state' => $query['state'], 'iss' => self::SVC]);
            $this->fail('The exchange was accepted.');
        } catch (HttpException $exception) {
            $this->assertSame(502, $exception->getStatusCode());
        }
    }

    public function test_a_token_response_without_an_access_token_is_refused(): void
    {
        Http::fake([self::SVC.'/oauth/token' => Http::response(['token_type' => 'Bearer'])]);
        $query = $this->startFlow('svc');

        $this->respond('svc', ['code' => 'c', 'state' => $query['state'], 'iss' => self::SVC])->assertStatus(502);
    }

    public function test_a_numeric_string_lifetime_is_read_as_seconds(): void
    {
        $this->freezeTime();
        Http::fake([self::SVC.'/oauth/token' => Http::response(['access_token' => 'a', 'expires_in' => '900'])]);

        $tokens = app(OAuthClient::class)->forServer('svc')->refreshTokens('r');

        $this->assertSame(900, $tokens->expiresAt?->getTimestamp() - now()->getTimestamp());
    }

    public function test_a_non_bearer_token_is_refused(): void
    {
        Http::fake([self::SVC.'/oauth/token' => Http::response(['access_token' => 'a', 'token_type' => 'mac'])]);
        $query = $this->startFlow('svc');

        $this->respond('svc', ['code' => 'c', 'state' => $query['state'], 'iss' => self::SVC])->assertStatus(502);
    }

    public function test_servers_sharing_a_callback_are_a_configuration_error(): void
    {
        config(['bherila-auth.oauth_client.servers.phr.redirect_uri' => 'https://pf.example.test/connections/svc/callback']);

        $this->get('/connections/svc/start')->assertStatus(503);
        $this->get('/connections/phr/start')->assertStatus(503);
    }

    public function test_a_server_sharing_the_sign_in_callback_is_a_configuration_error(): void
    {
        config(['bherila-auth.oauth_client.servers.svc.redirect_uri' => 'https://pf.example.test/oauth/callback']);

        $this->get('/connections/svc/start')->assertStatus(503);
    }

    public function test_an_unknown_server_is_not_configured(): void
    {
        $this->assertFalse(OAuthClient::isConfigured('nope'));
        $this->assertTrue(OAuthClient::isConfigured('svc'));
        $this->assertTrue(OAuthClient::isConfigured());

        $this->expectException(HttpException::class);
        app(OAuthClient::class)->forServer('nope')->redirect(Request::create('/'));
    }

    public function test_the_reserved_default_name_cannot_be_configured_as_a_server(): void
    {
        config(['bherila-auth.oauth_client.servers.default' => config('bherila-auth.oauth_client.servers.svc')]);

        $this->assertFalse(OAuthClient::isConfigured('default'));
    }

    public function test_a_server_without_an_issuer_is_not_configured(): void
    {
        config(['bherila-auth.oauth_client.servers.svc.issuer' => null]);

        $this->assertFalse(OAuthClient::isConfigured('svc'));
        $this->get('/connections/svc/start')->assertStatus(503);
    }

    public function test_an_issuer_with_a_query_or_fragment_is_not_configured(): void
    {
        foreach ([self::SVC.'?a=b', self::SVC.'#x', 'ftp://svc.example.test'] as $issuer) {
            config(['bherila-auth.oauth_client.servers.svc.issuer' => $issuer]);

            $this->get('/connections/svc/start')->assertStatus(503);
        }
    }

    public function test_server_metadata_is_exposed(): void
    {
        $svc = app(OAuthClient::class)->forServer('svc');

        $this->assertSame('svc', $svc->serverName());
        $this->assertSame('svc', $svc->providerName());
        $this->assertSame(self::SVC, $svc->issuer());
        $this->assertSame(self::SVC, $svc->providerBaseUrl());

        $default = app(OAuthClient::class);
        $this->assertSame('default', $default->serverName());
        $this->assertSame('https://identity.example.test', $default->issuer());
    }

    public function test_a_named_server_can_also_return_an_identity(): void
    {
        config(['bherila-auth.oauth_client.servers.svc.identity_path' => '/api/oauth/user']);
        Http::fake([
            self::SVC.'/oauth/token' => Http::response(['access_token' => 'svc-access', 'token_type' => 'Bearer']),
            self::SVC.'/api/oauth/user' => Http::response(['sub' => '42', 'name' => 'Person', 'email' => 'p@example.test']),
        ]);
        Route::middleware('web')->get('/connections/svc/identity', function (Request $request, OAuthClient $client) {
            $identity = $client->forServer('svc')->identityFromCallback($request);

            return response()->json(['provider' => $identity->provider, 'subject' => $identity->subject]);
        });
        config(['bherila-auth.oauth_client.servers.svc.redirect_uri' => 'https://pf.example.test/connections/svc/identity']);

        $query = $this->startFlow('svc');
        $this->get('/connections/svc/identity?'.http_build_query(['code' => 'c', 'state' => $query['state'], 'iss' => self::SVC]))
            ->assertOk()
            ->assertExactJson(['provider' => 'svc', 'subject' => '42']);
    }

    public function test_a_refresh_uses_the_configured_endpoint_client_and_resource(): void
    {
        Http::fake([self::SVC.'/oauth/token' => Http::response([
            'token_type' => 'Bearer', 'access_token' => 'next-access', 'refresh_token' => 'next-refresh', 'expires_in' => 900,
        ])]);

        $tokens = app(OAuthClient::class)->forServer('svc')->refreshTokens('old-refresh', ['finance:read']);

        $this->assertSame('next-access', $tokens->accessToken);
        $this->assertSame('next-refresh', $tokens->refreshToken);
        $this->assertSame('svc', $tokens->server);
        $this->assertSame(self::SVC, $tokens->issuer);
        $this->assertSame(self::SVC.'/api/v1', $tokens->resource);
        // The response omitted `scope`: the grant is unchanged, not the configured request.
        $this->assertSame(['finance:read'], $tokens->scopes);
        $this->assertNotNull($tokens->expiresAt);
        Http::assertSent(fn (ClientRequest $request): bool => $request->url() === self::SVC.'/oauth/token'
            && $request->data() === [
                'grant_type' => 'refresh_token',
                'client_id' => 'pf-at-svc',
                'client_secret' => 'svc-secret',
                'refresh_token' => 'old-refresh',
                'resource' => self::SVC.'/api/v1',
            ]);
    }

    public function test_a_refresh_omitting_scope_without_the_prior_grant_reports_none(): void
    {
        Http::fake([self::SVC.'/oauth/token' => Http::response(['access_token' => 'a', 'refresh_token' => 'r2'])]);

        $this->assertNull(app(OAuthClient::class)->forServer('svc')->refreshTokens('r')->scopes);
    }

    public function test_a_refresh_reports_the_scope_the_server_returns(): void
    {
        Http::fake([self::SVC.'/oauth/token' => Http::response(['access_token' => 'a', 'scope' => 'identity:read'])]);

        $this->assertSame(['identity:read'], app(OAuthClient::class)->forServer('svc')->refreshTokens('r', ['finance:read', 'identity:read'])->scopes);
    }

    public function test_a_code_exchange_omitting_scope_reports_the_requested_scope(): void
    {
        $this->fakeServers();
        $query = $this->startFlow('phr');

        $this->respond('phr', ['code' => 'c', 'state' => $query['state'], 'iss' => self::PHR])
            ->assertOk()
            ->assertJsonPath('scopes', ['billing:read', 'identity:read']);
    }

    public function test_malformed_prior_scopes_are_refused(): void
    {
        Http::fake();

        foreach ([['a b'], [''], [1], ['k' => 'finance:read']] as $scopes) {
            try {
                app(OAuthClient::class)->forServer('svc')->refreshTokens('r', $scopes);
                $this->fail('Malformed scopes were accepted.');
            } catch (\InvalidArgumentException) {
            }
        }

        Http::assertNothingSent();
    }

    public function test_a_malformed_successful_refresh_is_ambiguous(): void
    {
        foreach ([
            Http::response(['token_type' => 'Bearer']),
            Http::response(['access_token' => 'a', 'token_type' => 'mac']),
            Http::response(['access_token' => 'a', 'refresh_token' => 7]),
            Http::response('not json'),
        ] as $answer) {
            Http::fake([self::SVC.'/oauth/token' => $answer]);

            try {
                app(OAuthClient::class)->forServer('svc')->refreshTokens('old-refresh');
                $this->fail('The refresh was accepted.');
            } catch (OAuthTokenRequestFailed $failed) {
                $this->assertFalse($failed->definitive);
                $this->assertNull($failed->oauthError);
            }
        }
    }

    public function test_an_extension_error_code_is_kept(): void
    {
        Http::fake([self::SVC.'/oauth/token' => Http::response(['error' => 'Vendor-Specific.1'], 400)]);

        try {
            app(OAuthClient::class)->forServer('svc')->refreshTokens('r');
            $this->fail('The refresh was accepted.');
        } catch (OAuthTokenRequestFailed $failed) {
            $this->assertSame('Vendor-Specific.1', $failed->oauthError);
        }
    }

    public function test_credentials_are_kept_out_of_exception_traces(): void
    {
        $previous = ini_set('zend.exception_ignore_args', '0');

        try {
            Http::fake([self::SVC.'/oauth/token' => Http::response(['token_type' => 'Bearer'])]);
            try {
                app(OAuthClient::class)->forServer('svc')->refreshTokens('long-lived-refresh');
                $this->fail('The refresh was accepted.');
            } catch (OAuthTokenRequestFailed $failed) {
                $this->assertTraceArgumentsAvoid($failed, ['svc-secret', 'long-lived-refresh']);
            }

            $query = $this->startFlow('svc');
            $this->withoutExceptionHandling();
            try {
                $this->respond('svc', ['code' => 'one-time-code', 'state' => $query['state'], 'iss' => self::SVC]);
                $this->fail('The exchange was accepted.');
            } catch (OAuthTokenRequestFailed $failed) {
                $this->assertTraceArgumentsAvoid($failed, ['svc-secret', 'one-time-code', $this->verifierFrom($failed)]);
            }
        } finally {
            ini_set('zend.exception_ignore_args', (string) $previous);
        }
    }

    private function verifierFrom(OAuthTokenRequestFailed $failed): string
    {
        $verifier = null;
        Http::assertSent(function (ClientRequest $request) use (&$verifier): bool {
            $verifier = $request['code_verifier'] ?? $verifier;

            return true;
        });

        return (string) $verifier;
    }

    /** @param  list<string>  $secrets */
    private function assertTraceArgumentsAvoid(\Throwable $exception, array $secrets): void
    {
        $strings = [];
        $collect = function (mixed $value, int $depth) use (&$collect, &$strings): void {
            if (is_string($value)) {
                $strings[] = $value;
            } elseif (is_array($value) && $depth < 6) {
                foreach ($value as $item) {
                    $collect($item, $depth + 1);
                }
            }
        };
        $frames = 0;
        foreach ($exception->getTrace() as $frame) {
            // This test's own helpers are handed the values on purpose.
            if (array_key_exists('args', $frame) && ($frame['class'] ?? null) !== self::class) {
                $frames++;
                $collect($frame['args'], 0);
            }
        }

        $this->assertGreaterThan(0, $frames, 'Arguments were not recorded; the check proves nothing.');
        foreach ($secrets as $secret) {
            $this->assertNotContains($secret, $strings);
        }
    }

    public function test_a_numeric_server_name_is_its_own_server(): void
    {
        $servers = config('bherila-auth.oauth_client.servers');
        $servers['1'] = array_replace($servers['svc'], ['redirect_uri' => 'https://pf.example.test/connections/1/callback']);
        config(['bherila-auth.oauth_client.servers' => $servers]);
        Route::middleware('web')->get('/connections/1/start', fn (Request $request, OAuthClient $client) => $client->forServer('1')->redirect($request));

        $this->get('/connections/1/start')->assertRedirectContains(self::SVC.'/oauth/authorize?');
        $this->assertTrue(OAuthClient::isConfigured('1'));
    }

    public function test_a_refused_refresh_is_definitive(): void
    {
        Http::fake([self::SVC.'/oauth/token' => Http::response(['error' => 'invalid_grant'], 400)]);

        try {
            app(OAuthClient::class)->forServer('svc')->refreshTokens('old-refresh');
            $this->fail('The refresh was accepted.');
        } catch (OAuthTokenRequestFailed $failed) {
            $this->assertSame(502, $failed->getStatusCode());
            $this->assertSame('invalid_grant', $failed->oauthError);
            $this->assertTrue($failed->definitive);
        }
    }

    public function test_a_refresh_with_no_answer_is_ambiguous(): void
    {
        foreach ([
            fn () => Http::response('unavailable', 503),
            fn () => throw new ConnectionException('reset'),
        ] as $answer) {
            Http::fake([self::SVC.'/oauth/token' => $answer]);

            try {
                app(OAuthClient::class)->forServer('svc')->refreshTokens('old-refresh');
                $this->fail('The refresh was accepted.');
            } catch (OAuthTokenRequestFailed $failed) {
                $this->assertFalse($failed->definitive);
                $this->assertNull($failed->oauthError);
            }
        }
    }

    public function test_tokens_are_left_out_of_dumps(): void
    {
        Http::fake([self::SVC.'/oauth/token' => Http::response(['access_token' => 'secret-access', 'refresh_token' => 'secret-refresh'])]);

        $tokens = app(OAuthClient::class)->forServer('svc')->refreshTokens('old-refresh');

        $this->assertStringNotContainsString('secret-', print_r($tokens, true));
    }
}
