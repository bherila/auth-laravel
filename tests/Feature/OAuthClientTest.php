<?php

namespace BWH\Auth\Tests\Feature;

use BWH\Auth\OAuth\OAuthClient;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Route;
use BWH\Auth\Tests\TestCase;

class OAuthClientTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        config(['bherila-auth.oauth_client' => [
            'provider' => 'test-provider',
            'base_url' => 'https://identity.example.test',
            'client_id' => 'test-client',
            'client_secret' => 'test-secret',
            'redirect_uri' => 'https://app.example.test/oauth/callback',
            'scope' => 'identity:read',
            'authorize_path' => '/oauth/authorize',
            'token_path' => '/oauth/token',
            'identity_path' => '/api/oauth/user',
            'end_session_path' => '/oauth/end-session',
        ]]);

        Route::middleware('web')->group(function (): void {
            Route::get('/oauth/start-test', fn (Request $request, OAuthClient $client) => $client->redirect($request));
            Route::get('/oauth/callback-test', function (Request $request, OAuthClient $client) {
                $identity = $client->identityFromCallback($request);

                return response()->json([
                    'provider' => $identity->provider,
                    'subject' => $identity->subject,
                    'name' => $identity->name,
                    'email' => $identity->email,
                    'apps' => $identity->apps,
                ]);
            });
        });
    }

    public function test_redirect_creates_state_and_pkce_challenge(): void
    {
        $response = $this->get('/oauth/start-test');

        $response->assertRedirectContains('https://identity.example.test/oauth/authorize?');
        $response->assertSessionHas('oauth.login.state');
        $response->assertSessionHas('oauth.login.code_verifier');

        parse_str((string) parse_url((string) $response->headers->get('Location'), PHP_URL_QUERY), $query);
        $this->assertSame('S256', $query['code_challenge_method']);
        $this->assertSame('identity:read', $query['scope']);
        $this->assertSame(session('oauth.login.state'), $query['state']);
    }

    public function test_provider_metadata_is_exposed_from_the_validated_shared_config(): void
    {
        $client = app(OAuthClient::class);

        $this->assertSame('test-provider', $client->providerName());
        $this->assertSame('https://identity.example.test', $client->providerBaseUrl());
    }

    public function test_callback_exchanges_code_and_returns_validated_identity(): void
    {
        Http::fake([
            'https://identity.example.test/oauth/token' => Http::response(['access_token' => 'test-access-token']),
            'https://identity.example.test/api/oauth/user' => Http::response([
                'sub' => 'subject-123',
                'name' => ' Synthetic User ',
                'email' => 'SYNTHETIC@EXAMPLE.TEST',
            ]),
        ]);

        $response = $this->withSession([
            'oauth.login.state' => 'expected-state',
            'oauth.login.code_verifier' => 'expected-verifier',
        ])->get('/oauth/callback-test?state=expected-state&code=authorization-code');

        $response->assertOk()->assertExactJson([
            'provider' => 'test-provider',
            'subject' => 'subject-123',
            'name' => 'Synthetic User',
            'email' => 'synthetic@example.test',
            // A provider that sends no application list yields none, rather than failing.
            'apps' => [],
        ]);

        Http::assertSentCount(2);
        Http::assertSent(fn ($request): bool => $request->url() === 'https://identity.example.test/oauth/token'
            && $request['code_verifier'] === 'expected-verifier');
    }

    public function test_callback_rejects_invalid_state_before_network_requests(): void
    {
        Http::fake();

        $this->withSession([
            'oauth.login.state' => 'expected-state',
            'oauth.login.code_verifier' => 'expected-verifier',
        ])->get('/oauth/callback-test?state=wrong-state&code=authorization-code')->assertForbidden();

        Http::assertNothingSent();
    }
    /**
     * @return array<string, mixed>
     */
    private function identityPayload(mixed $apps): array
    {
        return array_filter([
            'sub' => '42',
            'name' => 'Account Holder',
            'email' => 'person@example.test',
            'apps' => $apps,
        ], static fn (mixed $value): bool => $value !== null);
    }

    private function completeCallback(mixed $apps): \Illuminate\Testing\TestResponse
    {
        Http::fake([
            'identity.example.test/oauth/token' => Http::response(['access_token' => 'token']),
            'identity.example.test/api/oauth/user' => Http::response($this->identityPayload($apps)),
        ]);

        $start = $this->get('/oauth/start-test');
        parse_str((string) parse_url((string) $start->headers->get('Location'), PHP_URL_QUERY), $query);

        return $this->get('/oauth/callback-test?'.http_build_query(['code' => 'code', 'state' => $query['state']]));
    }

    public function test_the_application_list_is_carried_through(): void
    {
        $this->completeCallback([['key' => 'finance', 'name' => 'Finance', 'url' => 'https://pf.example.test']])
            ->assertOk()
            ->assertJsonPath('apps.0.key', 'finance')
            ->assertJsonPath('apps.0.url', 'https://pf.example.test');
    }

    public function test_a_provider_that_sends_no_list_yields_none(): void
    {
        $this->completeCallback(null)->assertOk()->assertJsonPath('apps', []);
    }

    /**
     * The list is chrome. A malformed entry must not stop somebody signing in, which is what
     * aborting here would do — this runs inside the callback.
     */
    public function test_malformed_entries_are_dropped_rather_than_failing_sign_in(): void
    {
        $this->completeCallback([
            ['key' => 'ok', 'name' => 'Fine', 'url' => 'https://fine.example.test'],
            ['key' => 'no-url', 'name' => 'Nope'],
            ['key' => '', 'name' => 'Empty key', 'url' => 'https://x.example.test'],
            ['key' => 'blank-name', 'name' => '   ', 'url' => 'https://x.example.test'],
            ['key' => 'not-a-url', 'name' => 'Bad', 'url' => 'not a url'],
            'not even an array',
        ])
            ->assertOk()
            ->assertJsonCount(1, 'apps')
            ->assertJsonPath('apps.0.key', 'ok');
    }

    /**
     * `javascript:` and `data:` pass FILTER_VALIDATE_URL. These become href values, so the
     * scheme is checked rather than assumed.
     */
    public function test_non_http_schemes_are_dropped(): void
    {
        $this->completeCallback([
            ['key' => 'js', 'name' => 'Script', 'url' => 'javascript:alert(1)'],
            ['key' => 'data', 'name' => 'Data', 'url' => 'data:text/html,<script>alert(1)</script>'],
        ])->assertOk()->assertJsonPath('apps', []);
    }

    public function test_the_end_session_url_names_the_client_and_the_return_address(): void
    {
        $url = app(OAuthClient::class)->endSessionUrl('https://app.example.test/');

        $this->assertStringStartsWith('https://identity.example.test/oauth/end-session?', $url);
        parse_str((string) parse_url($url, PHP_URL_QUERY), $query);
        $this->assertSame('test-client', $query['client_id']);
        $this->assertSame('https://app.example.test/', $query['post_logout_redirect_uri']);
    }

    public function test_the_single_provider_redirect_is_unchanged(): void
    {
        $response = $this->get('/oauth/start-test');

        parse_str((string) parse_url((string) $response->headers->get('Location'), PHP_URL_QUERY), $query);
        $this->assertSame(
            ['client_id', 'redirect_uri', 'response_type', 'scope', 'state', 'code_challenge', 'code_challenge_method'],
            array_keys($query),
        );
        $this->assertSame('https://app.example.test/oauth/callback', $query['redirect_uri']);
        $this->assertSame(session('oauth.login.state'), $query['state']);
        $this->assertNull(session('oauth.flows'));
    }

    public function test_an_issuer_naming_the_provider_is_accepted(): void
    {
        $this->fakeProvider();
        $query = $this->start();

        $this->get('/oauth/callback-test?'.http_build_query([
            'code' => 'code', 'state' => $query['state'], 'iss' => 'https://identity.example.test',
        ]))->assertOk()->assertJsonPath('subject', '42');
    }

    public function test_an_issuer_naming_another_server_is_rejected_before_network_requests(): void
    {
        $this->fakeProvider();
        $query = $this->start();

        $this->get('/oauth/callback-test?'.http_build_query([
            'code' => 'code', 'state' => $query['state'], 'iss' => 'https://attacker.example.test',
        ]))->assertForbidden();

        Http::assertNothingSent();
    }

    public function test_a_configured_issuer_replaces_the_base_url_for_the_check(): void
    {
        config(['bherila-auth.oauth_client.issuer' => 'https://id.example.test']);
        $this->fakeProvider();

        $query = $this->start();
        $this->get('/oauth/callback-test?'.http_build_query([
            'code' => 'code', 'state' => $query['state'], 'iss' => 'https://identity.example.test',
        ]))->assertForbidden();

        $query = $this->start();
        $this->get('/oauth/callback-test?'.http_build_query([
            'code' => 'code', 'state' => $query['state'], 'iss' => 'https://id.example.test',
        ]))->assertOk();
    }

    public function test_a_missing_issuer_is_rejected_when_the_provider_is_configured_to_send_it(): void
    {
        config(['bherila-auth.oauth_client.authorization_response_iss' => 'required']);
        $this->fakeProvider();

        // Also for a session seeded with only the legacy keys.
        $this->withSession([
            'oauth.login.state' => 'expected-state',
            'oauth.login.code_verifier' => 'expected-verifier',
        ])->get('/oauth/callback-test?state=expected-state&code=authorization-code')->assertForbidden();

        $query = $this->start();
        $this->get('/oauth/callback-test?'.http_build_query(['code' => 'code', 'state' => $query['state']]))
            ->assertForbidden();

        Http::assertNothingSent();
    }

    public function test_a_replayed_state_is_rejected(): void
    {
        $this->fakeProvider();
        $query = $this->start();
        $callback = '/oauth/callback-test?'.http_build_query(['code' => 'code', 'state' => $query['state']]);

        $this->get($callback)->assertOk();
        $this->get($callback)->assertForbidden();

        Http::assertSentCount(2);
    }

    public function test_a_sign_in_started_as_a_guest_is_not_completed_as_someone_else(): void
    {
        $this->fakeProvider();
        $query = $this->start();

        $this->actingAs(new \Illuminate\Auth\GenericUser(['id' => 9]));
        $this->get('/oauth/callback-test?'.http_build_query(['code' => 'code', 'state' => $query['state']]))
            ->assertForbidden();

        Http::assertNothingSent();
    }

    public function test_a_sign_in_started_in_another_session_is_rejected(): void
    {
        $this->fakeProvider();
        $query = $this->start();
        $this->flushSession();

        $this->get('/oauth/callback-test?'.http_build_query(['code' => 'code', 'state' => $query['state']]))
            ->assertForbidden();

        Http::assertNothingSent();
    }

    private function fakeProvider(): void
    {
        Http::fake([
            'identity.example.test/oauth/token' => Http::response(['access_token' => 'token']),
            'identity.example.test/api/oauth/user' => Http::response($this->identityPayload(null)),
        ]);
    }

    /** @return array<string, string> */
    private function start(): array
    {
        $start = $this->get('/oauth/start-test');
        parse_str((string) parse_url((string) $start->headers->get('Location'), PHP_URL_QUERY), $query);

        return $query;
    }
}
