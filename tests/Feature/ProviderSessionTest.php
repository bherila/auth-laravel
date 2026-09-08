<?php

namespace BWH\Auth\Tests\Feature;

use BWH\Auth\OAuth\OAuthClient;
use BWH\Auth\OAuth\OAuthIdentity;
use BWH\Auth\OAuth\Session\ProviderIdentityStatusClient;
use BWH\Auth\OAuth\Session\ProviderSession;
use BWH\Auth\OAuth\Session\ProviderSessionExpired;
use BWH\Auth\OAuth\Session\ProviderStatusUnavailable;
use BWH\Auth\Tests\TestCase;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\Attributes\DataProvider;

class ProviderSessionTest extends TestCase
{
    private Request $request;

    protected function setUp(): void
    {
        parent::setUp();
        config(['app.env' => 'testing']);
        config(['bherila-auth.oauth_client' => [
            'provider' => 'example-provider',
            'base_url' => 'https://identity.example.test',
            'client_id' => 'example-client',
            'client_secret' => 'example-secret',
            'redirect_uri' => 'https://app.example.test/oauth/callback',
            'token_path' => '/oauth/token',
            'identity_path' => '/api/oauth/user',
        ]]);
        $this->request = Request::create('/private');
        $this->request->setLaravelSession(app('session.store'));
        $this->travelTo(Carbon::parse('2026-01-01T00:00:00Z'));
        Http::preventStrayRequests();
    }

    private function identity(): OAuthIdentity
    {
        return new OAuthIdentity('example-provider', 'subject-example', 'Example User',
            'user@example.test', credentialVersion: 7);
    }

    private function payload(): array
    {
        return ['contract_version' => 1, 'active' => true, 'subject' => 'subject-example', 'credential_version' => 7];
    }

    private function verify(bool $fresh = false): OAuthIdentity
    {
        return app(ProviderSession::class)->assertActive($this->request,
            'example-provider', 'subject-example', $fresh);
    }

    public function test_freshness_is_bounded_and_privileged_checks_bypass_it(): void
    {
        Http::fake(fn () => Http::response($this->payload()));
        app(ProviderSession::class)->remember($this->request, $this->identity());
        $this->assertSame('Example User', $this->verify()->name);
        $this->travel(299)->seconds();
        $this->verify();
        Http::assertNothingSent();
        $this->travel(1)->seconds();
        $this->assertSame('Example User', $this->verify()->name);
        $this->verify(true);
        Http::assertSentCount(2);
        Http::assertSent(fn ($request) => $request->method() === 'POST'
            && $request->url() === 'https://identity.example.test/api/reconciliation/identity-status'
            && $request['subject'] === 'subject-example'
            && $request->hasHeader('Authorization', 'Basic '.base64_encode('example-client:example-secret')));
    }

    #[DataProvider('endingStatuses')]
    public function test_inactivity_and_newer_generation_end_the_old_session(array $override): void
    {
        Http::fake(['*' => Http::response(array_replace($this->payload(), $override))]);
        app(ProviderSession::class)->remember($this->request, $this->identity());
        try {
            $this->verify(true);
            $this->fail('An old session must not adopt a new credential generation.');
        } catch (ProviderSessionExpired) {
            $this->assertFalse($this->request->session()->has('bherila_auth.provider_session'));
        }
    }

    public static function endingStatuses(): array
    {
        return [[['active' => false]], [['credential_version' => 8]], [['credential_version' => 6]]];
    }

    public function test_minimal_inactive_contract_does_not_require_identity_metadata(): void
    {
        Http::fake(['*' => Http::response(['contract_version' => 1, 'active' => false])]);
        $this->assertNull(app(ProviderIdentityStatusClient::class)->status('subject-example'));
    }

    public function test_contradictory_inactive_subject_is_unavailable_and_preserves_session(): void
    {
        Http::fake(['*' => Http::response(['contract_version' => 1, 'active' => false, 'subject' => 'other-subject'])]);
        app(ProviderSession::class)->remember($this->request, $this->identity());
        $baseline = $this->request->session()->get('bherila_auth.provider_session');
        try {
            $this->verify(true);
            $this->fail('Contradictory responses must not expire this session.');
        } catch (ProviderStatusUnavailable) {
            $this->assertSame($baseline, $this->request->session()->get('bherila_auth.provider_session'));
        }
    }

    public function test_outage_preserves_session_but_does_not_extend_its_freshness(): void
    {
        Http::fake(['*' => Http::sequence()->pushStatus(503)->push($this->payload())]);
        app(ProviderSession::class)->remember($this->request, $this->identity());
        $baseline = $this->request->session()->get('bherila_auth.provider_session');
        $this->travel(300)->seconds();
        try {
            $this->verify();
            $this->fail('Unavailable verification must not authorize protected work.');
        } catch (ProviderStatusUnavailable) {
            $this->assertSame($baseline, $this->request->session()->get('bherila_auth.provider_session'));
        }
        $this->assertSame(7, $this->verify()->credentialVersion);
        Http::assertSentCount(2);
    }

    public function test_status_never_refreshes_profile_data_because_the_client_credential_does_not_prove_the_person(): void
    {
        Http::fake(fn () => Http::response([...$this->payload(), 'name' => 'Attacker Chosen', 'email' => 'attacker@example.test']));
        app(ProviderSession::class)->remember($this->request, $this->identity());
        $identity = $this->verify(true);
        $this->assertSame('Example User', $identity->name);
        $this->assertSame('user@example.test', $identity->email);
        $this->assertSame(7, $identity->credentialVersion);
        $state = $this->request->session()->get('bherila_auth.provider_session');
        $this->assertSame(['Example User', 'user@example.test'], [$state['name'], $state['email']]);
        $status = app(ProviderIdentityStatusClient::class)->status('subject-example');
        $this->assertSame(['subject-example', 7], [$status->subject, $status->credentialVersion]);
        $this->assertFalse(property_exists($status, 'name') || property_exists($status, 'email'));
    }

    #[DataProvider('malformedStatuses')]
    public function test_bad_responses_never_authorize_or_become_inactive(array $override): void
    {
        Http::fake(['*' => Http::response(array_replace($this->payload(), $override))]);
        $this->expectException(ProviderStatusUnavailable::class);
        app(ProviderIdentityStatusClient::class)->status('subject-example');
    }

    public static function malformedStatuses(): array
    {
        return [
            [['contract_version' => '1']], [['active' => 'true']],
            [['subject' => 'other-subject']], [['credential_version' => '7']],
            [['credential_version' => 7.5]], [['credential_version' => -1]],
            [['credential_version' => null]],
        ];
    }

    #[DataProvider('changedContexts')]
    public function test_cached_checks_cannot_cross_provider_or_client_configuration(string $key, string $value): void
    {
        Http::fake();
        app(ProviderSession::class)->remember($this->request, $this->identity());
        config(['bherila-auth.oauth_client.'.$key => $value]);
        $this->expectException(ProviderSessionExpired::class);
        try {
            $this->verify();
        } finally {
            Http::assertNothingSent();
        }
    }

    public static function changedContexts(): array
    {
        return [['base_url', 'https://other.example.test'], ['client_id', 'other-client'], ['provider', 'other-provider']];
    }

    public function test_cached_checks_cannot_follow_a_different_local_binding(): void
    {
        app(ProviderSession::class)->remember($this->request, $this->identity());
        $this->expectException(ProviderSessionExpired::class);
        app(ProviderSession::class)->assertActive($this->request, 'example-provider', 'other-subject');
    }

    public function test_missing_baseline_requires_a_new_login_not_an_active_status_lookup(): void
    {
        Http::fake();
        $this->expectException(ProviderSessionExpired::class);
        try {
            $this->verify();
        } finally {
            Http::assertNothingSent();
        }
    }

    public function test_old_provider_identity_cannot_enable_generation_enforcement(): void
    {
        $this->expectException(ProviderStatusUnavailable::class);
        app(ProviderSession::class)->remember($this->request,
            new OAuthIdentity('example-provider', 'subject-example', 'Example User', 'user@example.test'));
    }

    public function test_clock_rollback_requires_a_fresh_check(): void
    {
        Http::fake(['*' => Http::response($this->payload())]);
        app(ProviderSession::class)->remember($this->request, $this->identity());
        $this->travel(-1)->seconds();
        $this->verify();
        Http::assertSentCount(1);
    }

    #[DataProvider('unsafeProviders')]
    public function test_unsafe_provider_urls_never_receive_client_credentials(string $url): void
    {
        Http::fake();
        config(['bherila-auth.oauth_client.base_url' => $url]);
        $this->expectException(ProviderStatusUnavailable::class);
        try {
            app(ProviderIdentityStatusClient::class)->status('subject-example');
        } finally {
            Http::assertNothingSent();
        }
    }

    public static function unsafeProviders(): array
    {
        return [['http://identity.example.test'], ['https://user:password@identity.example.test'],
            ['https://identity.example.test?target=other'], ['https://identity.example.test#fragment']];
    }

    public function test_redirect_is_unavailable(): void
    {
        Http::fake(['*' => Http::response('', 302, ['Location' => 'https://other.example.test'])]);
        $this->expectException(ProviderStatusUnavailable::class);
        app(ProviderIdentityStatusClient::class)->status('subject-example');
    }

    public function test_network_failure_does_not_expose_transport_details(): void
    {
        Http::fake(['*' => Http::failedConnection('example-secret')]);
        try {
            app(ProviderIdentityStatusClient::class)->status('subject-example');
            $this->fail('Network failures must remain unavailable.');
        } catch (ProviderStatusUnavailable $exception) {
            $this->assertStringNotContainsString('example-secret', $exception->getMessage());
            $this->assertNull($exception->getPrevious());
        }
    }

    public function test_response_limit_stops_reading_before_materializing_a_large_body(): void
    {
        $stream = new class(\GuzzleHttp\Psr7\Utils::streamFor(str_repeat('x', 100_000))) implements \Psr\Http\Message\StreamInterface {
            use \GuzzleHttp\Psr7\StreamDecoratorTrait;

            public int $bytesRead = 0;
            public bool $closed = false;

            public function read(int $length): string
            {
                $bytes = $this->stream->read($length);
                $this->bytesRead += strlen($bytes);
                return $bytes;
            }

            public function getContents(): string
            {
                throw new \LogicException('The entire body must not be materialized.');
            }

            public function close(): void
            {
                $this->closed = true;
                $this->stream->close();
            }
        };
        Http::fake(function ($request, $options) use ($stream) {
            $this->assertTrue($options['stream']);
            return Http::response($stream);
        });
        try {
            app(ProviderIdentityStatusClient::class)->status('subject-example');
            $this->fail('Oversized responses must fail closed.');
        } catch (ProviderStatusUnavailable) {
            $this->assertSame(16_385, $stream->bytesRead);
            $this->assertTrue($stream->closed);
        }
    }

    #[DataProvider('caseVariantProviders')]
    public function test_url_scheme_case_does_not_break_valid_provider_configuration(string $url): void
    {
        config(['bherila-auth.oauth_client.base_url' => $url]);
        Http::fake(['*' => Http::response($this->payload())]);
        $this->assertSame('subject-example', app(ProviderIdentityStatusClient::class)->status('subject-example')->subject);
    }

    public static function caseVariantProviders(): array
    {
        return [['HTTPS://identity.example.test'], ['HTTP://LOCALHOST']];
    }

    public function test_slow_body_cannot_extend_the_total_deadline(): void
    {
        $stream = new class(\GuzzleHttp\Psr7\Utils::streamFor(json_encode($this->payload()))) implements \Psr\Http\Message\StreamInterface {
            use \GuzzleHttp\Psr7\StreamDecoratorTrait;

            public bool $closed = false;

            public function read(int $length): string
            {
                // A valid payload arriving after the deadline must still be rejected.
                usleep(5_100_000);
                return $this->stream->read($length);
            }

            public function close(): void
            {
                $this->closed = true;
                $this->stream->close();
            }
        };
        Http::fake(function ($request, $options) use ($stream) {
            $this->assertSame(1, $options['read_timeout']);
            return Http::response($stream);
        });
        try {
            app(ProviderIdentityStatusClient::class)->status('subject-example');
            $this->fail('Late status must not authorize the request.');
        } catch (ProviderStatusUnavailable) {
            $this->assertTrue($stream->closed);
        }
    }

    #[DataProvider('callbackGenerations')]
    public function test_callback_preserves_only_a_valid_optional_generation(mixed $generation, int $status): void
    {
        Route::middleware('web')->get('/generation-callback', function (Request $request, OAuthClient $client) {
            return response()->json(['generation' => $client->identityFromCallback($request)->credentialVersion]);
        });
        Http::fake([
            'identity.example.test/oauth/token' => Http::response(['access_token' => 'example-token']),
            'identity.example.test/api/oauth/user' => Http::response([
                'sub' => 'subject-example', 'name' => 'Example User', 'email' => 'user@example.test',
                'credential_version' => $generation,
            ]),
        ]);
        $response = $this->withSession(['oauth.login.state' => 'state', 'oauth.login.code_verifier' => 'verifier'])
            ->get('/generation-callback?state=state&code=example-code')->assertStatus($status);
        if ($status === 200) {
            $response->assertJsonPath('generation', $generation);
        }
    }

    public static function callbackGenerations(): array
    {
        return [[7, 200], [0, 200], [null, 200], ['7', 502], [-1, 502], [7.5, 502]];
    }
}
