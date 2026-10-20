<?php

namespace BWH\Auth\Tests\Feature;

use BWH\Auth\OAuth\Client\OAuthHttpTransport;
use BWH\Auth\OAuth\Client\PendingFlow;
use BWH\Auth\OAuth\OAuthCallbackFailure;
use BWH\Auth\OAuth\OAuthCallbackRejected;
use BWH\Auth\OAuth\OAuthClient;
use BWH\Auth\OAuth\OAuthTokenRequestFailed;
use BWH\Auth\Tests\TestCase;
use Illuminate\Auth\GenericUser;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Client\PendingRequest;
use Illuminate\Http\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use PHPUnit\Framework\Attributes\DataProvider;
use Symfony\Component\HttpKernel\Exception\HttpException;

class OAuthExplicitServerTest extends TestCase
{
    private ?string $metadataIssuer = null;
    protected function setUp(): void
    {
        parent::setUp();
        config(['cache.default' => 'array', 'bherila-auth.oauth_client' => [
            'provider' => 'identity',
            'base_url' => 'https://identity.example.test',
            'client_id' => 'default-client',
            'client_secret' => 'default-secret',
            'redirect_uri' => 'https://client.example.test/oauth/callback',
            'scope' => 'identity:read',
            'authorize_path' => '/oauth/authorize',
            'token_path' => '/oauth/token',
            'identity_path' => '/identity',
            'servers' => ['records' => $this->settings('configured')],
        ]]);
        Cache::flush();
        Http::preventStrayRequests();
        Http::fake(function ($request) {
            if (str_contains($request->url(), '/.well-known/')) {
                return Http::response([
                    'issuer' => $this->metadataIssuer ?? 'https://'.parse_url($request->url(), PHP_URL_HOST),
                    'authorization_response_iss_parameter_supported' => true,
                    // Discovery never silently replaces the application's endpoint settings.
                    'token_endpoint' => 'https://unused.example.test/token',
                ]);
            }
            if (str_ends_with($request->url(), '/identity')) {
                return Http::response(['sub' => 'synthetic-subject', 'name' => 'Synthetic Person', 'email' => 'person@example.test']);
            }

            return Http::response(['token_type' => 'Bearer', 'access_token' => 'synthetic-access', 'refresh_token' => 'synthetic-refresh']);
        });
    }

    public function test_metadata_exchange_identity_and_refresh_use_the_supplied_transport(): void
    {
        $transport = $this->transport();
        $settings = $this->settings('first');
        $settings['authorization_response_iss'] = 'advertised';
        $client = app(OAuthClient::class)->forServerSettings('records', $settings, $transport);
        $session = $this->newSession();
        $query = $this->start($client, $session);
        $identity = $client->identityFromCallback($this->callbackRequest($session, $query, $settings));
        $tokens = $client->refreshTokens('synthetic-refresh', ['records:read']);

        $this->assertSame('records', $identity->provider);
        $this->assertSame('synthetic-subject', $identity->subject);
        $this->assertSame(['records:read'], $tokens->scopes);
        $this->assertSame([
            $settings['issuer'].'/.well-known/oauth-authorization-server',
            $settings['issuer'].'/oauth/token',
            $settings['issuer'].'/identity',
            $settings['issuer'].'/oauth/token',
        ], $transport->urls);
        Http::assertSentCount(4);
        Http::assertSent(function ($request) use ($query, $settings): bool {
            return ($request['grant_type'] ?? null) === 'authorization_code'
                && $request['client_id'] === $settings['client_id']
                && $request['client_secret'] === $settings['client_secret']
                && $request['resource'] === $settings['resource']
                && rtrim(strtr(base64_encode(hash('sha256', $request['code_verifier'], true)), '+/', '-_'), '=') === $query['code_challenge'];
        });
        foreach (Http::recorded() as [$request]) {
            $this->assertTrue($request->hasHeader('X-Synthetic-Transport', 'selected'));
        }
    }

    public function test_explicit_instances_snapshot_settings_without_mutating_global_configuration(): void
    {
        $config = config('bherila-auth.oauth_client');
        $firstSettings = $this->settings('first');
        $secondSettings = $this->settings('second');
        $firstTransport = $this->transport();
        $secondTransport = $this->transport();
        $first = app(OAuthClient::class)->forServerSettings('records', $firstSettings, $firstTransport);
        $second = app(OAuthClient::class)->forServerSettings('records', $secondSettings, $secondTransport);
        $firstSettings['issuer'] = 'https://changed.example.test';
        $firstSettings['client_secret'] = 'changed-secret';
        $firstSession = $this->newSession();
        $secondSession = $this->newSession();
        $firstQuery = $this->start($first, $firstSession, 7);
        $secondQuery = $this->start($second, $secondSession, 8);
        $firstTokens = $first->tokensFromCallback($this->callbackRequest($firstSession, $firstQuery, $this->settings('first'), 7));
        $secondTokens = $second->tokensFromCallback($this->callbackRequest($secondSession, $secondQuery, $secondSettings, 8));

        $this->assertSame($config, config('bherila-auth.oauth_client'));
        $this->assertSame('https://first.example.test', $firstTokens->issuer);
        $this->assertSame('https://second.example.test', $secondTokens->issuer);
        $this->assertSame(['https://first.example.test/oauth/token'], $firstTransport->urls);
        $this->assertSame(['https://second.example.test/oauth/token'], $secondTransport->urls);
        Http::assertSent(fn ($request): bool => $request->url() === 'https://first.example.test/oauth/token' && $request['client_secret'] === 'first-secret');
        Http::assertSent(fn ($request): bool => $request->url() === 'https://second.example.test/oauth/token' && $request['client_secret'] === 'second-secret');
    }

    #[DataProvider('bindingChanges')]
    public function test_explicit_instances_retain_pending_flow_and_issuer_bindings(string $change, OAuthCallbackFailure $failure): void
    {
        $settings = $this->settings('first');
        $client = app(OAuthClient::class)->forServerSettings('records', $settings, $this->transport());
        $session = $this->newSession();
        $query = $this->start($client, $session);
        $callback = $this->callbackRequest($session, $query, $settings, $change === 'user' ? 8 : 7);
        if ($change === 'issuer-response') {
            $callback->server->set('QUERY_STRING', http_build_query([...$callback->query->all(), 'iss' => 'https://second.example.test']));
        } elseif ($change === 'missing-issuer') {
            $parameters = $callback->query->all();
            unset($parameters['iss']);
            $callback->server->set('QUERY_STRING', http_build_query($parameters));
        } elseif ($change !== 'user') {
            $settings[$change] = $change === 'issuer' ? 'https://second.example.test' : ($change === 'resource' ? 'urn:example:other' : 'https://client.example.test/other/callback');
            $client = app(OAuthClient::class)->forServerSettings('records', $settings, $this->transport());
        }
        try {
            $client->tokensFromCallback($callback);
            $this->fail('A mismatched named flow was accepted.');
        } catch (OAuthCallbackRejected $rejected) {
            $this->assertSame($failure, $rejected->reason);
        }
        Http::assertNothingSent();
    }

    public static function bindingChanges(): array
    {
        return [
            ['user', OAuthCallbackFailure::UserMismatch],
            ['issuer', OAuthCallbackFailure::ServerMismatch],
            ['resource', OAuthCallbackFailure::ServerMismatch],
            ['redirect_uri', OAuthCallbackFailure::ServerMismatch],
            ['issuer-response', OAuthCallbackFailure::IssuerMismatch],
            ['missing-issuer', OAuthCallbackFailure::IssuerMissing],
        ];
    }

    public function test_transport_refusal_never_falls_back_to_an_unrestricted_request(): void
    {
        $transport = new class implements OAuthHttpTransport
        {
            public function prepare(PendingRequest $request, string $url): PendingRequest
            {
                throw new ConnectionException('Synthetic destination refused.');
            }
        };
        $client = app(OAuthClient::class)->forServerSettings('records', $this->settings('first'), $transport);
        try {
            $client->refreshTokens('synthetic-refresh');
            $this->fail('The refused transport fell back to another request.');
        } catch (OAuthTokenRequestFailed $failure) {
            $this->assertFalse($failure->definitive);
        }
        Http::assertNothingSent();
    }

    public function test_explicit_factory_is_optional_for_named_configured_and_default_clients(): void
    {
        foreach (['records', null] as $name) {
            $client = $name === null ? app(OAuthClient::class) : app(OAuthClient::class)->forServer($name);
            $session = $this->newSession();
            $query = $this->start($client, $session, $name === null ? null : 7);
            $settings = $name === null ? ['issuer' => 'https://identity.example.test', 'redirect_uri' => 'https://client.example.test/oauth/callback'] : $this->settings('configured');
            if ($name === null) {
                $this->assertSame($query['state'], $session->get(PendingFlow::LEGACY_STATE_KEY));
                $this->assertNotEmpty($session->get(PendingFlow::LEGACY_VERIFIER_KEY));
            }
            $tokens = $client->tokensFromCallback($this->callbackRequest($session, $query, $settings, $name === null ? null : 7));
            $this->assertSame($name ?? 'default', $tokens->server);
            $this->assertSame($settings['issuer'], $tokens->issuer);
            if ($name === null) {
                $this->assertFalse($session->has(PendingFlow::LEGACY_STATE_KEY));
            }
        }
        Http::assertSentCount(2);
        foreach (Http::recorded() as [$request]) {
            $this->assertFalse($request->hasHeader('X-Synthetic-Transport'));
        }
    }

    public function test_explicit_factory_without_transport_uses_the_existing_http_client(): void
    {
        $settings = $this->settings('first');
        $client = app(OAuthClient::class)->forServerSettings('records', $settings);
        $session = $this->newSession();
        $query = $this->start($client, $session);
        $this->assertSame('synthetic-access', $client->tokensFromCallback($this->callbackRequest($session, $query, $settings))->accessToken);
        Http::assertSentCount(1);
    }

    #[DataProvider('invalidNames')]
    public function test_explicit_settings_cannot_use_reserved_or_invalid_names(string $name): void
    {
        $this->expectException(HttpException::class);
        app(OAuthClient::class)->forServerSettings($name, $this->settings('first'));
    }

    public static function invalidNames(): array
    {
        return [['default'], [''], ['bad.name'], [str_repeat('a', 65)]];
    }

    public function test_explicit_settings_cannot_reuse_another_servers_callback(): void
    {
        $this->expectException(HttpException::class);
        app(OAuthClient::class)->forServerSettings('another', $this->settings('first'));
    }

    public function test_an_explicit_flow_cannot_be_replayed(): void
    {
        $settings = $this->settings('first');
        $client = app(OAuthClient::class)->forServerSettings('records', $settings);
        $session = $this->newSession();
        $query = $this->start($client, $session);
        $client->tokensFromCallback($this->callbackRequest($session, $query, $settings));
        try {
            $client->tokensFromCallback($this->callbackRequest($session, $query, $settings));
            $this->fail('An explicit flow was exchanged twice.');
        } catch (OAuthCallbackRejected $rejected) {
            $this->assertSame(OAuthCallbackFailure::StateMismatch, $rejected->reason);
        }
        Http::assertSentCount(1);
    }

    public function test_an_explicit_flow_still_expires(): void
    {
        config(['bherila-auth.oauth_client.pending_flow_ttl' => 60]);
        $settings = $this->settings('first');
        $client = app(OAuthClient::class)->forServerSettings('records', $settings);
        $session = $this->newSession();
        $query = $this->start($client, $session);
        $this->travel(61)->seconds();
        try {
            $client->tokensFromCallback($this->callbackRequest($session, $query, $settings));
            $this->fail('An expired explicit flow was exchanged.');
        } catch (OAuthCallbackRejected $rejected) {
            $this->assertContains($rejected->reason, [OAuthCallbackFailure::Expired, OAuthCallbackFailure::StateMismatch]);
        }
        Http::assertNothingSent();
    }

    public function test_metadata_with_another_issuer_is_refused_through_the_transport(): void
    {
        $this->metadataIssuer = 'https://different.example.test';
        $settings = $this->settings('first');
        $settings['authorization_response_iss'] = 'advertised';
        $transport = $this->transport();
        $client = app(OAuthClient::class)->forServerSettings('records', $settings, $transport);
        try {
            $this->start($client, $this->newSession());
            $this->fail('Metadata for another issuer was accepted.');
        } catch (HttpException $rejected) {
            $this->assertSame(503, $rejected->getStatusCode());
        }
        $this->assertSame([$settings['issuer'].'/.well-known/oauth-authorization-server'], $transport->urls);
        Http::assertSentCount(1);
    }

    public function test_transport_policy_is_applied_after_metadata_request_defaults(): void
    {
        $transport = new class implements OAuthHttpTransport
        {
            public array $options = [];

            public function prepare(PendingRequest $request, string $url): PendingRequest
            {
                return $request->timeout(1)->connectTimeout(1)->withoutRedirecting()
                    ->beforeSending(function ($request, array $options): void {
                        $this->options = $options;
                    });
            }
        };
        $settings = $this->settings('first');
        $settings['authorization_response_iss'] = 'advertised';
        $client = app(OAuthClient::class)->forServerSettings('records', $settings, $transport);
        $this->start($client, $this->newSession());
        $this->assertSame(1, $transport->options['timeout']);
        $this->assertSame(1, $transport->options['connect_timeout']);
        $this->assertFalse($transport->options['allow_redirects']);
    }

    public function test_client_diagnostics_do_not_dump_the_explicit_secret(): void
    {
        $client = app(OAuthClient::class)->forServerSettings('records', $this->settings('first'));
        $this->assertStringNotContainsString('first-secret', print_r($client, true));
    }

    private function settings(string $instance): array
    {
        return [
            'issuer' => 'https://'.$instance.'.example.test',
            'client_id' => $instance.'-client',
            'client_secret' => $instance.'-secret',
            'redirect_uri' => 'https://client.example.test/connect/records/callback',
            'scope' => 'records:read',
            'resource' => 'urn:example:'.$instance,
            'identity_path' => '/identity',
            'authorization_response_iss' => 'required',
        ];
    }

    private function transport(): OAuthHttpTransport
    {
        return new class implements OAuthHttpTransport
        {
            public array $urls = [];

            public function prepare(PendingRequest $request, string $url): PendingRequest
            {
                $this->urls[] = $url;

                return $request->withHeader('X-Synthetic-Transport', 'selected');
            }
        };
    }

    private function newSession(): Store
    {
        $session = new Store('synthetic-session', new ArraySessionHandler(120));
        $session->start();

        return $session;
    }

    private function start(OAuthClient $client, Store $session, ?int $user = 7): array
    {
        $response = $client->redirect($this->flowRequest('/start', $session, $user));
        parse_str((string) parse_url($response->getTargetUrl(), PHP_URL_QUERY), $query);

        return $query;
    }

    private function callbackRequest(Store $session, array $query, array $settings, ?int $user = 7): Request
    {
        return $this->flowRequest($settings['redirect_uri'].'?'.http_build_query(['state' => $query['state'], 'code' => 'synthetic-code', 'iss' => $settings['issuer']]), $session, $user);
    }

    private function flowRequest(string $url, Store $session, ?int $user): Request
    {
        $request = Request::create($url);
        $request->setLaravelSession($session);
        $request->setUserResolver(fn () => $user === null ? null : new GenericUser(['id' => $user]));

        return $request;
    }
}
