<?php

namespace BWH\Auth\Tests\Feature;

use BWH\Auth\OAuth\OAuthCallbackFailure;
use BWH\Auth\OAuth\OAuthCallbackRejected;
use BWH\Auth\OAuth\OAuthClient;
use BWH\Auth\Tests\TestCase;
use Illuminate\Auth\GenericUser;
use Illuminate\Cache\ArrayStore;
use Illuminate\Http\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Symfony\Component\HttpKernel\Exception\HttpException;

class OAuthNamedPendingFlowCacheTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        config([
            'cache.default' => 'array',
            'cache.stores.pending' => ['driver' => 'array', 'serialize' => true],
            'bherila-auth.oauth_client.pending_flow_ttl' => 60,
            'bherila-auth.oauth_client.pending_flow_cache_store' => 'pending',
            'bherila-auth.oauth_client.servers.records' => [
                'issuer' => 'https://authorization.example.test',
                'client_id' => 'synthetic-client',
                'client_secret' => 'synthetic-secret',
                'redirect_uri' => 'https://client.example.test/connect/records/callback',
                'scope' => 'records:read',
                'resource' => 'urn:example:records',
                'authorization_response_iss' => 'required',
            ],
        ]);
        Http::fake(['https://authorization.example.test/oauth/token' => Http::response(['token_type' => 'Bearer', 'access_token' => 'synthetic-access'])]);
    }

    public function test_a_stale_session_save_does_not_erase_a_named_servers_pending_flow(): void
    {
        $session = $this->newSession();
        $snapshot = $session->all();
        $query = $this->start($session);

        // A request that loaded the session before redirect saves its older attributes later.
        $session->flush();
        $session->put($snapshot);
        $tokens = app(OAuthClient::class)->forServer('records')->tokensFromCallback($this->callbackRequest($session, $query['state']));

        $this->assertSame('synthetic-access', $tokens->accessToken);
        $this->assertSame(['records:read'], $tokens->scopes);
        Http::assertSent(fn ($request): bool => rtrim(strtr(base64_encode(hash('sha256', $request['code_verifier'], true)), '+/', '-_'), '=') === $query['code_challenge']);
    }

    public function test_restoring_a_session_snapshot_cannot_replay_a_consumed_flow(): void
    {
        $session = $this->newSession();
        $query = $this->start($session);
        $snapshot = $session->all();
        $client = app(OAuthClient::class)->forServer('records');
        $client->tokensFromCallback($this->callbackRequest($session, $query['state']));
        $session->flush();
        $session->put($snapshot);
        try {
            $client->tokensFromCallback($this->callbackRequest($session, $query['state']));
            $this->fail('A consumed flow was replayed.');
        } catch (OAuthCallbackRejected $rejected) {
            $this->assertSame(OAuthCallbackFailure::StateMismatch, $rejected->reason);
        }
        Http::assertSentCount(1);
    }

    public function test_an_expired_cached_flow_is_refused_before_token_exchange(): void
    {
        $session = $this->newSession();
        $query = $this->start($session);
        $this->travel(61)->seconds();
        try {
            app(OAuthClient::class)->forServer('records')->tokensFromCallback($this->callbackRequest($session, $query['state']));
            $this->fail('An expired flow was accepted.');
        } catch (OAuthCallbackRejected $rejected) {
            $this->assertContains($rejected->reason, [OAuthCallbackFailure::Expired, OAuthCallbackFailure::StateMismatch]);
        }
        Http::assertNothingSent();
    }

    public function test_a_different_user_is_refused_and_consumes_the_flow(): void
    {
        $session = $this->newSession();
        $query = $this->start($session);
        try {
            app(OAuthClient::class)->forServer('records')->tokensFromCallback($this->callbackRequest($session, $query['state'], 8));
            $this->fail('A different user completed the flow.');
        } catch (OAuthCallbackRejected $rejected) {
            $this->assertSame(OAuthCallbackFailure::UserMismatch, $rejected->reason);
        }
        try {
            app(OAuthClient::class)->forServer('records')->tokensFromCallback($this->callbackRequest($session, $query['state']));
            $this->fail('A refused flow was reused.');
        } catch (OAuthCallbackRejected $rejected) {
            $this->assertSame(OAuthCallbackFailure::StateMismatch, $rejected->reason);
        }
        Http::assertNothingSent();
    }

    public function test_the_cache_override_stores_only_the_existing_binding_and_verifier_under_a_hashed_state(): void
    {
        $session = $this->newSession();
        $snapshot = $session->all();
        $query = $this->start($session);
        $key = 'bherila-auth:oauth-client:pending-flow:'.hash('sha256', $query['state']);
        $binding = Cache::store('pending')->get($key);
        $this->assertIsArray($binding);
        $this->assertSame(['server', 'issuer', 'callback', 'resource', 'issuer_required', 'user', 'started_at', 'scope', 'verifier'], array_keys($binding));
        $this->assertSame('records', $binding['server']);
        $this->assertSame('7', $binding['user']);
        $this->assertNull(Cache::store('array')->get($key));
        $this->assertSame($snapshot, $session->all());
    }

    public function test_overlapping_callbacks_cannot_both_consume_the_same_cached_flow(): void
    {
        $store = new class extends ArrayStore
        {
            public ?\Closure $afterRead = null;

            public function get($key): mixed
            {
                $value = parent::get($key);
                if ($this->afterRead !== null) {
                    $callback = $this->afterRead;
                    $this->afterRead = null;
                    $callback();
                }

                return $value;
            }
        };
        Cache::extend('interleaving', fn () => Cache::repository($store));
        config([
            'cache.stores.interleaving' => ['driver' => 'interleaving'],
            'bherila-auth.oauth_client.pending_flow_cache_store' => 'interleaving',
        ]);
        $session = $this->newSession();
        $query = $this->start($session);
        $client = app(OAuthClient::class)->forServer('records');
        $competingRefusal = null;
        $store->afterRead = function () use ($client, $session, $query, &$competingRefusal): void {
            // Run a competing callback after the first cache read, before its delete.
            try {
                $client->tokensFromCallback($this->callbackRequest($session, $query['state']));
            } catch (OAuthCallbackRejected $rejected) {
                $competingRefusal = $rejected->reason;
            }
        };
        $tokens = $client->tokensFromCallback($this->callbackRequest($session, $query['state']));

        $this->assertSame('synthetic-access', $tokens->accessToken);
        $this->assertSame(OAuthCallbackFailure::StateMismatch, $competingRefusal);
        Http::assertSentCount(1);
    }

    public function test_null_cache_override_uses_the_configured_default_store(): void
    {
        config(['bherila-auth.oauth_client.pending_flow_cache_store' => null]);
        $session = $this->newSession();
        $query = $this->start($session);
        $key = 'bherila-auth:oauth-client:pending-flow:'.hash('sha256', $query['state']);

        $this->assertIsArray(Cache::store('array')->get($key));
        $this->assertNull(Cache::store('pending')->get($key));
        $this->assertSame('synthetic-access', app(OAuthClient::class)->forServer('records')->tokensFromCallback($this->callbackRequest($session, $query['state']))->accessToken);
    }

    public function test_default_sign_in_keeps_its_legacy_session_state_and_verifier(): void
    {
        config([
            'bherila-auth.oauth_client.base_url' => 'https://identity.example.test',
            'bherila-auth.oauth_client.client_id' => 'synthetic-sign-in-client',
            'bherila-auth.oauth_client.client_secret' => 'synthetic-sign-in-secret',
            'bherila-auth.oauth_client.redirect_uri' => 'https://client.example.test/oauth/callback',
        ]);
        $session = $this->newSession();
        $request = Request::create('https://client.example.test/oauth/start');
        $request->setLaravelSession($session);
        $request->setUserResolver(fn (): ?GenericUser => null);
        $response = app(OAuthClient::class)->redirect($request);
        parse_str((string) parse_url($response->getTargetUrl(), PHP_URL_QUERY), $query);

        $this->assertSame($query['state'], $session->get('oauth.login.state'));
        $this->assertIsString($session->get('oauth.login.code_verifier'));
        $this->assertIsArray($session->get('oauth.login.binding'));
        $key = 'bherila-auth:oauth-client:pending-flow:'.hash('sha256', $query['state']);
        $this->assertNull(Cache::store('pending')->get($key));
        $this->assertNull(Cache::store('array')->get($key));
        Http::fake(['https://identity.example.test/oauth/token' => Http::response(['token_type' => 'Bearer', 'access_token' => 'synthetic-sign-in-access'])]);
        $callback = Request::create('https://client.example.test/oauth/callback', 'GET', ['state' => $query['state'], 'code' => 'synthetic-code']);
        $callback->setLaravelSession($session);
        $callback->setUserResolver(fn (): ?GenericUser => null);
        $tokens = app(OAuthClient::class)->tokensFromCallback($callback);
        $this->assertSame('synthetic-sign-in-access', $tokens->accessToken);
        $this->assertNull($session->get('oauth.login.state'));
        $this->assertNull($session->get('oauth.login.code_verifier'));
        Http::assertSentCount(1);
    }

    public function test_an_anonymous_user_cannot_start_a_named_connect_flow(): void
    {
        try {
            $this->start($this->newSession(), null);
            $this->fail('A named connect flow requires a signed-in user.');
        } catch (HttpException $rejected) {
            $this->assertSame(403, $rejected->getStatusCode());
        }
        Http::assertNothingSent();
    }

    public function test_an_empty_authenticated_user_key_cannot_start_a_named_flow(): void
    {
        $request = Request::create('https://client.example.test/connect/records');
        $request->setLaravelSession($this->newSession());
        $request->setUserResolver(fn (): GenericUser => new GenericUser(['id' => '']));
        try {
            app(OAuthClient::class)->forServer('records')->redirect($request);
            $this->fail('A named connect flow requires a nonempty user key.');
        } catch (HttpException $rejected) {
            $this->assertSame(403, $rejected->getStatusCode());
        }
        Http::assertNothingSent();
    }

    public function test_a_known_anonymous_cached_flow_is_refused_before_token_exchange(): void
    {
        $session = $this->newSession();
        $query = $this->start($session);
        $key = 'bherila-auth:oauth-client:pending-flow:'.hash('sha256', $query['state']);
        $binding = Cache::store('pending')->get($key);
        $this->assertIsArray($binding);
        $binding['user'] = null;
        Cache::store('pending')->put($key, $binding, 60);

        try {
            app(OAuthClient::class)->forServer('records')->tokensFromCallback($this->callbackRequest($session, $query['state'], null));
            $this->fail('An anonymous cached binding cannot authorize a connect flow.');
        } catch (OAuthCallbackRejected $rejected) {
            $this->assertSame(OAuthCallbackFailure::UserMismatch, $rejected->reason);
        }
        $this->assertNull(Cache::store('pending')->get($key));
        Http::assertNothingSent();
    }

    public function test_stringable_authentication_identifiers_bind_and_complete_the_named_flow(): void
    {
        $identifier = new class implements \Stringable
        {
            public function __toString(): string
            {
                return 'synthetic-user-7';
            }
        };
        $session = $this->newSession();
        $query = $this->start($session, $identifier);
        $key = 'bherila-auth:oauth-client:pending-flow:'.hash('sha256', $query['state']);
        $this->assertSame('synthetic-user-7', Cache::store('pending')->get($key)['user']);
        $tokens = app(OAuthClient::class)->forServer('records')->tokensFromCallback($this->callbackRequest($session, $query['state'], clone $identifier));

        $this->assertSame('synthetic-access', $tokens->accessToken);
        Http::assertSentCount(1);
    }

    private function newSession(): Store
    {
        $session = new Store('synthetic-session', new ArraySessionHandler(120));
        $session->start();
        $session->put('unrelated', 'synthetic-value');

        return $session;
    }

    /** @return array<string, string> */
    private function start(Store $session, int|string|\Stringable|null $user = 7): array
    {
        $request = Request::create('https://client.example.test/connect/records');
        $request->setLaravelSession($session);
        $request->setUserResolver(fn (): ?GenericUser => $user === null ? null : new GenericUser(['id' => $user]));
        $response = app(OAuthClient::class)->forServer('records')->redirect($request);
        parse_str((string) parse_url($response->getTargetUrl(), PHP_URL_QUERY), $query);

        return $query;
    }

    private function callbackRequest(Store $session, string $state, int|string|\Stringable|null $user = 7): Request
    {
        $request = Request::create('https://client.example.test/connect/records/callback', 'GET', ['state' => $state, 'code' => 'synthetic-code', 'iss' => 'https://authorization.example.test']);
        $request->setLaravelSession($session);
        $request->setUserResolver(fn (): ?GenericUser => $user === null ? null : new GenericUser(['id' => $user]));

        return $request;
    }
}
