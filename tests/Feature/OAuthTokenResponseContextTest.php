<?php

namespace BWH\Auth\Tests\Feature;

use BWH\Auth\OAuth\OAuthClient;
use BWH\Auth\OAuth\OAuthTokenRequestFailed;
use BWH\Auth\OAuth\OAuthTokens;
use BWH\Auth\Tests\TestCase;
use Illuminate\Auth\GenericUser;
use Illuminate\Http\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;

class OAuthTokenResponseContextTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        config(['cache.default' => 'array', 'bherila-auth.oauth_client' => [
            'provider' => 'identity', 'base_url' => 'https://identity.example.test',
            'client_id' => 'default-client', 'client_secret' => 'synthetic-secret',
            'redirect_uri' => 'https://client.example.test/oauth/callback',
            'scope' => 'records:read', 'authorization_response_iss' => 'required',
            'authorize_path' => '/oauth/authorize', 'token_path' => '/oauth/token',
            'servers' => ['records' => $this->settings()],
        ]]);
        Cache::flush();
        Http::preventStrayRequests();
    }

    public function test_exchange_and_refresh_retain_only_the_immutable_opted_in_context(): void
    {
        $names = ['patient', 'encounter'];
        $client = app(OAuthClient::class)->forServerSettings('records', $this->settings(), null, $names);
        $names[] = 'unrequested';
        Http::fakeSequence()
            ->push($this->body(['patient' => 'synthetic-patient', 'encounter' => null, 'unrequested' => ['private' => 'ignored']]))
            ->push($this->body(['patient' => 'synthetic-refreshed-patient', 'unrequested' => 'ignored']));

        $tokens = $this->exchange($client);
        $this->assertSame(['patient' => 'synthetic-patient', 'encounter' => null], $tokens->context);
        $this->assertSame('synthetic-access', $tokens->accessToken);
        $this->assertSame(['records:read'], $tokens->scopes);
        $refreshed = $client->refreshTokens('synthetic-refresh', $tokens->scopes);
        $this->assertSame(['patient' => 'synthetic-refreshed-patient'], $refreshed->context);
        Http::assertSentCount(2);
        Http::assertSent(fn ($request): bool => $request['grant_type'] === 'authorization_code'
            && $request['code'] === 'synthetic-code' && is_string($request['code_verifier'])
            && $request['resource'] === 'urn:example:records');
        Http::assertSent(fn ($request): bool => $request['grant_type'] === 'refresh_token'
            && $request['refresh_token'] === 'synthetic-refresh');
    }

    public function test_context_omission_never_carries_forward_and_null_and_empty_are_distinct(): void
    {
        $client = app(OAuthClient::class)->forServerSettings('records', $this->settings(), null, ['patient']);
        Http::fakeSequence()
            ->push($this->body(['patient' => 'synthetic-patient']))
            ->push($this->body())
            ->push($this->body(['patient' => null]))
            ->push($this->body(['patient' => '']));

        $this->assertSame(['patient' => 'synthetic-patient'], $this->exchange($client)->context);
        $this->assertSame([], $client->refreshTokens('synthetic-refresh')->context);
        $this->assertSame(['patient' => null], $client->refreshTokens('synthetic-refresh')->context);
        $this->assertSame(['patient' => ''], $client->refreshTokens('synthetic-refresh')->context);
    }

    public function test_default_configured_and_unopted_explicit_clients_ignore_extra_fields(): void
    {
        Http::fake(['*' => Http::response($this->body(['patient' => ['unknown' => 'ignored']]))]);
        $clients = [app(OAuthClient::class), app(OAuthClient::class)->forServer('records'),
            app(OAuthClient::class)->forServerSettings('records', $this->settings())];
        foreach ($clients as $client) {
            $this->assertSame([], $this->exchange($client)->context);
            $this->assertSame([], $client->refreshTokens('synthetic-refresh')->context);
        }
    }

    #[DataProvider('invalidAllowlists')]
    public function test_invalid_or_reserved_context_names_are_refused_before_network(array $names): void
    {
        try {
            app(OAuthClient::class)->forServerSettings('records', $this->settings(), null, $names);
            $this->fail('Invalid context names were accepted.');
        } catch (InvalidArgumentException $error) {
            $this->assertSame('Token response context names are invalid.', $error->getMessage());
            Http::assertNothingSent();
        }
    }

    public static function invalidAllowlists(): array
    {
        return [
            'not a list' => [['key' => 'patient']],
            'too many' => [array_map(static fn (int $i): string => 'context_'.$i, range(1, 17))],
            'duplicate' => [['patient', 'patient']],
            'empty' => [['']], 'numeric' => [[3]], 'null' => [[null]],
            'control' => [["patient\n"]], 'nested path' => [['patient.id']],
            'too long' => [[str_repeat('a', 65)]],
            ...array_combine(
                self::reservedNames(),
                array_map(static fn (string $name): array => [[$name]], self::reservedNames()),
            ),
        ];
    }

    private static function reservedNames(): array
    {
        return ['access_token', 'ACCESS_TOKEN', 'refresh_token', 'id_token', 'token_type', 'expires_in', 'scope',
            'error', 'error_description', 'error_uri', 'client_id', 'client_secret', 'client_assertion',
            'client_assertion_type', 'password', 'username', 'code', 'code_verifier', 'code_challenge',
            'code_challenge_method', 'grant_type', 'redirect_uri', 'state', 'iss', 'issuer', 'resource',
            'aud', 'authorization', 'assertion', 'device_code', 'user_code'];
    }

    #[DataProvider('invalidContextValues')]
    public function test_malformed_opted_in_context_is_an_uncertain_failure_for_both_grants(mixed $value): void
    {
        $client = app(OAuthClient::class)->forServerSettings('records', $this->settings(), null, ['patient']);
        Http::fake(['*' => Http::response($this->body(['patient' => $value]))]);
        foreach (['exchange', 'refresh'] as $grant) {
            try {
                $grant === 'exchange' ? $this->exchange($client) : $client->refreshTokens('synthetic-refresh');
                $this->fail('Malformed context was accepted.');
            } catch (OAuthTokenRequestFailed $failure) {
                $this->assertSame('The authorization server returned invalid token context.', $failure->getMessage());
                $this->assertFalse($failure->definitive);
                $this->assertNull($failure->getPrevious());
                $this->assertStringNotContainsString('synthetic-private', (string) $failure);
            }
        }
    }

    public static function invalidContextValues(): array
    {
        return [['synthetic-private'.str_repeat('x', 2048)], [["synthetic-private"]], [4], [false], [1.5],
            ["synthetic-private\n"], ["synthetic-private\x7f"], ['synthetic-privateé']];
    }

    public function test_maximum_names_and_ascii_value_boundaries_are_accepted(): void
    {
        $names = array_map(static fn (int $i): string => 'context_'.$i, range(1, 15));
        $name = str_repeat('a', 64);
        $names[] = $name;
        $value = ' '.str_repeat('x', 2046).'~';
        $client = app(OAuthClient::class)->forServerSettings('records', $this->settings(), null, $names);
        Http::fake(['*' => Http::response($this->body([$name => $value]))]);
        $this->assertSame([$name => $value], $this->exchange($client)->context);
    }

    public function test_standard_token_validation_still_precedes_context_and_context_is_not_diagnostic_output(): void
    {
        $client = app(OAuthClient::class)->forServerSettings('records', $this->settings(), null, ['patient']);
        Http::fakeSequence()->push($this->body(['access_token' => [], 'patient' => []]))
            ->push($this->body(['patient' => 'synthetic-private-patient']));
        try {
            $this->exchange($client);
            $this->fail('An invalid access token was accepted.');
        } catch (OAuthTokenRequestFailed $failure) {
            $this->assertSame('The identity provider returned an invalid token.', $failure->getMessage());
        }
        $tokens = $this->exchange($client);
        $this->assertStringNotContainsString('synthetic-private-patient', print_r($tokens, true));
        $this->assertStringNotContainsString('synthetic-access', print_r($tokens, true));
        $this->assertArrayNotHasKey('context', $tokens->__debugInfo());
        $legacy = new OAuthTokens('records', 'https://records.example.test', null, 'synthetic-access', null, null, null);
        $this->assertSame([], $legacy->context);
    }

    private function settings(): array
    {
        return ['issuer' => 'https://records.example.test', 'client_id' => 'synthetic-client',
            'client_secret' => 'synthetic-secret', 'redirect_uri' => 'https://client.example.test/connect/records/callback',
            'scope' => 'records:read', 'resource' => 'urn:example:records', 'authorization_response_iss' => 'required'];
    }

    private function body(array $context = []): array
    {
        return [...['access_token' => 'synthetic-access', 'refresh_token' => 'synthetic-refresh', 'token_type' => 'Bearer'], ...$context];
    }

    private function exchange(OAuthClient $client): OAuthTokens
    {
        $session = new Store('synthetic-context', new ArraySessionHandler(120));
        $session->start();
        $start = $this->request('https://client.example.test/start', $session);
        parse_str((string) parse_url($client->redirect($start)->getTargetUrl(), PHP_URL_QUERY), $query);
        $callback = $client->serverName() === 'default' ? 'https://client.example.test/oauth/callback' : $this->settings()['redirect_uri'];
        $request = $this->request($callback.'?'.http_build_query(['state' => $query['state'], 'code' => 'synthetic-code',
            'iss' => $client->issuer(), 'patient' => 'untrusted-callback-patient']), $session);

        return $client->tokensFromCallback($request);
    }

    private function request(string $url, Store $session): Request
    {
        $request = Request::create($url);
        $request->setLaravelSession($session);
        $request->setUserResolver(static fn (): GenericUser => new GenericUser(['id' => 7]));

        return $request;
    }
}
