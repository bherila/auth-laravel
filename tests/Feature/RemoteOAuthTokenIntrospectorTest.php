<?php

namespace BWH\Auth\Tests\Feature;

use BWH\Auth\OAuth\Introspection\IntrospectedToken;
use BWH\Auth\OAuth\Introspection\OAuthIntrospectionException;
use BWH\Auth\OAuth\Introspection\RemoteOAuthTokenIntrospector;
use BWH\Auth\Tests\TestCase;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Http;
use PHPUnit\Framework\Attributes\DataProvider;

final class RemoteOAuthTokenIntrospectorTest extends TestCase
{
    private const ENDPOINT = 'https://auth.example.test/oauth/introspect';

    private const RESOURCE = 'https://resource.example.test/mcp';

    protected function setUp(): void
    {
        parent::setUp();

        config([
            'app.env' => 'testing',
            'bherila-auth.oauth_resource_server.introspection_endpoint' => self::ENDPOINT,
            'bherila-auth.oauth_resource_server.client_id' => 'resource-server',
            'bherila-auth.oauth_resource_server.client_secret' => 'test-secret',
            'bherila-auth.oauth_resource_server.issuer' => 'https://auth.example.test',
            'bherila-auth.oauth_resource_server.resource' => self::RESOURCE,
            'bherila-auth.oauth_resource_server.timeout_seconds' => 5,
        ]);
    }

    public function test_it_returns_a_defensively_validated_active_context(): void
    {
        Http::fake([
            self::ENDPOINT => Http::response([
                'active' => true,
                'iss' => 'https://auth.example.test',
                'sub' => '42',
                'client_id' => 'public-client',
                'scope' => 'mcp:use offers:read',
                'exp' => time() + 300,
                'iat' => time() - 10,
                'nbf' => time() - 10,
                'aud' => ['public-client', self::RESOURCE],
                'resource' => self::RESOURCE,
            ]),
        ]);

        $result = app(RemoteOAuthTokenIntrospector::class)->introspect('opaque-to-the-resource-server');

        self::assertTrue($result->active);
        self::assertSame('42', $result->subject);
        self::assertSame(['mcp:use', 'offers:read'], $result->scopes);
        Http::assertSent(function (Request $request): bool {
            return $request->url() === self::ENDPOINT
                && $request['token'] === 'opaque-to-the-resource-server'
                && $request['token_type_hint'] === 'access_token'
                && $request->hasHeader('Authorization', 'Basic '.base64_encode('resource-server:test-secret'));
        });
    }

    public function test_it_accepts_integral_float_timestamps_from_json(): void
    {
        $expiresAt = time() + 300;
        $issuedAt = time() - 10;
        $notBefore = time() - 10;
        Http::fake([
            self::ENDPOINT => Http::response($this->activeResponseJson(
                "{$expiresAt}.0",
                "{$issuedAt}.0",
                "{$notBefore}.0",
            ), 200, ['Content-Type' => 'application/json']),
        ]);

        $result = app(RemoteOAuthTokenIntrospector::class)->introspect('integral-float-timestamps');

        self::assertSame($expiresAt, $result->expiresAt);
        self::assertSame($issuedAt, $result->issuedAt);
        self::assertSame($notBefore, $result->notBefore);
    }

    /**
     * The shape Laravel Passport actually emits. Before this was accepted, a
     * resource server pointed at a stock Passport authorization server rejected
     * every live token and reported the authorization server as unavailable.
     */
    public function test_it_accepts_fractional_numeric_date_timestamps(): void
    {
        $expiresAt = time() + 300;
        $issuedAt = time() - 10;
        $notBefore = time() - 10;
        Http::fake([
            self::ENDPOINT => Http::response($this->activeResponseJson(
                "{$expiresAt}.76965808868408203125",
                "{$issuedAt}.776278018951416015625",
                "{$notBefore}.776279926300048828125",
            ), 200, ['Content-Type' => 'application/json']),
        ]);

        $result = app(RemoteOAuthTokenIntrospector::class)->introspect('fractional-timestamps');

        // exp and iat floor; nbf ceils, so the validity window is never widened.
        self::assertSame($expiresAt, $result->expiresAt);
        self::assertSame($issuedAt, $result->issuedAt);
        self::assertSame($notBefore + 1, $result->notBefore);
    }

    /**
     * Flooring an `nbf` of `now + 0.75` yields exactly `now`, and parse()
     * rejects only `$notBefore > $now`, so the token would be honoured up to a
     * second before it became valid. Ceiling is what closes that window.
     *
     * The clock is frozen because this is a whole-second boundary case: if the
     * second ticked between building the payload and the comparison in parse(),
     * the ceiled `nbf` would equal the new current second and the token would
     * be accepted for a reason that has nothing to do with the rounding.
     */
    public function test_it_does_not_honour_a_token_before_a_fractional_not_before(): void
    {
        Carbon::setTestNow(Carbon::createFromTimestamp(1770000000));
        $now = Carbon::now()->getTimestamp();

        Http::fake([
            self::ENDPOINT => Http::response($this->activeResponseJson(
                (string) ($now + 300),
                (string) ($now - 10),
                "{$now}.75",
            ), 200, ['Content-Type' => 'application/json']),
        ]);

        self::assertEquals(
            IntrospectedToken::inactive(),
            app(RemoteOAuthTokenIntrospector::class)->introspect('not-yet-valid'),
        );
    }

    /**
     * The same frozen instant, one second earlier: once `now` reaches the
     * ceiled `nbf` the token must be honoured, so the claim above is about
     * rounding direction and not about rejecting fractional `nbf` outright.
     */
    public function test_it_honours_a_token_once_a_fractional_not_before_has_passed(): void
    {
        Carbon::setTestNow(Carbon::createFromTimestamp(1770000001));
        $notBefore = 1770000000;

        Http::fake([
            self::ENDPOINT => Http::response($this->activeResponseJson(
                (string) (1770000001 + 300),
                (string) ($notBefore - 10),
                "{$notBefore}.75",
            ), 200, ['Content-Type' => 'application/json']),
        ]);

        $result = app(RemoteOAuthTokenIntrospector::class)->introspect('now-valid');

        self::assertTrue($result->active);
        self::assertSame($notBefore + 1, $result->notBefore);
    }

    /**
     * Flooring must not round a fraction up into validity: an `exp` whose whole
     * second has already passed is expired no matter how large its fraction is.
     */
    public function test_it_floors_rather_than_rounds_a_fractional_expiry(): void
    {
        $expiresAt = time();
        Http::fake([
            self::ENDPOINT => Http::response(
                $this->activeResponseJson($expiresAt.'.999999'),
                200,
                ['Content-Type' => 'application/json'],
            ),
        ]);

        self::assertEquals(
            IntrospectedToken::inactive(),
            app(RemoteOAuthTokenIntrospector::class)->introspect('fractional-expired'),
        );
    }

    #[DataProvider('invalidTimestampProvider')]
    public function test_it_rejects_malformed_or_out_of_range_timestamps(string $timestamp): void
    {
        Http::fake([
            self::ENDPOINT => Http::response(
                $this->activeResponseJson($timestamp),
                200,
                ['Content-Type' => 'application/json'],
            ),
        ]);

        $this->expectException(OAuthIntrospectionException::class);

        app(RemoteOAuthTokenIntrospector::class)->introspect('invalid-timestamp');
    }

    /** @return array<string, array{string}> */
    public static function invalidTimestampProvider(): array
    {
        return [
            'string' => ['"1770000000"'],
            'nan' => ['NaN'],
            'infinity' => ['Infinity'],
            'overflow' => ['9223372036854775808'],
            'underflow' => ['-9223372036854775809'],
            // A double cannot represent these literals, so json_decode rounds
            // them onto the exact platform bounds. They must not be laundered
            // into PHP_INT_MAX by the range check.
            'float overflow' => ['9223372036854775809.0'],
            'float upper bound' => ['9223372036854775808.0'],
        ];
    }

    #[DataProvider('outOfRangeIssuedAtProvider')]
    public function test_it_rejects_out_of_range_issued_at_timestamps(string $issuedAt): void
    {
        $expiresAt = time() + 300;
        Http::fake([
            self::ENDPOINT => Http::response(
                $this->activeResponseJson((string) $expiresAt, $issuedAt),
                200,
                ['Content-Type' => 'application/json'],
            ),
        ]);

        $this->expectException(OAuthIntrospectionException::class);

        app(RemoteOAuthTokenIntrospector::class)->introspect('out-of-range-iat');
    }

    /**
     * `iat` carries no ordering constraint, so unlike `exp` it is rejected only
     * by the range check itself. The underflow literal is the important case:
     * json_decode rounds it onto exactly PHP_INT_MIN, where an inclusive lower
     * bound would silently accept it.
     *
     * @return array<string, array{string}>
     */
    public static function outOfRangeIssuedAtProvider(): array
    {
        return [
            'float underflow' => ['-9223372036854775809.0'],
            'float lower bound' => ['-9223372036854775808.0'],
            'float overflow' => ['9223372036854775809.0'],
            'float upper bound' => ['9223372036854775808.0'],
            'integer underflow' => ['-9223372036854775809'],
        ];
    }

    public function test_it_still_accepts_the_largest_representable_in_range_float(): void
    {
        // The greatest double strictly below 2 ** 63; the exclusive bounds must
        // not narrow the accepted range any further than the rounding demands.
        $expiresAt = 9223372036854774784;
        Http::fake([
            self::ENDPOINT => Http::response(
                $this->activeResponseJson($expiresAt.'.0'),
                200,
                ['Content-Type' => 'application/json'],
            ),
        ]);

        $result = app(RemoteOAuthTokenIntrospector::class)->introspect('largest-in-range-float');

        self::assertSame($expiresAt, $result->expiresAt);
    }

    public function test_inactive_tokens_remain_inactive_without_requiring_claims(): void
    {
        Http::fake([self::ENDPOINT => Http::response(['active' => false])]);

        self::assertFalse(app(RemoteOAuthTokenIntrospector::class)->introspect('revoked')->active);
    }

    private function activeResponseJson(string $expiresAt, string $issuedAt = '1770000000', string $notBefore = '1770000000'): string
    {
        return '{"active":true,"iss":"https://auth.example.test","sub":"42",'
            .'"client_id":"public-client","scope":"mcp:use","exp":'.$expiresAt
            .',"iat":'.$issuedAt.',"nbf":'.$notBefore.',"aud":["public-client","'
            .self::RESOURCE.'"],"resource":"'.self::RESOURCE.'"}';
    }

    public function test_it_form_encodes_basic_credentials(): void
    {
        $clientId = 'resource: server+%';
        $clientSecret = 'secret: with+percent%';
        config([
            'bherila-auth.oauth_resource_server.client_id' => $clientId,
            'bherila-auth.oauth_resource_server.client_secret' => $clientSecret,
        ]);
        Http::fake([self::ENDPOINT => Http::response(['active' => false])]);

        self::assertFalse(app(RemoteOAuthTokenIntrospector::class)->introspect('revoked')->active);
        Http::assertSent(fn (Request $request): bool => $request->hasHeader(
            'Authorization',
            'Basic '.base64_encode(urlencode($clientId).':'.urlencode($clientSecret)),
        ));
    }

    public function test_an_active_response_for_the_wrong_resource_fails_closed(): void
    {
        Http::fake([self::ENDPOINT => Http::response([
            'active' => true,
            'iss' => 'https://auth.example.test',
            'sub' => '42',
            'client_id' => 'public-client',
            'scope' => 'mcp:use',
            'exp' => time() + 300,
            'aud' => ['public-client', 'https://other.example.test/mcp'],
            'resource' => 'https://other.example.test/mcp',
        ])]);

        self::assertEquals(
            IntrospectedToken::inactive(),
            app(RemoteOAuthTokenIntrospector::class)->introspect('wrong-resource'),
        );
    }

    #[DataProvider('invalidContextProvider')]
    public function test_invalid_active_contexts_return_no_authorization_claims(array $overrides, array $missing = []): void
    {
        $payload = json_decode($this->activeResponseJson((string) (time() + 300)), true, 512, JSON_THROW_ON_ERROR);
        $payload = array_replace($payload, $overrides);
        foreach ($missing as $key) {
            unset($payload[$key]);
        }
        Http::fake([self::ENDPOINT => Http::response($payload)]);

        self::assertEquals(
            IntrospectedToken::inactive(),
            app(RemoteOAuthTokenIntrospector::class)->introspect('invalid-context'),
        );
    }

    public static function invalidContextProvider(): array
    {
        return [
            'wrong issuer' => [['iss' => 'https://other.example.test']],
            'wrong resource' => [['resource' => 'https://other.example.test/mcp']],
            'wrong audience' => [['aud' => ['https://other.example.test/mcp']]],
            'empty audience' => [['aud' => []]],
            'expired' => [['exp' => 0]],
            'not yet valid' => [['nbf' => PHP_INT_MAX]],
            'missing resource' => [[], ['resource']],
            'missing audience' => [[], ['aud']],
            'no resource binding' => [[], ['resource', 'aud']],
            'null binding' => [['resource' => null, 'aud' => null]],
        ];
    }

    #[DataProvider('upstreamFailureProvider')]
    public function test_upstream_http_failures_remain_unavailable(int $status): void
    {
        Http::fake([self::ENDPOINT => Http::response(['active' => false], $status)]);
        $this->expectException(OAuthIntrospectionException::class);

        app(RemoteOAuthTokenIntrospector::class)->introspect('server-failure');
    }

    public static function upstreamFailureProvider(): array
    {
        return [[302], [401], [403], [429], [500], [503]];
    }

    public function test_connection_failures_remain_unavailable(): void
    {
        Http::fake(fn () => throw new ConnectionException('Synthetic outage'));
        $this->expectException(OAuthIntrospectionException::class);

        app(RemoteOAuthTokenIntrospector::class)->introspect('server-failure');
    }

    #[DataProvider('malformedClaimsProvider')]
    public function test_malformed_claims_remain_unavailable_even_when_the_token_is_expired(array $overrides): void
    {
        $payload = json_decode($this->activeResponseJson('0'), true, 512, JSON_THROW_ON_ERROR);
        Http::fake([self::ENDPOINT => Http::response(array_replace($payload, $overrides))]);
        $this->expectException(OAuthIntrospectionException::class);

        app(RemoteOAuthTokenIntrospector::class)->introspect('malformed-claims');
    }

    public static function malformedClaimsProvider(): array
    {
        return [
            'resource type' => [['resource' => []]],
            'resource URL' => [['resource' => 'not-a-url']],
            'audience type' => [['aud' => 42]],
            'audience item' => [['aud' => [null]]],
            'audience object' => [['aud' => ['resource' => self::RESOURCE]]],
            'issuer type' => [['iss' => []]],
            'subject type' => [['sub' => 42]],
            'client type' => [['client_id' => []]],
            'scope type' => [['scope' => []]],
            'expiry type' => [['exp' => '0']],
            'issued-at type' => [['iat' => '0']],
            'not-before type' => [['nbf' => '0']],
        ];
    }

    public function test_it_canonicalizes_resource_identifiers_without_tls_restriction(): void
    {
        $configured = 'HTTPS://RESOURCE.EXAMPLE.TEST:443/mcp';
        config(['bherila-auth.oauth_resource_server.resource' => $configured]);
        Http::fake([self::ENDPOINT => Http::response([
            'active' => true, 'iss' => 'https://auth.example.test', 'sub' => '42',
            'client_id' => 'public-client', 'scope' => 'mcp:use', 'exp' => time() + 300,
            'aud' => ['public-client', 'https://resource.example.test/mcp'],
            'resource' => 'HTTPS://RESOURCE.EXAMPLE.TEST:443/mcp',
        ])]);

        self::assertSame('https://resource.example.test/mcp', app(RemoteOAuthTokenIntrospector::class)->introspect('token')->resource);
    }

    public function test_it_preserves_opaque_subject_and_client_identifier_whitespace(): void
    {
        Http::fake([self::ENDPOINT => Http::response([
            'active' => true, 'iss' => 'https://auth.example.test', 'sub' => ' subject ',
            'client_id' => ' client ', 'scope' => 'mcp:use', 'exp' => time() + 300,
            'aud' => ['public-client', self::RESOURCE], 'resource' => self::RESOURCE,
        ])]);

        $result = app(RemoteOAuthTokenIntrospector::class)->introspect('token');
        self::assertSame(' subject ', $result->subject);
        self::assertSame(' client ', $result->clientId);
    }

    public function test_http_resource_is_allowed_when_introspection_endpoint_is_https(): void
    {
        config(['bherila-auth.oauth_resource_server.resource' => 'http://resource.example.test/mcp']);
        Http::fake([self::ENDPOINT => Http::response(['active' => false])]);

        self::assertFalse(app(RemoteOAuthTokenIntrospector::class)->introspect('token')->active);
    }

    public function test_http_and_schema_failures_are_reported_as_unavailable(): void
    {
        Http::fake([self::ENDPOINT => Http::response(['active' => 'yes'], 200)]);

        $this->expectException(OAuthIntrospectionException::class);

        app(RemoteOAuthTokenIntrospector::class)->introspect('malformed-response');
    }

    public function test_it_refuses_insecure_endpoints_before_sending_the_token(): void
    {
        config(['bherila-auth.oauth_resource_server.introspection_endpoint' => 'http://auth.example.test/oauth/introspect']);
        Http::fake();

        try {
            app(RemoteOAuthTokenIntrospector::class)->introspect('must-not-leave');
            self::fail('Expected insecure endpoint configuration to be rejected.');
        } catch (OAuthIntrospectionException) {
            Http::assertNothingSent();
        }
    }

    public function test_it_refuses_loopback_http_outside_local_or_testing(): void
    {
        config([
            'app.env' => 'production',
            'bherila-auth.oauth_resource_server.introspection_endpoint' => 'http://127.0.0.1/oauth/introspect',
            'bherila-auth.oauth_resource_server.issuer' => 'http://127.0.0.1',
        ]);
        Http::fake();

        try {
            app(RemoteOAuthTokenIntrospector::class)->introspect('must-not-leave');
            self::fail('Expected production loopback HTTP configuration to be rejected.');
        } catch (OAuthIntrospectionException) {
            Http::assertNothingSent();
        }
    }

    public function test_it_allows_loopback_http_during_testing(): void
    {
        $endpoint = 'http://127.0.0.1/oauth/introspect';
        config([
            'bherila-auth.oauth_resource_server.introspection_endpoint' => $endpoint,
            'bherila-auth.oauth_resource_server.issuer' => 'http://127.0.0.1',
        ]);
        Http::fake([$endpoint => Http::response(['active' => false])]);

        self::assertFalse(app(RemoteOAuthTokenIntrospector::class)->introspect('inactive')->active);
        Http::assertSentCount(1);
    }

    public function test_it_allows_bracketed_ipv6_loopback_http_during_testing(): void
    {
        $endpoint = 'http://[::1]/oauth/introspect';
        config([
            'bherila-auth.oauth_resource_server.introspection_endpoint' => $endpoint,
            'bherila-auth.oauth_resource_server.issuer' => 'http://[::1]',
        ]);
        Http::fake([$endpoint => Http::response(['active' => false])]);

        self::assertFalse(app(RemoteOAuthTokenIntrospector::class)->introspect('inactive')->active);
        Http::assertSentCount(1);
    }

    public function test_it_refuses_a_cross_origin_introspection_endpoint_before_sending_the_token(): void
    {
        config(['bherila-auth.oauth_resource_server.introspection_endpoint' => 'https://other.example.test/oauth/introspect']);
        Http::fake();

        try {
            app(RemoteOAuthTokenIntrospector::class)->introspect('must-not-leave');
            self::fail('Expected cross-origin endpoint configuration to be rejected.');
        } catch (OAuthIntrospectionException) {
            Http::assertNothingSent();
        }
    }
}
