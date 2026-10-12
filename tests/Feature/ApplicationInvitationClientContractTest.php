<?php

namespace BWH\Auth\Tests\Feature;

use BWH\Auth\OAuth\DelegatedAccess\NonceStore;
use BWH\Auth\OAuth\Invitations\ApplicationInvitationClient;
use BWH\Auth\OAuth\Invitations\ApplicationInvitations;
use BWH\Auth\Tests\Fixtures\ConfiguresApplicationInvitations;
use BWH\Auth\Tests\Fixtures\IdentityProvider\ApplicationActorAssertionVerifier;
use BWH\Auth\Tests\Fixtures\IdentityProvider\ApplicationInvitationRefused;
use BWH\Auth\Tests\TestCase;
use Illuminate\Http\Client\Request;
use Illuminate\Http\Request as ServerRequest;
use Illuminate\Support\Facades\Http;
use Lcobucci\JWT\Encoding\JoseEncoder;
use PHPUnit\Framework\Attributes\DataProvider;

/**
 * What the client sends is what the identity provider verifies.
 *
 * The provider's verifier is copied verbatim into tests/Fixtures/IdentityProvider. Each request the
 * client sends is checked the way the provider's middleware checks it: the audience is the provider's
 * issuer and the request path, the body is the raw request content, and the client id is the token's.
 */
class ApplicationInvitationClientContractTest extends TestCase
{
    use ConfiguresApplicationInvitations;

    protected function setUp(): void
    {
        parent::setUp();
        $this->configureInvitations();
    }

    /** @return array<string, array{0: \Closure(ApplicationInvitations): mixed, 1: string, 2: string, 3: array<mixed>}> */
    public static function operations(): array
    {
        return [
            'create' => [fn ($invitations) => $invitations->create('42', 'person@example.test'),
                '/api/application-invitations', '{"email":"person@example.test"}', self::issuedBody()],
            // Characters a JSON encoder may escape: whatever is sent is what is hashed.
            'create, an address with a slash and non-ASCII' => [fn ($invitations) => $invitations->create('42', 'a/b.ünï@example.test'),
                '/api/application-invitations', '{"email":"a/b.ünï@example.test"}', self::issuedBody()],
            'resend' => [fn ($invitations) => $invitations->resend('42', 42),
                '/api/application-invitations/42/resend', '{}', self::issuedBody()],
            'revoke' => [fn ($invitations) => $invitations->revoke('42', 42),
                '/api/application-invitations/42/revoke', '{}', ['invitation' => ['id' => 42, 'status' => 'revoked']]],
        ];
    }

    #[DataProvider('operations')]
    public function test_the_provider_verifier_accepts_what_the_client_sends(\Closure $operation, string $path, string $body, array $answer): void
    {
        $this->provider($answer, $path === '/api/application-invitations' ? 201 : 200);

        $operation($this->invitations());

        [$request] = $this->invitationRequests();
        $this->assertSame('POST', $request->method());
        $this->assertSame(self::ISSUER.$path, $request->url());
        $this->assertSame($body, $request->body());
        $this->assertSame(['application/json'], $request->header('Content-Type'));
        $this->assertSame(['application/json'], $request->header('Accept'));
        $this->assertSame(['Bearer '.self::TOKEN], $request->header('Authorization'));

        $claims = $this->providerVerifies($request);
        $this->assertSame(['sub' => '42'], ['sub' => $claims['sub']]);
    }

    public function test_the_assertion_has_exactly_the_contract_members(): void
    {
        $this->provider();

        $this->invitations()->create('9007199254740993', 'person@example.test');

        [$request] = $this->invitationRequests();
        [$header, $claims] = $this->decode($request->header(ApplicationInvitationClient::ASSERTION_HEADER)[0]);
        $this->assertSame(['alg' => 'RS256', 'kid' => 'example-app-v1', 'typ' => 'application-invitation+jwt'], self::sorted($header));
        $this->assertSame(['aud', 'body_sha256', 'exp', 'iat', 'iss', 'jti', 'method', 'sub'], array_keys(self::sorted($claims)));
        $this->assertSame(self::CLIENT_ID, $claims['iss']);
        // A subject past 2^53 stays an exact decimal string.
        $this->assertSame('9007199254740993', $claims['sub']);
        $this->assertSame(self::ISSUER.'/api/application-invitations', $claims['aud']);
        $this->assertIsInt($claims['iat']);
        $this->assertSame($claims['iat'] + 60, $claims['exp']);
        $this->assertMatchesRegularExpression('/^[a-f0-9]{64}$/D', $claims['jti']);
        $this->assertSame('POST', $claims['method']);
        $this->assertSame(hash('sha256', '{"email":"person@example.test"}'), $claims['body_sha256']);
        $this->providerVerifies($request, '9007199254740993');
    }

    public function test_every_request_carries_a_new_assertion_id(): void
    {
        $this->provider(fn (Request $request) => Http::response(self::issuedBody(), 200));

        $this->invitations()->resend('42', 42);
        $this->invitations()->resend('42', 42);

        $ids = array_map(fn (Request $request): string => $this->decode($request->header(ApplicationInvitationClient::ASSERTION_HEADER)[0])[1]['jti'],
            $this->invitationRequests());
        $this->assertCount(2, array_unique($ids));
    }

    public function test_the_verifier_copy_refuses_an_assertion_for_another_body_or_url(): void
    {
        // The fixture is not vacuous: the same request with one byte changed, or sent elsewhere, is refused.
        $this->provider();
        $this->invitations()->create('42', 'person@example.test');
        [$request] = $this->invitationRequests();
        $assertion = $request->header(ApplicationInvitationClient::ASSERTION_HEADER)[0];
        $verifier = new ApplicationActorAssertionVerifier($this->nonces());
        $keys = ['example-app-v1' => $this->publicKey];

        foreach ([
            [self::ISSUER.'/api/application-invitations', '{"email":"other@example.test"}', $keys],
            [self::ISSUER.'/api/application-invitations/42/resend', $request->body(), $keys],
            [self::ISSUER.'/api/application-invitations', $request->body(), ['example-app-v2' => $this->publicKey]],
        ] as [$audience, $body, $publicKeys]) {
            try {
                $verifier->verify($assertion, self::CLIENT_ID, $audience, $body, $publicKeys);
                $this->fail('The provider verifier accepted an assertion for another request.');
            } catch (ApplicationInvitationRefused $refused) {
                $this->assertSame('invalid_actor_assertion', $refused->error);
            }
        }
    }

    /**
     * Verify as the provider does: issuer and path for the audience, the raw body, the token's client.
     *
     * @return array{sub: string, jti: string}
     */
    private function providerVerifies(Request $request, string $subject = '42'): array
    {
        // AuthenticateApplicationInvitationRequest::audience(): rtrim(issuer, '/').'/'.$request->path()
        $server = ServerRequest::create($request->url(), 'POST', content: $request->body());
        $audience = rtrim(self::ISSUER, '/').'/'.$server->path();

        $claims = (new ApplicationActorAssertionVerifier($this->nonces()))->verify(
            $request->header(ApplicationActorAssertionVerifier::HEADER)[0],
            self::CLIENT_ID, $audience, $server->getContent(), ['example-app-v1' => $this->publicKey],
        );
        $this->assertSame($subject, $claims['sub']);

        return $claims;
    }

    private function nonces(): NonceStore
    {
        return new class implements NonceStore
        {
            /** @var array<string, true> */
            private array $used = [];

            public function consume(string $key, int $seconds): bool
            {
                if (isset($this->used[$key])) {
                    return false;
                }

                return $this->used[$key] = true;
            }
        };
    }

    /** @return array{0: array<string, mixed>, 1: array<string, mixed>} */
    private function decode(string $assertion): array
    {
        $encoder = new JoseEncoder;
        [$header, $claims] = explode('.', $assertion);

        return [$encoder->jsonDecode($encoder->base64UrlDecode($header)), $encoder->jsonDecode($encoder->base64UrlDecode($claims))];
    }

    /** @param  array<string, mixed>  $values */
    private static function sorted(array $values): array
    {
        ksort($values);

        return $values;
    }
}
