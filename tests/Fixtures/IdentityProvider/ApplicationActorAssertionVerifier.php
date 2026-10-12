<?php

namespace BWH\Auth\Tests\Fixtures\IdentityProvider;

use BWH\Auth\OAuth\DelegatedAccess\NonceStore;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\UnencryptedToken;
use SensitiveParameter;
use Throwable;

/**
 * VERBATIM COPY of the identity provider's verifier (its app/Services/Invitations/ApplicationActorAssertionVerifier.php
 * at 85e5b19d9065), only the namespace changed. ApplicationInvitationClientContractTest signs with the
 * package client and verifies here, so an assertion the provider would refuse fails the suite. Refresh it
 * from the provider when the provider changes, never by hand.
 *
 * Verifies the actor assertion an application signs for an admission invitation request.
 *
 * The delegated access assertion's shape, in the other direction: RS256 with a key pinned to the
 * application, its own `typ` so neither kind can be replayed as the other, the calling client as
 * issuer, the exact endpoint URL as audience, the SHA-256 of the exact body, a 64-hex `jti` used
 * once, and at most 60 seconds of life (five seconds of clock skew). Returns the actor's subject
 * only; whether that person may act is decided after.
 */
final readonly class ApplicationActorAssertionVerifier
{
    public const TYPE = 'application-invitation+jwt';

    /** The request header that carries the assertion. */
    public const HEADER = 'Actor-Assertion';

    public function __construct(private NonceStore $nonces) {}

    /**
     * @param  array<string, string>  $publicKeys  PEM public keys by key id, all the calling application's
     * @return array{sub: string, jti: string}
     *
     * @throws ApplicationInvitationRefused
     */
    public function verify(#[SensitiveParameter] string $assertion, string $clientId, string $audience, string $body, array $publicKeys): array
    {
        try {
            if ($publicKeys === [] || strlen($assertion) > 8192 || strlen($body) > 65536) {
                throw self::invalid();
            }
            $parts = explode('.', $assertion);
            if (count($parts) !== 3) {
                throw self::invalid();
            }
            $encoder = new JoseEncoder;
            $headers = $encoder->jsonDecode($encoder->base64UrlDecode($parts[0]));
            $claims = $encoder->jsonDecode($encoder->base64UrlDecode($parts[1]));
            if (! is_array($headers) || ! is_array($claims)
                || array_diff(array_keys($headers), ['alg', 'typ', 'kid']) !== []
                || array_diff(array_keys($claims), ['iss', 'sub', 'aud', 'iat', 'exp', 'jti', 'method', 'body_sha256']) !== []
                || ($headers['alg'] ?? null) !== 'RS256'
                || ($headers['typ'] ?? null) !== self::TYPE
                || ! is_string($headers['kid'] ?? null)
                || ! isset($publicKeys[$headers['kid']])) {
                throw self::invalid();
            }
            $token = (new Parser($encoder))->parse($assertion);
            if (! $token instanceof UnencryptedToken
                || ! (new Sha256)->verify($token->signature()->hash(), $token->payload(), InMemory::plainText($publicKeys[$headers['kid']]))) {
                throw self::invalid();
            }
            $now = time();
            if (($claims['iss'] ?? null) !== $clientId
                || ! in_array($claims['aud'] ?? null, [$audience, [$audience]], true)
                || ($claims['method'] ?? null) !== 'POST'
                || ! is_string($claims['sub'] ?? null) || preg_match('/^[1-9][0-9]{0,19}$/D', $claims['sub']) !== 1
                || ! is_string($claims['jti'] ?? null) || preg_match('/^[a-f0-9]{64}$/D', $claims['jti']) !== 1
                || ! is_int($claims['iat'] ?? null) || ! is_int($claims['exp'] ?? null)
                || $claims['iat'] < 0 || $claims['iat'] > $now + 5
                || $claims['exp'] <= $now - 5 || $claims['exp'] <= $claims['iat']
                || $claims['exp'] > $claims['iat'] + 60
                || ! is_string($claims['body_sha256'] ?? null)
                || ! hash_equals(hash('sha256', $body), $claims['body_sha256'])) {
                throw self::invalid();
            }
        } catch (Throwable) {
            throw self::invalid();
        }

        try {
            $consumed = $this->nonces->consume(hash('sha256', "application-invitation\0{$clientId}\0{$claims['jti']}"), max(1, $claims['exp'] + 5 - $now));
        } catch (Throwable) {
            throw new ApplicationInvitationRefused('replay_storage_unavailable', 503, 'The request could not be checked for replay. Try again later.');
        }
        if (! $consumed) {
            throw new ApplicationInvitationRefused('replayed_actor_assertion', 401, 'This actor assertion was already used.');
        }
        // Storage may block past the validity boundary; a newly stored id must not revive an
        // assertion that expired in flight.
        if ($claims['exp'] <= time() - 5) {
            throw self::invalid();
        }

        return ['sub' => $claims['sub'], 'jti' => $claims['jti']];
    }

    private static function invalid(): ApplicationInvitationRefused
    {
        return new ApplicationInvitationRefused('invalid_actor_assertion', 401, 'A valid actor assertion is required.');
    }
}
