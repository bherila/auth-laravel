<?php

namespace BWH\Auth\OAuth\DelegatedAccess;

use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\UnencryptedToken;
use SensitiveParameter;
use Throwable;

/** Consumer-side primitive: construction requires locally pinned trust, never JWT URLs. */
final readonly class ActorAssertionVerifier
{
    public const TYPE = 'application-access+jwt';

    private string $issuer;

    public function __construct(
        string $issuer,
        private string $endpoint,
        private string $application,
        private array $publicKeys,
        private NonceStore $nonces,
    ) {
        try {
            TrustedUrl::validate($issuer, issuer: true);
            $this->issuer = rtrim($issuer, '/');
            TrustedUrl::validate($endpoint);
            if (parse_url($issuer, PHP_URL_SCHEME) !== 'https' || parse_url($endpoint, PHP_URL_SCHEME) !== 'https'
                || preg_match('/^[a-z][a-z0-9-]{0,63}$/D', $application) !== 1 || $publicKeys === []) {
                throw new DelegatedAccessException('invalid_verifier_configuration');
            }
        } catch (Throwable) {
            throw new DelegatedAccessException('invalid_verifier_configuration');
        }
    }

    /** Returns the actor subject only; application authorization must still run. */
    public function verify(#[SensitiveParameter] string $assertion, string $method, string $body): string
    {
        try {
            if (strlen($assertion) > 8192 || strlen($body) > 65536 || $method !== 'POST') {
                throw new DelegatedAccessException('invalid_actor_assertion', 401);
            }
            $parts = explode('.', $assertion);
            if (count($parts) !== 3) {
                throw new DelegatedAccessException('invalid_actor_assertion', 401);
            }
            $encoder = new JoseEncoder;
            $headers = $encoder->jsonDecode($encoder->base64UrlDecode($parts[0]));
            $claims = $encoder->jsonDecode($encoder->base64UrlDecode($parts[1]));
            if (! is_array($headers) || ! is_array($claims)
                || array_diff(array_keys($headers), ['alg', 'typ', 'kid']) !== []
                || array_diff(array_keys($claims), ['iss', 'sub', 'aud', 'iat', 'exp', 'jti', 'application', 'method', 'body_sha256']) !== []
                || ($headers['alg'] ?? null) !== 'RS256'
                || ($headers['typ'] ?? null) !== self::TYPE
                || ! is_string($headers['kid'] ?? null)
                || ! isset($this->publicKeys[$headers['kid']])) {
                throw new DelegatedAccessException('invalid_actor_assertion', 401);
            }
            $token = (new Parser($encoder))->parse($assertion);
            if (! $token instanceof UnencryptedToken
                || ! (new Sha256)->verify($token->signature()->hash(), $token->payload(), InMemory::plainText($this->publicKeys[$headers['kid']]))) {
                throw new DelegatedAccessException('invalid_actor_assertion', 401);
            }
            $now = time();
            if (($claims['iss'] ?? null) !== $this->issuer
                || ! in_array($claims['aud'] ?? null, [$this->endpoint, [$this->endpoint]], true)
                || ($claims['application'] ?? null) !== $this->application
                || ($claims['method'] ?? null) !== $method
                || ! is_string($claims['sub'] ?? null) || $claims['sub'] === '' || strlen($claims['sub']) > 191
                || ! is_string($claims['jti'] ?? null) || preg_match('/^[a-f0-9]{64}$/D', $claims['jti']) !== 1
                || ! is_int($claims['iat'] ?? null) || ! is_int($claims['exp'] ?? null)
                || $claims['iat'] < 0 || $claims['iat'] > $now + 5
                || $claims['exp'] <= $now - 5 || $claims['exp'] <= $claims['iat']
                || $claims['exp'] > $claims['iat'] + 60
                || ! is_string($claims['body_sha256'] ?? null)
                || ! hash_equals(hash('sha256', $body), $claims['body_sha256'])) {
                throw new DelegatedAccessException('invalid_actor_assertion', 401);
            }
        } catch (Throwable) {
            throw new DelegatedAccessException('invalid_actor_assertion', 401);
        }

        try {
            $consumed = $this->nonces->consume(
                hash('sha256', $this->issuer."\0".$this->application."\0".$claims['jti']),
                max(1, $claims['exp'] + 5 - $now),
            );
        } catch (Throwable) {
            throw new DelegatedAccessException('replay_storage_unavailable');
        }
        if (! $consumed) {
            throw new DelegatedAccessException('replayed_actor_assertion', 401);
        }

        // Storage may block past the validity boundary or prune an expired nonce.
        // A newly inserted row must never revive an assertion that expired in flight.
        if ($claims['exp'] <= time() - 5) {
            throw new DelegatedAccessException('invalid_actor_assertion', 401);
        }

        return $claims['sub'];
    }
}
