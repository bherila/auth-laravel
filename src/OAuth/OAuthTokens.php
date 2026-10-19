<?php

namespace BWH\Auth\OAuth;

use DateTimeImmutable;
use SensitiveParameter;

/**
 * Tokens one authorization server issued to this application, with the server, issuer and
 * resource they were requested for. The token values are left out of dumps; store them
 * encrypted.
 */
final readonly class OAuthTokens
{
    /**
     * @param  list<string>|null  $scopes  the granted scopes. When the server omitted `scope`: for a
     *                                     code exchange, the requested ones (RFC 6749 §5.1); for a refresh, the
     *                                     granted scopes the caller passed, or null (unchanged, not known here)
     */
    public function __construct(
        public string $server,
        public string $issuer,
        public ?string $resource,
        #[SensitiveParameter] public string $accessToken,
        #[SensitiveParameter] public ?string $refreshToken,
        public ?DateTimeImmutable $expiresAt,
        public ?array $scopes,
    ) {}

    /** @return array<string, mixed> */
    public function __debugInfo(): array
    {
        return [
            'server' => $this->server,
            'issuer' => $this->issuer,
            'resource' => $this->resource,
            'accessToken' => '[redacted]',
            'refreshToken' => $this->refreshToken === null ? null : '[redacted]',
            'expiresAt' => $this->expiresAt,
            'scopes' => $this->scopes,
        ];
    }
}
