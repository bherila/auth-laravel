<?php

namespace BWH\Auth\OAuth\DelegatedAccess;

use Illuminate\Contracts\Config\Repository;

/**
 * The delegated access endpoint's settings, read from `bherila-auth.delegated_access`.
 *
 * Every value that decides whom to trust is pinned in configuration and never discovered from a
 * request: the provider's issuer, this endpoint's exact URL as the provider calls it, this
 * application's registry key, and the provider's integration public keys. A missing or malformed
 * value refuses every request; it never falls back to anything.
 */
final readonly class DelegatedAccessSettings
{
    public function __construct(private Repository $config) {}

    public function enabled(): bool
    {
        return filter_var($this->config->get('bherila-auth.delegated_access.enabled', false), FILTER_VALIDATE_BOOLEAN);
    }

    public function application(): string
    {
        return (string) $this->config->get('bherila-auth.delegated_access.application', '');
    }

    /**
     * The issuer name local identity bindings are stored under: the OAuth provider name sign-in uses.
     *
     * Adapters resolve actors and targets through the same binding sign-in resolves, so a person
     * provisioned through this endpoint and a person who signs in are the same account.
     */
    public function bindingIssuer(): string
    {
        return (string) $this->config->get('bherila-auth.oauth_client.provider', '');
    }

    /**
     * @throws DelegatedAccessException When the configuration cannot build a trustworthy verifier.
     */
    public function verifier(NonceStore $nonces): ActorAssertionVerifier
    {
        $publicKeys = self::parsePublicKeys((string) $this->config->get('bherila-auth.delegated_access.public_keys', ''));

        // `oauth_client.provider` defaults to a package value, so it can never read as unset. The raw
        // OAUTH_PROVIDER mirror must be set and agree with it: bindings stored under a default nobody
        // chose would stop matching sign-in once the operator sets the real name.
        $explicitProvider = $this->config->get('bherila-auth.delegated_access.oauth_provider');

        if ($publicKeys === [] || ! is_string($explicitProvider) || trim($explicitProvider) === ''
            || trim($explicitProvider) !== $this->bindingIssuer()) {
            throw new DelegatedAccessException('invalid_verifier_configuration');
        }

        return new ActorAssertionVerifier(
            (string) $this->config->get('bherila-auth.delegated_access.issuer', ''),
            (string) $this->config->get('bherila-auth.delegated_access.endpoint', ''),
            $this->application(),
            $publicKeys,
            $nonces,
        );
    }

    /**
     * Parse `key-id|/path/to/public.pem` pairs, comma-separated, into `key id => PEM`.
     *
     * Any entry that is malformed, repeated, or names an unreadable file empties the whole map. A
     * partly loaded key set would silently stop accepting the key that failed, and an operator would
     * learn about it from a provider error rather than from this deployment.
     *
     * @return array<string, string>
     */
    public static function parsePublicKeys(string $value): array
    {
        $keys = [];

        foreach (array_filter(array_map('trim', explode(',', $value)), static fn (string $entry): bool => $entry !== '') as $entry) {
            $parts = explode('|', $entry, 2);

            if (count($parts) !== 2 || trim($parts[0]) === '' || isset($keys[trim($parts[0])])) {
                return [];
            }

            $path = trim($parts[1]);
            $pem = is_file($path) && is_readable($path) ? file_get_contents($path) : false;

            if (! is_string($pem) || ! str_contains($pem, 'PUBLIC KEY')) {
                return [];
            }

            $keys[trim($parts[0])] = $pem;
        }

        return $keys;
    }
}
