<?php

namespace BWH\Auth\OAuth\DelegatedAccess;

/** Validates local trust configuration; never discovers keys or follows token URLs. */
final class TrustedUrl
{
    public static function validate(string $url, bool $issuer = false): void
    {
        $parts = parse_url($url);
        $host = is_array($parts) ? strtolower($parts['host'] ?? '') : '';
        $ip = trim($host, '[]');
        $validHost = $host === 'localhost' || filter_var($ip, FILTER_VALIDATE_IP) !== false
            || (strlen($host) <= 253 && str_contains($host, '.')
                && filter_var($host, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) !== false
                && preg_match('/\.[a-z]{2,}$/D', $host) === 1);
        if (strlen($url) > 2048 || filter_var($url, FILTER_VALIDATE_URL) === false
            || ! is_array($parts) || ($parts['scheme'] ?? '') !== 'https' || ! $validHost
            || isset($parts['user']) || isset($parts['pass']) || isset($parts['query']) || isset($parts['fragment'])
            || (isset($parts['port']) && ($parts['port'] < 1 || $parts['port'] > 65535))
            || ($issuer && ! self::validIssuerPath($parts['path'] ?? ''))) {
            throw new DelegatedAccessException('invalid_verifier_configuration');
        }
    }

    /** Accept explicit canonical mount paths, never URL/path normalization or discovery. */
    private static function validIssuerPath(string $path): bool
    {
        if (in_array($path, ['', '/'], true)) {
            return true;
        }

        // Unreserved ASCII segments only: encoded separators/dots, backslashes,
        // empty segments and traversal must not alias another issuer namespace.
        return preg_match('#\A/(?:[A-Za-z0-9._~-]+/)*[A-Za-z0-9._~-]+/?\z#D', $path) === 1
            && array_intersect(explode('/', $path), ['.', '..']) === [];
    }
}
