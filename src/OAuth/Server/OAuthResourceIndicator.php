<?php

namespace BWH\Auth\OAuth\Server;

use Illuminate\Http\Request;
use RuntimeException;
use Traversable;

final class OAuthResourceIndicator
{
    public const REQUEST_ATTRIBUTE = 'bherila_auth_oauth_resource';

    public const EXPECTED_RESOURCE_ATTRIBUTE = 'bherila_auth_expected_oauth_resource';

    /**
     * Return the issuer exactly as configured. The trailing slash is significant
     * for RFC 9207 and for authorization-server metadata consumers.
     */
    public static function issuer(): string
    {
        $issuer = config('bherila-auth.oauth_server.issuer');
        if (self::absoluteHttpUrl($issuer, allowQuery: false) === null) {
            throw new RuntimeException('The OAuth issuer is not configured.');
        }

        return (string) $issuer;
    }

    public static function resource(): string
    {
        $resource = config('bherila-auth.oauth_server.resource');
        if (! is_string($resource) || self::canonicalize($resource) === null) {
            throw new RuntimeException('The OAuth protected resource is not configured.');
        }

        return $resource;
    }

    public static function configuredCanonical(): string
    {
        return self::canonicalize(self::resource())
            ?? throw new RuntimeException('The OAuth protected resource is not configured.');
    }

    public static function canonicalize(mixed $value): ?string
    {
        if (! is_string($value) || $value === '' || strlen($value) > 2048) {
            return null;
        }

        try {
            $parts = parse_url($value);
        } catch (\ValueError) {
            return null;
        }
        if (! is_array($parts)
            || ! isset($parts['scheme'], $parts['host'])
            || isset($parts['user'])
            || isset($parts['pass'])
            || isset($parts['query'])
            || isset($parts['fragment'])) {
            return null;
        }

        $scheme = strtolower((string) $parts['scheme']);
        $host = strtolower((string) $parts['host']);
        if (! in_array($scheme, ['http', 'https'], true) || $host === '') {
            return null;
        }

        $port = '';
        if (isset($parts['port'])) {
            $portNumber = (int) $parts['port'];
            if ($portNumber < 1 || $portNumber > 65535) {
                return null;
            }
            $port = ':'.$portNumber;
        }
        if (($scheme === 'https' && $port === ':443') || ($scheme === 'http' && $port === ':80')) {
            $port = '';
        }

        return "{$scheme}://{$host}{$port}".(string) ($parts['path'] ?? '');
    }

    public static function isConfiguredResource(mixed $value): bool
    {
        return self::canonicalize($value) === self::canonicalize(self::resource());
    }

    public static function validatedFor(Request $request): ?string
    {
        $attribute = $request->attributes->get(self::REQUEST_ATTRIBUTE);

        return is_string($attribute) ? self::canonicalize($attribute) : null;
    }

    /** Mark a protected request with the exact audience its route accepts. */
    public static function expectConfiguredFor(Request $request): string
    {
        $resource = self::configuredCanonical();
        $request->attributes->set(self::EXPECTED_RESOURCE_ATTRIBUTE, $resource);

        return $resource;
    }

    public static function expectedFor(Request $request): ?string
    {
        $attribute = $request->attributes->get(self::EXPECTED_RESOURCE_ATTRIBUTE);

        return is_string($attribute) ? self::canonicalize($attribute) : null;
    }

    /**
     * Whether an omitted `resource` parameter means the configured resource.
     *
     * Opt-in (`oauth_server.assume_omitted_resource`). RFC 8707 makes the
     * parameter optional, and many generic OAuth clients never send it. An
     * application whose authorization server protects exactly one resource can
     * bind such a client's codes and tokens to that resource instead of refusing
     * them or issuing unbound credentials its resource routes then reject. An
     * explicit resource that differs is still refused.
     */
    public static function assumesOmittedResource(): bool
    {
        return (bool) config('bherila-auth.oauth_server.assume_omitted_resource', false);
    }

    /** Whether a token/authorization request names a resource, explicitly or by that assumption. */
    public static function requestNamesResource(Request $request): bool
    {
        return $request->exists('resource') || self::assumesOmittedResource();
    }

    /**
     * Return a normalized resource parameter from a token/authorization request.
     * A missing parameter and a malformed parameter both return null; callers that
     * need to distinguish them should inspect Request::exists('resource'). With
     * {@see self::assumesOmittedResource()}, a missing parameter returns the
     * configured resource.
     */
    public static function requestResource(Request $request): ?string
    {
        if (! $request->exists('resource')) {
            return self::assumesOmittedResource() ? self::configuredCanonical() : null;
        }

        return self::canonicalize($request->input('resource'));
    }

    /** @return list<string> */
    public static function requiredScopes(): array
    {
        $configured = [];
        $legacy = config('bherila-auth.oauth_server.resource_required_scope');
        if (is_string($legacy) && trim($legacy) !== '') {
            $configured[] = trim($legacy);
        }

        $scopes = config('bherila-auth.oauth_server.resource_required_scopes', []);
        if (is_string($scopes)) {
            $scopes = preg_split('/\s+/', trim($scopes)) ?: [];
        }
        if (is_array($scopes)) {
            foreach ($scopes as $scope) {
                if (is_string($scope) && trim($scope) !== '') {
                    $configured[] = trim($scope);
                }
            }
        }

        return array_values(array_unique($configured));
    }

    /**
     * The application owns the scope catalog and declares which of those scopes
     * require an audience-bound resource credential.
     *
     * @param  mixed  $scopes  Scope identifiers, a JSON array, an iterable collection, or Passport scope entities.
     */
    public static function scopesRequireResource(mixed $scopes): bool
    {
        return array_intersect(self::scopeIdentifiers($scopes), self::requiredScopes()) !== [];
    }

    /** @return list<string> */
    public static function scopeIdentifiers(mixed $scopes): array
    {
        if (is_string($scopes)) {
            $trimmed = trim($scopes);
            $decoded = json_decode($scopes, true);
            $scopes = json_last_error() === JSON_ERROR_NONE
                ? (is_array($decoded) ? $decoded : [])
                : preg_split('/\s+/', $trimmed);
        }
        if ($scopes instanceof Traversable) {
            $scopes = iterator_to_array($scopes);
        }
        if (! is_array($scopes) || ! array_is_list($scopes)) {
            return [];
        }

        $identifiers = [];
        foreach ($scopes as $scope) {
            if (is_string($scope) && trim($scope) !== '') {
                $identifiers[] = trim($scope);
            } elseif (is_object($scope) && method_exists($scope, 'getIdentifier')) {
                $identifier = $scope->getIdentifier();
                if (is_string($identifier) && $identifier !== '') {
                    $identifiers[] = $identifier;
                }
            }
        }

        return array_values(array_unique($identifiers));
    }

    /**
     * Inspect claims after Passport's resource-server validator has verified the
     * signature. This is deliberately not a replacement for signature validation.
     *
     * @return array<string, mixed>|null
     */
    public static function tokenClaims(string $serializedToken): ?array
    {
        $parts = explode('.', $serializedToken);
        if (count($parts) !== 3) {
            return null;
        }

        $encodedPayload = strtr($parts[1], '-_', '+/');
        $padding = strlen($encodedPayload) % 4;
        if ($padding !== 0) {
            $encodedPayload .= str_repeat('=', 4 - $padding);
        }

        $payload = base64_decode($encodedPayload, true);
        if ($payload === false || $payload === '') {
            return null;
        }

        $claims = json_decode($payload, true);

        return is_array($claims) ? $claims : null;
    }

    public static function tokenHasAudience(?string $serializedToken, string $resource): bool
    {
        if (! is_string($serializedToken)) {
            return false;
        }

        $audiences = self::tokenClaims($serializedToken)['aud'] ?? null;
        if (is_string($audiences)) {
            $audiences = [$audiences];
        }
        if (! is_array($audiences)) {
            return false;
        }

        foreach ($audiences as $audience) {
            if (is_string($audience) && self::canonicalize($audience) === self::canonicalize($resource)) {
                return true;
            }
        }

        return false;
    }

    public static function tokenHasAnyResourceAudience(?string $serializedToken): bool
    {
        if (! is_string($serializedToken)) {
            return false;
        }

        $audiences = self::tokenClaims($serializedToken)['aud'] ?? null;
        if (is_string($audiences)) {
            $audiences = [$audiences];
        }
        if (! is_array($audiences)) {
            return false;
        }

        // Passport's first audience is the client identifier. Only an
        // additional URL-form audience can represent a resource. This avoids
        // treating a future URL-form client ID as an unbound resource claim.
        foreach (array_slice($audiences, 1) as $audience) {
            if (is_string($audience) && self::canonicalize($audience) !== null) {
                return true;
            }
        }

        return false;
    }

    public static function tokenResourceClaimMatches(?string $serializedToken, string $resource): bool
    {
        $claim = is_string($serializedToken)
            ? (self::tokenClaims($serializedToken)['resource'] ?? null)
            : null;

        return $claim === null
            || (is_string($claim) && self::canonicalize($claim) === self::canonicalize($resource));
    }

    public static function tokenHasIssuer(?string $serializedToken, string $issuer): bool
    {
        return is_string($serializedToken)
            && (self::tokenClaims($serializedToken)['iss'] ?? null) === $issuer;
    }

    public static function absoluteHttpUrl(mixed $value, bool $allowQuery = true): ?string
    {
        if (! is_string($value)
            || $value === ''
            || strlen($value) > 2048
            || filter_var($value, FILTER_VALIDATE_URL) === false) {
            return null;
        }

        try {
            $parts = parse_url($value);
        } catch (\ValueError) {
            return null;
        }
        if (! is_array($parts)
            || ! isset($parts['scheme'], $parts['host'])
            || $parts['host'] === ''
            || isset($parts['user'])
            || isset($parts['pass'])
            || isset($parts['fragment'])
            || (! $allowQuery && isset($parts['query']))
            || ! in_array(strtolower((string) $parts['scheme']), ['http', 'https'], true)) {
            return null;
        }
        if (isset($parts['port'])
            && ((int) $parts['port'] < 1 || (int) $parts['port'] > 65535)) {
            return null;
        }

        return $value;
    }
}
