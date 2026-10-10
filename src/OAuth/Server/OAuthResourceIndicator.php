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

    /**
     * The configured protected resources, by name, each with its canonical identifier and
     * its scope ceiling (null: the whole catalog).
     *
     * An application protecting one resource configures `oauth_server.resource`; it is the
     * single resource `default`. One protecting several (for example a REST API and an MCP
     * endpoint, each its own audience) configures `oauth_server.resources` instead.
     *
     * @return array<string, array{uri: string, scopes: list<string>|null}>
     */
    public static function resources(): array
    {
        $configured = config('bherila-auth.oauth_server.resources');
        if (! is_array($configured) || $configured === []) {
            $configured = ['default' => ['uri' => config('bherila-auth.oauth_server.resource')]];
        }

        $resources = [];
        foreach ($configured as $name => $definition) {
            $uri = is_array($definition) ? ($definition['uri'] ?? null) : null;
            $canonical = self::canonicalize($uri);
            if (! is_string($name) || $name === '' || $canonical === null) {
                throw new RuntimeException('An OAuth protected resource is not configured correctly.');
            }
            $scopes = $definition['scopes'] ?? null;
            $resources[$name] = [
                'uri' => $canonical,
                'scopes' => is_array($scopes) ? self::scopeIdentifiers(array_is_list($scopes) ? $scopes : array_keys($scopes)) : null,
            ];
        }
        if (count(array_unique(array_column($resources, 'uri'))) !== count($resources)) {
            throw new RuntimeException('Two OAuth protected resources share an identifier.');
        }

        return $resources;
    }

    /**
     * The resource a request that names none is bound to (when that is enabled), and the one
     * single-resource callers mean: `assume_omitted_resource` when it names a resource,
     * otherwise the first configured.
     */
    public static function defaultName(): string
    {
        $resources = self::resources();
        $assumed = config('bherila-auth.oauth_server.assume_omitted_resource');
        if (is_string($assumed) && $assumed !== '') {
            if (! array_key_exists($assumed, $resources)) {
                throw new RuntimeException('The assumed OAuth protected resource is not configured.');
            }

            return $assumed;
        }

        return array_key_first($resources);
    }

    /** The canonical identifier of a configured resource; the default one when no name is given. */
    public static function resource(?string $name = null): string
    {
        $resources = self::resources();
        $name ??= self::defaultName();

        return $resources[$name]['uri'] ?? throw new RuntimeException("The OAuth protected resource [{$name}] is not configured.");
    }

    /** The name of the configured resource with this identifier, if any. */
    public static function nameFor(mixed $value): ?string
    {
        $canonical = self::canonicalize($value);
        if ($canonical === null) {
            return null;
        }
        foreach (self::resources() as $name => $resource) {
            if ($resource['uri'] === $canonical) {
                return $name;
            }
        }

        return null;
    }

    /** The default resource's canonical identifier. Prefer isConfiguredResource() to test a value. */
    public static function configuredCanonical(): string
    {
        return self::resource();
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

    /** Whether the value is one of the configured resources. */
    public static function isConfiguredResource(mixed $value): bool
    {
        return self::nameFor($value) !== null;
    }

    /**
     * Whether these scopes fit the resource's ceiling. A scope may sit under several
     * resources; the ceiling only keeps scopes off resources that do not list them.
     *
     * @param  mixed  $scopes
     */
    public static function scopesAllowedFor(string $resource, mixed $scopes): bool
    {
        $name = self::nameFor($resource);
        if ($name === null) {
            return false;
        }
        $ceiling = self::resources()[$name]['scopes'];

        return $ceiling === null || array_diff(self::scopeIdentifiers($scopes), $ceiling) === [];
    }

    public static function validatedFor(Request $request): ?string
    {
        $attribute = $request->attributes->get(self::REQUEST_ATTRIBUTE);

        return is_string($attribute) ? self::canonicalize($attribute) : null;
    }

    /** Mark a protected request with the exact audience its route accepts. */
    public static function expectFor(Request $request, ?string $name = null): string
    {
        $resource = self::resource($name);
        $request->attributes->set(self::EXPECTED_RESOURCE_ATTRIBUTE, $resource);

        return $resource;
    }

    /** @deprecated use expectFor(); kept for applications calling it directly */
    public static function expectConfiguredFor(Request $request): string
    {
        return self::expectFor($request);
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
        $assumed = config('bherila-auth.oauth_server.assume_omitted_resource', false);

        return $assumed === true || (is_string($assumed) && $assumed !== '');
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
            return self::assumesOmittedResource() ? self::resource() : null;
        }
        // One audience per credential: a repeated parameter is refused, not silently narrowed
        // to whichever value the query parser kept.
        if (self::repeatsResource($request)) {
            return null;
        }

        return self::canonicalize($request->input('resource'));
    }

    /** Whether the raw query or form body carries `resource` more than once. */
    public static function repeatsResource(Request $request): bool
    {
        $count = 0;
        $sources = [(string) $request->server('QUERY_STRING', '')];
        if (str_contains((string) $request->header('Content-Type', ''), 'application/x-www-form-urlencoded')) {
            $sources[] = (string) $request->getContent();
        }
        foreach ($sources as $source) {
            foreach (explode('&', $source) as $pair) {
                $key = urldecode(explode('=', $pair, 2)[0]);
                if ($key === 'resource' || str_starts_with($key, 'resource[')) {
                    $count++;
                }
            }
        }

        return $count > 1;
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
