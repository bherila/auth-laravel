<?php

namespace BWH\Auth\OAuth\Server;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

/**
 * RFC 9728 protected-resource metadata and RFC 6750 bearer challenges.
 *
 * Route registration remains an application concern because the metadata URI
 * normally includes the concrete MCP endpoint path.
 */
final class OAuthProtectedResource
{
    /**
     * RFC 9728 metadata for one resource (the default when none is named). `resource` is
     * that resource's identifier exactly, as a client that discovered it expects.
     *
     * @return array<string, mixed>
     */
    public static function metadata(?array $supportedScopes = null, ?string $resource = null): array
    {
        return [
            'resource' => OAuthResourceIndicator::resource($resource),
            'authorization_servers' => [OAuthResourceIndicator::issuer()],
            'scopes_supported' => self::scopes($supportedScopes, $resource),
            'bearer_methods_supported' => ['header'],
        ];
    }

    public static function metadataResponse(?array $supportedScopes = null, ?string $resource = null): JsonResponse
    {
        return response()->json(self::metadata($supportedScopes, $resource))->withHeaders([
            'Cache-Control' => 'public, max-age=300',
            'X-Content-Type-Options' => 'nosniff',
        ]);
    }

    /**
     * The metadata URI for a resource's bearer challenge: the RFC 9728 path-inserted
     * well-known URL of that resource's identifier. Without a name, the resource the
     * current request's route expects, else the default one.
     */
    public static function metadataUrl(?string $resource = null): ?string
    {
        $resource ??= self::currentResource();
        $default = OAuthResourceIndicator::defaultName();
        $url = config('bherila-auth.oauth_server.protected_resource_metadata_url');
        // The legacy single-resource override applies to the default resource only.
        if ($url !== null && ($resource === null || $resource === $default)) {
            return OAuthResourceIndicator::absoluteHttpUrl($url);
        }

        return self::wellKnownFor(OAuthResourceIndicator::resource($resource));
    }

    /** The RFC 9728 well-known URL for a resource identifier. */
    public static function wellKnownFor(string $identifier): ?string
    {
        try {
            $parts = parse_url($identifier);
        } catch (\ValueError) {
            return null;
        }
        if (! is_array($parts)
            || ! isset($parts['scheme'], $parts['host'])
            || ! in_array(strtolower((string) $parts['scheme']), ['http', 'https'], true)) {
            return null;
        }

        $port = isset($parts['port']) ? ':'.(int) $parts['port'] : '';
        $path = rtrim((string) ($parts['path'] ?? ''), '/');

        return "{$parts['scheme']}://{$parts['host']}{$port}/.well-known/oauth-protected-resource".$path;
    }

    /** The name of the resource the current request's route expects, if it declared one. */
    private static function currentResource(): ?string
    {
        $request = app()->bound('request') ? app('request') : null;

        return $request === null ? null : OAuthResourceIndicator::nameFor(OAuthResourceIndicator::expectedFor($request));
    }

    /**
     * Build a standards-compatible Bearer challenge. Values are quoted and escaped
     * rather than emitted with http_build_query, which uses the wrong grammar here.
     *
     * @param  list<string>  $scopes
     * @param  array<string, string>  $extraParameters
     */
    public static function bearerChallenge(
        ?string $error = null,
        ?string $errorDescription = null,
        array $scopes = [],
        array $extraParameters = [],
    ): string {
        $parameters = [];
        if (is_string($error) && ($error = self::headerValue($error)) !== '') {
            $parameters['error'] = $error;
        }
        if (is_string($errorDescription)
            && ($errorDescription = self::headerValue($errorDescription)) !== '') {
            $parameters['error_description'] = $errorDescription;
        }
        $scopes = array_values(array_filter(
            OAuthResourceIndicator::scopeIdentifiers($scopes),
            static fn (string $scope): bool => preg_match(
                '/^[\x21\x23-\x5B\x5D-\x7E]+$/D',
                $scope,
            ) === 1,
        ));
        if ($scopes !== []) {
            $parameters['scope'] = implode(' ', $scopes);
        }
        if (($metadataUrl = self::metadataUrl()) !== null) {
            $parameters['resource_metadata'] = $metadataUrl;
        }
        foreach ($extraParameters as $name => $value) {
            if (is_string($name)
                && preg_match("/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/D", $name) === 1
                && is_string($value)
                && ($value = self::headerValue($value)) !== ''
                && ! array_key_exists($name, $parameters)) {
                $parameters[$name] = $value;
            }
        }

        if ($parameters === []) {
            return 'Bearer';
        }

        return 'Bearer '.collect($parameters)
            ->map(fn (string $value, string $name): string => $name.'='.self::quoted($value))
            ->implode(', ');
    }

    /** @param list<string> $scopes */
    public static function unauthorizedResponse(
        ?string $error = 'invalid_token',
        ?string $errorDescription = null,
        array $scopes = [],
    ): JsonResponse {
        return self::challengeResponse(401, $error, $errorDescription, $scopes, [
            'error' => $error ?? 'invalid_token',
        ]);
    }

    /**
     * The 401 for an unauthenticated request to a protected route, for an application's
     * exception handler:
     *
     *     $exceptions->render(fn (AuthenticationException $e, Request $request)
     *         => OAuthProtectedResource::unauthenticated($request));
     *
     * Null for a route that declared no expected resource (ExpectOAuthResource), so the
     * application's usual handling applies there. The challenge names the metadata of the
     * route's own resource, from configuration rather than the request's host.
     */
    public static function unauthenticated(Request $request): ?JsonResponse
    {
        if (OAuthResourceIndicator::expectedFor($request) === null) {
            return null;
        }

        return self::unauthorizedResponse('invalid_token', 'Authentication is required.');
    }

    /** @param list<string> $scopes */
    public static function insufficientScopeResponse(array $scopes): JsonResponse
    {
        return self::challengeResponse(403, 'insufficient_scope', null, $scopes, [
            'error' => 'insufficient_scope',
        ]);
    }

    /** @param list<string> $scopes @param array<string, mixed> $body */
    private static function challengeResponse(
        int $status,
        ?string $error,
        ?string $errorDescription,
        array $scopes,
        array $body,
    ): JsonResponse {
        return response()->json($body, $status, [
            'Cache-Control' => 'private, no-store',
            'Pragma' => 'no-cache',
            'WWW-Authenticate' => self::bearerChallenge($error, $errorDescription, $scopes),
        ]);
    }

    private static function quoted(string $value): string
    {
        return '"'.addcslashes($value, "\\\"").'"';
    }

    private static function headerValue(string $value): string
    {
        return preg_replace('/[\x00-\x1F\x7F]/', '', $value) ?? '';
    }

    /** @return list<string> */
    private static function scopes(?array $supportedScopes = null, ?string $resource = null): array
    {
        if ($supportedScopes === null) {
            $resources = config('bherila-auth.oauth_server.resources');
            if (is_array($resources) && $resources !== []) {
                // A resource without a ceiling admits the whole catalog, and says so.
                $resource ??= OAuthResourceIndicator::defaultName();
                $supportedScopes = OAuthResourceIndicator::resources()[$resource]['scopes']
                    ?? config('bherila-auth.oauth_server.scopes', []);
            } else {
                $supportedScopes = config('bherila-auth.oauth_server.protected_resource_scopes');
            }
        }
        $scopes = $supportedScopes ?? config('bherila-auth.oauth_server.scopes', []);
        if (! is_array($scopes)) {
            return [];
        }

        $scopes = array_is_list($scopes) ? $scopes : array_keys($scopes);

        return array_values(array_unique(array_filter(
            $scopes,
            static fn (mixed $scope): bool => is_string($scope) && $scope !== '',
        )));
    }
}
