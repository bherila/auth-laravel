<?php

namespace BWH\Auth\OAuth\Client;

use Illuminate\Http\Client\ConnectionException;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;

/**
 * Whether an authorization server advertises RFC 9207 authorization response `iss`.
 *
 * Read from the RFC 8414 document at the configured issuer, which must name that exact
 * issuer. Only `authorization_response_iss_parameter_supported` is used: every endpoint
 * still comes from configuration. A document that cannot be read or names another issuer is
 * a 503 before the person is sent anywhere, because proceeding would mean not knowing
 * whether a response without `iss` is acceptable.
 *
 * @internal
 */
final class AuthorizationServerMetadata
{
    public static function issuerParameterSupported(AuthorizationServer $server, ?OAuthHttpTransport $transport = null): bool
    {
        $issuer = $server->issuer();
        $key = 'bherila-auth:oauth-client:iss-supported:'.hash('sha256', $issuer);

        $cached = Cache::get($key);
        if (is_bool($cached)) {
            return $cached;
        }

        try {
            $url = self::url($issuer);
            $request = Http::acceptJson()->timeout(5)->connectTimeout(5)->withoutRedirecting();
            $request = $transport?->prepare($request, $url) ?? $request;
            $response = $request->get($url);
        } catch (ConnectionException) {
            abort(503, 'The authorization server metadata could not be verified.');
        }

        $document = $response->status() === 200 ? $response->json() : null;
        abort_unless(
            is_array($document) && ($document['issuer'] ?? null) === $issuer,
            503,
            'The authorization server metadata could not be verified.',
        );

        $supported = ($document['authorization_response_iss_parameter_supported'] ?? false) === true;
        Cache::put($key, $supported, self::ttl());

        return $supported;
    }

    /** RFC 8414 §3.1: the well-known segment goes between the host and any issuer path. */
    private static function url(string $issuer): string
    {
        $parts = parse_url($issuer);
        $origin = $parts['scheme'].'://'.$parts['host'].(isset($parts['port']) ? ':'.$parts['port'] : '');

        return $origin.'/.well-known/oauth-authorization-server'.rtrim($parts['path'] ?? '', '/');
    }

    private static function ttl(): int
    {
        $ttl = config('bherila-auth.oauth_client.metadata_cache_seconds', 3600);

        return is_int($ttl) && $ttl > 0 ? $ttl : 3600;
    }
}
