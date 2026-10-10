<?php

namespace BWH\Auth\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * CORS for the OAuth machine endpoints a browser-based agent calls directly: discovery
 * documents, dynamic client registration and the token endpoint.
 *
 * Deliberately narrow: only origins listed in `oauth_server.cors.allowed_origins` (or `*`)
 * get CORS headers, never credentials, and an origin that is not listed is simply not
 * given any (a browser then refuses the response) rather than an error, so non-browser
 * clients are unaffected. This is separate from an MCP endpoint's own origin validation.
 */
final class OAuthEndpointCors
{
    public function handle(Request $request, Closure $next): Response
    {
        $origin = $request->headers->get('Origin');
        $allowed = is_string($origin) && $this->allows($origin);

        if ($request->isMethod('OPTIONS') && $allowed) {
            return $this->preflight($this->decorate(response('', 204), $origin));
        }
        // Any other preflight continues, so an application's own CORS middleware on these routes
        // can still answer it.

        $response = $next($request);
        if ($allowed) {
            return $this->decorate($response, $origin);
        }
        // Once CORS depends on the origin, every response varies by it: a cache must never hand
        // a header-less copy (fetched without an Origin, or by an unlisted one) to a listed origin.
        if ($this->configured()) {
            $this->vary($response);
        }

        return $response;
    }

    private function configured(): bool
    {
        $origins = config('bherila-auth.oauth_server.cors.allowed_origins', []);

        return is_array($origins) && $origins !== [];
    }

    private function vary(Response $response): void
    {
        $vary = array_filter(array_map('trim', explode(',', (string) $response->headers->get('Vary', ''))));
        $response->headers->set('Vary', implode(', ', array_unique([...$vary, 'Origin'])));
    }

    private function allows(string $origin): bool
    {
        $origins = config('bherila-auth.oauth_server.cors.allowed_origins', []);
        if (! is_array($origins) || $origins === [] || preg_match('#^https?://[^/\s]+$#i', $origin) !== 1) {
            return false;
        }

        return in_array('*', $origins, true) || in_array(strtolower($origin), array_map('strtolower', array_filter($origins, 'is_string')), true);
    }

    private function decorate(Response $response, string $origin): Response
    {
        $response->headers->set('Access-Control-Allow-Origin', $origin);
        $response->headers->set('Access-Control-Expose-Headers', 'WWW-Authenticate');
        $this->vary($response);

        return $response;
    }

    private function preflight(Response $response): Response
    {
        $response->headers->set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
        $response->headers->set('Access-Control-Allow-Headers', 'Authorization, Content-Type, MCP-Protocol-Version');
        $response->headers->set('Access-Control-Max-Age', (string) (int) config('bherila-auth.oauth_server.cors.max_age', 600));

        return $response;
    }
}
