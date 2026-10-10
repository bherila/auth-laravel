<?php

namespace BWH\Auth\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Laravel\Passport\Passport;
use Symfony\Component\HttpFoundation\Response;

/**
 * Drops Passport's transient-token cookie from every request under the agent profile.
 *
 * That cookie authenticates API requests as the signed-in person with every scope,
 * outside both the browser session's checks and the bearer token's, until it expires.
 * Refusing the route that mints it is not enough: Passport's CreateFreshApiToken
 * middleware attaches one to ordinary web responses. Agents use OAuth tokens and
 * first-party pages use the session, so the profile ignores the cookie outright.
 */
final class IgnoreTransientTokenCookies
{
    public function handle(Request $request, Closure $next): Response
    {
        $request->cookies->remove(Passport::cookie());

        return $next($request);
    }
}
