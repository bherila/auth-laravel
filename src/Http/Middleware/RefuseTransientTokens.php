<?php

namespace BWH\Auth\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Refuses Passport's transient-token cookie route under the agent profile.
 *
 * The cookie it mints authenticates API requests as the signed-in person with every
 * scope, outside both the browser session's checks and the bearer token's, and keeps
 * working until it expires. Agents use OAuth tokens and first-party pages use the
 * session, so the profile has no use for it.
 */
final class RefuseTransientTokens
{
    public function handle(Request $request, Closure $next): Response
    {
        abort(404);
    }
}
