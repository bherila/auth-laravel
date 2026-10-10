<?php

namespace BWH\Auth\Http\Middleware;

use BWH\Auth\OAuth\Server\OAuthResourceIndicator;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Establish the audience expected by one protected application route.
 *
 * Without a parameter the route accepts the default resource. With several resources,
 * name the route's own (`ExpectOAuthResource::class.':mcp'`): a token bound to any other
 * resource, including an alias of this endpoint, is refused, and the route's bearer
 * challenge points at this resource's metadata. Register it before `auth:api`.
 */
final class ExpectOAuthResource
{
    public function handle(Request $request, Closure $next, ?string $resource = null): Response
    {
        OAuthResourceIndicator::expectFor($request, $resource === '' ? null : $resource);

        return $next($request);
    }
}
