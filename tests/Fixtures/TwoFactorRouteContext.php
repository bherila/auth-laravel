<?php

namespace BWH\Auth\Tests\Fixtures;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/** Model the configuration overlay an embedding provider applies for its own requests. */
class TwoFactorRouteContext
{
    public function handle(Request $request, Closure $next, string $prefix): Response
    {
        $previous = config('bherila-auth.two_factor.route_name_prefix');
        config(['bherila-auth.two_factor.route_name_prefix' => $prefix]);

        try {
            return $next($request);
        } finally {
            config(['bherila-auth.two_factor.route_name_prefix' => $previous]);
        }
    }
}
