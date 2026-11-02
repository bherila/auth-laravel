<?php

namespace BWH\Auth\Http\Middleware;

use BWH\Auth\Http\Controllers\RelyingPartyLoginController;
use BWH\Auth\OAuth\AuthenticationRequirement;
use BWH\Auth\OAuth\Session\AuthenticationContext;
use Closure;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use LogicException;
use Symfony\Component\HttpFoundation\Response;

/**
 * Require a recent provider authentication, and optionally a rung or a set of methods.
 *
 * ```php
 * Route::middleware(['auth', RequireRecentAuthentication::class.':900'])->...;
 * Route::middleware(['auth', RequireRecentAuthentication::class.':3600,acr=urn:auth-manager:acr:phishing-resistant'])->...;
 * Route::middleware(['auth', RequireRecentAuthentication::class.':900,amr=otp|hwk|swk'])->...;
 * ```
 *
 * A browser goes to `recent_authentication.redirect_to`, which must route to
 * {@see RelyingPartyLoginController::redirect()}, and that sign-in
 * asks the provider for the requirement. A JSON client gets a 403 naming what's needed.
 */
final class RequireRecentAuthentication
{
    public function handle(Request $request, Closure $next, string ...$arguments): Response
    {
        $requirement = self::parse($arguments);
        $user = $request->user();

        if ($user !== null && AuthenticationContext::satisfies($request, $user, $requirement)) {
            return $next($request);
        }

        if ($request->expectsJson()) {
            return new JsonResponse([
                'message' => 'Please sign in again to continue.',
                'error' => 'insufficient_user_authentication',
                'max_age' => $requirement->maxAge,
                'acr_values' => $requirement->acrValues,
            ], Response::HTTP_FORBIDDEN, ['Cache-Control' => 'private, no-store']);
        }

        AuthenticationContext::requireNext($request, $requirement);
        if ($request->isMethod('GET')) {
            $request->session()->put('url.intended', $request->fullUrl());
        }

        return redirect((string) config('bherila-auth.recent_authentication.redirect_to', '/login'));
    }

    /** @param  list<string>  $arguments */
    private static function parse(array $arguments): AuthenticationRequirement
    {
        $maxAge = null;
        $values = [];

        foreach ($arguments as $argument) {
            if (ctype_digit($argument)) {
                $maxAge = (int) $argument;
            } elseif (str_starts_with($argument, 'acr=')) {
                array_push($values, ...explode('|', substr($argument, 4)));
            } elseif (str_starts_with($argument, 'amr=')) {
                foreach (explode('|', substr($argument, 4)) as $method) {
                    $values[] = AuthenticationRequirement::AMR_PREFIX.$method;
                }
            } else {
                throw new LogicException("Unknown RequireRecentAuthentication argument: {$argument}");
            }
        }

        if ($maxAge === null && $values === []) {
            throw new LogicException('RequireRecentAuthentication needs a number of seconds, acr= or amr=.');
        }

        return new AuthenticationRequirement(maxAge: $maxAge, acrValues: $values);
    }
}
