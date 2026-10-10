<?php

namespace BWH\Auth\Http\Middleware;

use BWH\Auth\OAuth\Session\ProviderBindingResolver;
use BWH\Auth\OAuth\Session\ProviderSession;
use BWH\Auth\OAuth\Session\ProviderSessionExpired;
use BWH\Auth\OAuth\Session\ProviderStatusUnavailable;
use Closure;
use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * End a browser session whose provider identity was disabled, deleted, reset or
 * ungranted since sign-in.
 *
 * Register it after authentication on every session-authenticated route, for
 * example by appending it to the `web` group or wrapping the `auth` alias:
 *
 * ```php
 * Route::middleware(['auth', RequireActiveProviderSession::class])->group(...);
 * ```
 *
 * Off unless `bherila-auth.provider_identity.enabled`. Only session (stateful)
 * guards are checked here; bearer credentials have their own enforcement. An
 * account the binding resolver reports as unbound is left to the application's
 * login policy. Unsafe methods always check freshly. Application authorization
 * still runs afterwards: an active identity grants nothing by itself.
 *
 * Pass guard names as parameters when the route authenticates with a guard other
 * than the default (`RequireActiveProviderSession::class.':admin'`).
 */
final readonly class RequireActiveProviderSession
{
    public function __construct(
        private AuthFactory $auth,
        private ProviderSession $session,
        private ProviderBindingResolver $bindings,
    ) {}

    public function handle(Request $request, Closure $next, string ...$guards): Response
    {
        if (! config('bherila-auth.provider_identity.enabled', false)) {
            return $next($request);
        }
        // Signing out must stay reachable while the provider or the shared store is down;
        // it only ends local access, so letting it through grants nothing.
        $except = config('bherila-auth.provider_identity.except_routes', ['logout']);
        if (is_array($except) && $except !== [] && $request->routeIs(...$except)) {
            return $next($request);
        }

        foreach ($guards === [] ? [null] : $guards as $name) {
            $guard = $this->auth->guard($name);
            $user = $guard->user();
            if (! $guard instanceof StatefulGuard || $user === null) {
                continue;
            }

            try {
                $binding = $this->bindings->binding($user);
                if ($binding === null) {
                    continue;
                }
                $this->session->assertActive($request, $binding->provider, $binding->subject,
                    fresh: ! $request->isMethodSafe());
            } catch (ProviderSessionExpired) {
                $guard->logout();
                $request->session()->invalidate();
                $request->session()->regenerateToken();

                return $this->expired($request);
            } catch (ProviderStatusUnavailable) {
                return $this->unavailable($request);
            }
        }

        return $next($request);
    }

    private function expired(Request $request): Response
    {
        if ($request->expectsJson()) {
            return response()->json(['message' => 'Your sign-in has ended. Sign in again.'], 401)
                ->header('Cache-Control', 'private, no-store');
        }

        $route = config('bherila-auth.provider_identity.expired_redirect_route');
        $target = is_string($route) && $route !== '' ? route($route) : url('/');

        return redirect()->guest($target)->header('Cache-Control', 'private, no-store');
    }

    private function unavailable(Request $request): Response
    {
        $message = 'Sign-in verification is temporarily unavailable. Please retry.';
        $response = $request->expectsJson()
            ? response()->json(['message' => $message], 503)
            : response($message, 503);

        return $response->header('Retry-After', '30')->header('Cache-Control', 'private, no-store');
    }
}
