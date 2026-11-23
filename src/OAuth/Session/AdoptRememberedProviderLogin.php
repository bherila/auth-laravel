<?php

namespace BWH\Auth\OAuth\Session;

use Illuminate\Auth\Events\Login;
use Illuminate\Auth\SessionGuard;
use Illuminate\Contracts\Auth\Factory as AuthFactory;

/**
 * When a session guard restores a session from a remember-me cookie, give the restored session
 * the provider baseline recorded for that cookie's token (RememberedProviderLogins), so
 * provider lifecycle enforcement checks it instead of ending it for want of a baseline.
 *
 * Registered by the package for every application. It writes only the session's baseline, never
 * authorizes anything, and does nothing for an unbound account, an unrecorded token, or a login
 * that did not come from a remember-me cookie.
 */
final readonly class AdoptRememberedProviderLogin
{
    public function __construct(
        private AuthFactory $auth,
        private ProviderBindingResolver $bindings,
        private ProviderSession $session,
    ) {}

    public function handle(Login $event): void
    {
        $provider = config('bherila-auth.oauth_client.provider');
        if (! $event->remember || ! is_string($provider) || $provider === '') {
            return;
        }
        $guard = $this->auth->guard($event->guard);
        if (! $guard instanceof SessionGuard || ! $guard->viaRemember()) {
            return;
        }

        try {
            $binding = $this->bindings->binding($event->user);
        } catch (ProviderSessionExpired) {
            // A broken binding is refused by the enforcement middleware; nothing to adopt.
            return;
        }
        if ($binding !== null) {
            $this->session->restoreRemembered($guard, $event->user, $binding);
        }
    }
}
