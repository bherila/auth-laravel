<?php

namespace BWH\Auth\Services;

use BWH\Auth\Contracts\AuthUserPolicy;
use BWH\Auth\Support\IntendedUrl;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;

class DefaultAuthUserPolicy implements AuthUserPolicy
{
    /**
     * Whether the user is allowed to log in.
     *
     * Duck-types `$user->canLogin()` first (covers approved/active/disabled checks in one call),
     * then falls back to `$user->is_disabled`, then defaults to `true` for apps that have no
     * such columns.
     *
     * Apps with an `approved_at` column or a multi-step onboarding state should bind a custom
     * {@see AuthUserPolicy} implementation that encodes those rules here,
     * and call `canLogin()` from their primary password-login controller and from any
     * post-email-verification redirect so all entry points share the same gate.
     */
    public function canLogin(Authenticatable $user, Request $request): bool
    {
        if (method_exists($user, 'canLogin')) {
            return (bool) $user->canLogin();
        }

        if (isset($user->is_disabled)) {
            return ! (bool) $user->is_disabled;
        }

        return true;
    }

    /**
     * Whether the user may authenticate via a passkey.
     *
     * Delegates to {@see canLogin()} — if the user is not allowed to log in at all, passkey
     * login is also denied.
     */
    public function canPasskeyLogin(Authenticatable $user, Request $request): bool
    {
        return $this->canLogin($user, $request);
    }

    public function redirectAfterLogin(Authenticatable $user, Request $request): string
    {
        if (method_exists($user, 'getLoginRedirectUrl')) {
            return (string) $user->getLoginRedirectUrl();
        }

        return IntendedUrl::consume($request) ?? '/';
    }
}
