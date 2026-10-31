<?php

namespace BWH\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;

/**
 * Whether an account may sign in with, or acquire, a credential this application holds itself:
 * a password, a password reset, a passkey, or the second factor of a password sign-in.
 *
 * Separate from {@see AuthUserPolicy::canLogin()}, which answers whether the account may sign
 * in at all, by any method, the identity provider included. An account bound to the provider
 * can be active and still be one that must only ever sign in there: a local credential would
 * outlive the provider disabling it, revoking its grant, or requiring a second factor.
 *
 * The package's password-reset, change-password, passkey and two-factor paths consult it. An
 * application's own password-login controller must call it too.
 */
interface LocalCredentialPolicy
{
    public function mayUseLocalCredentials(Authenticatable $user, Request $request): bool;
}
