<?php

namespace BWH\Auth\OAuth\Session;

use Illuminate\Contracts\Auth\Authenticatable;

/**
 * Where an application keeps the provider binding of a local account.
 *
 * Return null only for an account that is deliberately unbound (a local emergency
 * account, for example); those fall to the application's own login policy. Throw
 * ProviderSessionExpired for a binding that is incomplete or names another provider:
 * that is a broken binding, not an unbound account, and must never be let through.
 */
interface ProviderBindingResolver
{
    public function binding(Authenticatable $user): ?ProviderBinding;
}
