<?php

namespace BWH\Auth\Services;

use BWH\Auth\Contracts\LocalCredentialPolicy;
use BWH\Auth\OAuth\Session\ProviderBindingResolver;
use BWH\Auth\OAuth\Session\ProviderSessionExpired;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;

/**
 * `bherila-auth.local_credentials.provider_bound`: 'allow' (the default, no change for any
 * application) or 'refuse'.
 *
 * With 'refuse', an account the application's {@see ProviderBindingResolver} reports as bound
 * to the identity provider has no local credential path. A deliberately unbound account (a
 * break-glass administrator, say) keeps its own. A binding the resolver calls broken is
 * refused too: it is not an unbound account, and must never be let through as one.
 */
final class ConfiguredLocalCredentialPolicy implements LocalCredentialPolicy
{
    public function __construct(private readonly ProviderBindingResolver $bindings) {}

    public function mayUseLocalCredentials(Authenticatable $user, Request $request): bool
    {
        $setting = config('bherila-auth.local_credentials.provider_bound', 'allow');

        if ($setting === 'allow') {
            return true;
        }

        if ($setting !== 'refuse') {
            throw new \LogicException("bherila-auth.local_credentials.provider_bound must be 'allow' or 'refuse'.");
        }

        try {
            return $this->bindings->binding($user) === null;
        } catch (ProviderSessionExpired) {
            // A persisted account whose binding columns were never loaded (created in this
            // request, or selected without them) is read again rather than refused: the
            // stored row is the answer. Anything still unreadable is refused.
            $stored = $user instanceof Model && $user->exists ? $user->fresh() : null;
            if ($stored === null || $stored === $user) {
                return false;
            }

            try {
                return $this->bindings->binding($stored) === null;
            } catch (ProviderSessionExpired) {
                return false;
            }
        }
    }
}
