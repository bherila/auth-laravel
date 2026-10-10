<?php

namespace BWH\Auth\OAuth\Session;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;

/** The default: provider and subject columns on the user record, named in configuration. */
final class ColumnProviderBindingResolver implements ProviderBindingResolver
{
    public function binding(Authenticatable $user): ?ProviderBinding
    {
        if (! $user instanceof Model) {
            throw new ProviderSessionExpired('The provider session binding is invalid.');
        }

        $provider = $user->getAttribute((string) config('bherila-auth.provider_identity.binding.provider_column', 'oauth_provider'));
        $subject = $user->getAttribute((string) config('bherila-auth.provider_identity.binding.subject_column', 'oauth_subject'));
        if ($provider === null && $subject === null) {
            return null;
        }
        if (! is_string($provider) || ! is_string($subject) || $subject === ''
            || $provider !== config('bherila-auth.oauth_client.provider')) {
            throw new ProviderSessionExpired('The provider session binding is invalid.');
        }

        return new ProviderBinding($provider, $subject);
    }
}
