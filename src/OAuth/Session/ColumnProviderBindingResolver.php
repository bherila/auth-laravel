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

        $providerColumn = (string) config('bherila-auth.provider_identity.binding.provider_column', 'oauth_provider');
        $subjectColumn = (string) config('bherila-auth.provider_identity.binding.subject_column', 'oauth_subject');
        $attributes = $user->getAttributes();
        // An absent column (misnamed in configuration, not selected, or never migrated) reads
        // as null, which would exempt every account as if it were deliberately unbound.
        if (! array_key_exists($providerColumn, $attributes) || ! array_key_exists($subjectColumn, $attributes)) {
            throw new ProviderSessionExpired('The provider session binding is invalid.');
        }
        $provider = $user->getAttribute($providerColumn);
        $subject = $user->getAttribute($subjectColumn);
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
