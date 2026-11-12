<?php

namespace BWH\Auth\OAuth;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;

/** The default explicitly declares one realm with globally unique local authentication IDs. */
final class ConfiguredIdentityNamespaceResolver implements IdentityNamespaceResolver
{
    public function resolve(Request $request, Authenticatable $account): string
    {
        $namespace = config('bherila-auth.oauth_client.identity_namespace', IdentityNamespace::LEGACY);
        abort_unless(is_string($namespace), 503, 'The OAuth identity namespace is unavailable.');

        return $namespace;
    }
}
