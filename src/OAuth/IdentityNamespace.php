<?php

namespace BWH\Auth\OAuth;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Throwable;

/** Shared binding for named connect flows and remembered provider authentication. */
final class IdentityNamespace
{
    public const string LEGACY = 'legacy';

    public static function resolve(Request $request, Authenticatable $account): string
    {
        try {
            $namespace = app(IdentityNamespaceResolver::class)->resolve($request, $account);
        } catch (Throwable) {
            abort(503, 'The OAuth identity namespace is unavailable.');
        }
        abort_unless(self::valid($namespace), 503, 'The OAuth identity namespace is unavailable.');

        return $namespace;
    }

    public static function valid(mixed $namespace): bool
    {
        return is_string($namespace) && preg_match('/\A[A-Za-z0-9][A-Za-z0-9._:\/-]{0,127}\z/', $namespace) === 1;
    }
}
