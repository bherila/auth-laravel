<?php

namespace BWH\Auth\Support;

/** Named two-factor links, resolved from the current host or mounted-provider context. */
final class TwoFactorRoutes
{
    public static function name(string $action): string
    {
        return config('bherila-auth.two_factor.route_name_prefix', 'bherila-auth.two-factor.').$action;
    }
}
