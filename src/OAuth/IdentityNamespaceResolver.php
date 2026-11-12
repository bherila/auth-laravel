<?php

namespace BWH\Auth\OAuth;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;

/** A stable identity realm from trusted host guard/tenant context, never callback input or email. */
interface IdentityNamespaceResolver
{
    public function resolve(Request $request, Authenticatable $account): string;
}
