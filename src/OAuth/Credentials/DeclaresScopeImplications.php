<?php

namespace BWH\Auth\OAuth\Credentials;

/**
 * Optional companion to {@see ScopePresentation}: scopes a picker should tick
 * together, such as `billing:write` needing `billing:read`.
 *
 * Presentation only. A credential still stores explicit scopes, no endpoint adds
 * an implied scope or rejects a set missing one, and authorization never infers
 * one scope from another, so no existing grant widens.
 */
interface DeclaresScopeImplications
{
    /** @return array<string, list<string>> scope => scopes it needs, e.g. ['billing:write' => ['billing:read']] */
    public function implications(): array;
}
