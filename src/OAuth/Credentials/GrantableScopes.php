<?php

namespace BWH\Auth\OAuth\Credentials;

/**
 * The permissions a person may give an API token or an OAuth app they register.
 *
 * Bind an implementation that offers only scopes some REST operation actually
 * requires (for example, read from the application's operation registry), so
 * nobody can create a credential that cannot call anything.
 */
interface GrantableScopes
{
    /** @return array<string, string> scope identifier => description */
    public function scopes(): array;
}
