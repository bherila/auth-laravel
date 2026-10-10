<?php

namespace BWH\Auth\OAuth\Credentials;

use Illuminate\Contracts\Auth\Authenticatable;

/**
 * Whether an account may hold OAuth credentials at all: the application's own account
 * state (disabled, suspended, not approved), independent of the identity provider.
 *
 * Opt-in: bind an implementation and every authorization code, access token (agent and
 * personal) and refresh token is checked against it when issued, exchanged, refreshed and
 * used. A refused refresh is refused without consuming the refresh token. Pair it with
 * OAuthCredentialOwners::revokeAll() when the application disables an account, so
 * re-enabling it does not revive old credentials.
 *
 * Deliberately separate from AuthUserPolicy::canLogin(): applications use that for
 * interactive login eligibility (some only for local password login), which is not the
 * same question.
 */
interface CredentialOwnerPolicy
{
    public function mayHoldCredentials(Authenticatable $owner): bool;
}
