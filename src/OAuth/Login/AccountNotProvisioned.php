<?php

namespace BWH\Auth\OAuth\Login;

use RuntimeException;

/**
 * A sign-in for a subject with no local account, in an application that does not create
 * accounts at sign-in ({@see RelyingPartyAccounts::provisionsNewAccounts()}).
 *
 * Carries no address or subject: the provider name is all a log needs.
 */
final class AccountNotProvisioned extends RuntimeException
{
    public function __construct(public readonly string $provider)
    {
        parent::__construct('No local account is linked to this identity.');
    }
}
