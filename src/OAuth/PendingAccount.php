<?php

namespace BWH\Auth\OAuth;

/**
 * Placeholder contact details for a local account created for a provider subject before its first
 * sign-in: by delegated access provisioning, or by an operator bootstrapping a first administrator.
 *
 * Deriving them one way everywhere keeps the placeholder recognisable. The real name and address
 * arrive from the provider at first sign-in; neither is ever an account-linking key. The
 * (provider, subject) binding is.
 */
final class PendingAccount
{
    /** A name to show until the provider supplies the real one. */
    public static function name(string $label, string $subject): string
    {
        return $label.' ('.(mb_strlen($subject) > 40 ? mb_substr($subject, 0, 40).'…' : $subject).')';
    }

    /**
     * `.invalid` is reserved (RFC 2606) and resolves nowhere, so this address can never be mailed or
     * mistaken for a real one. It is deterministic in the pair, for unique `email` columns.
     */
    public static function email(string $provider, string $subject): string
    {
        return 'sso-'.substr(hash('sha256', $provider."\0".$subject), 0, 32).'@invalid';
    }
}
