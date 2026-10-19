<?php

namespace BWH\Auth\OAuth;

use BWH\Auth\OAuth\Session\ProviderBindingResolver;
use BWH\Auth\OAuth\Session\ProviderSessionExpired;
use Illuminate\Contracts\Auth\Authenticatable;

/**
 * Whether an account at another application is the same person as a local account.
 *
 * Use it when an application connects to another one's API for a person (for example after
 * {@see OAuthClient::tokensFromCallback()}) and that API reports the identity provider's
 * subject for the token's owner: compare it with the local owner's binding before trusting
 * the connection, and again whenever the report is read.
 *
 * It matches only when both sides name the trusted identity provider and the same non-empty
 * subject, byte for byte. An unbound owner, an empty or missing subject, or any other
 * provider never matches: a connection must not be made for an account whose identity
 * cannot be established. Subjects are opaque; an integer (as a JSON id) is compared as its
 * decimal string, nothing is trimmed or case-folded.
 */
final class SameSubject
{
    public static function matches(
        string $trustedProvider,
        mixed $boundProvider,
        mixed $boundSubject,
        mixed $reportedProvider,
        mixed $reportedSubject,
    ): bool {
        $bound = self::subject($boundSubject);
        $reported = self::subject($reportedSubject);

        return $trustedProvider !== ''
            && $trustedProvider === trim($trustedProvider)
            && $boundProvider === $trustedProvider
            && $reportedProvider === $trustedProvider
            && $bound !== null
            && $reported !== null
            && hash_equals($bound, $reported);
    }

    /**
     * Compare with the account's binding, as the application's ProviderBindingResolver reads
     * it, under the sign-in provider (`oauth_client.provider`) unless another is named.
     */
    public static function matchesUser(
        Authenticatable $user,
        mixed $reportedProvider,
        mixed $reportedSubject,
        ?string $trustedProvider = null,
    ): bool {
        $trustedProvider ??= config('bherila-auth.oauth_client.provider');
        if (! is_string($trustedProvider)) {
            return false;
        }

        try {
            $binding = app(ProviderBindingResolver::class)->binding($user);
        } catch (ProviderSessionExpired) {
            return false;
        }

        return $binding !== null
            && self::matches($trustedProvider, $binding->provider, $binding->subject, $reportedProvider, $reportedSubject);
    }

    private static function subject(mixed $subject): ?string
    {
        if (is_int($subject) && $subject >= 0) {
            return (string) $subject;
        }

        return is_string($subject) && $subject !== '' && strlen($subject) <= 191 ? $subject : null;
    }
}
