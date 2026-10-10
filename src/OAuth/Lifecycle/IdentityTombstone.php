<?php

namespace BWH\Auth\OAuth\Lifecycle;

use DateTimeImmutable;

/**
 * A person the identity provider deleted: no name, email address or credential, only the
 * opaque OAuth subject this application already stores against the configured provider.
 */
final readonly class IdentityTombstone
{
    /**
     * @param  string  $id  the tombstone's identifier, used to acknowledge it
     * @param  string  $provider  the configured `bherila-auth.oauth_client.provider`, the namespace the subject belongs to
     * @param  string  $subject  the exact OAuth `sub`; opaque and case-sensitive, never a number to normalize
     * @param  DateTimeImmutable  $tombstonedAt  when the provider deleted the person (UTC)
     * @param  DateTimeImmutable  $purgeAfter  when the provider may hard-delete its own record regardless of acknowledgements (UTC)
     * @param  DateTimeImmutable|null  $providerPurgedAt  when it did, if it already has (UTC); the tombstone is still owed an acknowledgement
     */
    public function __construct(
        public string $id,
        public string $provider,
        public string $subject,
        public DateTimeImmutable $tombstonedAt,
        public DateTimeImmutable $purgeAfter,
        public ?DateTimeImmutable $providerPurgedAt,
    ) {}
}
