<?php

namespace BWH\Auth\Invitations;

/**
 * The bearer secret of an invitation link: 32 bytes from the CSPRNG, rendered as 64 lowercase
 * hex characters so it is safe in a URL path without encoding.
 *
 * Only {@see self::digest()} is ever stored. The plaintext exists for the request that issues
 * the invitation, goes into the link handed to the invitee once, and is never written to the
 * database, a log line or a dump: {@see self::__debugInfo()} redacts it, and the constructor
 * marks it sensitive so it is left out of stack traces.
 */
final readonly class InvitationSecret
{
    /** Random bytes per secret: 256 bits, so the space cannot be probed. */
    public const BYTES = 32;

    /**
     * A presented secret longer than this is refused without hashing it. Far above any secret
     * this class issues, so a legacy format with longer tokens still validates.
     */
    public const MAX_PRESENTED_LENGTH = 512;

    private function __construct(#[\SensitiveParameter] public string $plaintext) {}

    /** A fresh secret. */
    public static function generate(): self
    {
        return new self(bin2hex(random_bytes(self::BYTES)));
    }

    /**
     * The stored form of a presented secret: SHA-256, as hex by default or as the 32 raw bytes
     * for a binary column. Hashing the presented value rather than comparing it means a value
     * read out of the database cannot be replayed as a link.
     */
    public static function digestOf(#[\SensitiveParameter] string $presented, InvitationDigest $encoding = InvitationDigest::Hex): string
    {
        return hash('sha256', $presented, $encoding === InvitationDigest::Binary);
    }

    /**
     * Whether a presented value could be a secret at all. An empty or oversized value is refused
     * before it reaches a query, so it matches nothing and costs nothing to reject.
     */
    public static function plausible(#[\SensitiveParameter] string $presented): bool
    {
        return $presented !== '' && strlen($presented) <= self::MAX_PRESENTED_LENGTH;
    }

    /** This secret's stored form. */
    public function digest(InvitationDigest $encoding = InvitationDigest::Hex): string
    {
        return self::digestOf($this->plaintext, $encoding);
    }

    /** @return array{plaintext: string} */
    public function __debugInfo(): array
    {
        return ['plaintext' => '[redacted]'];
    }
}
