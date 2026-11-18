<?php

namespace BWH\Auth\Invitations;

use DateTimeInterface;

/**
 * Where an invitation stands. Derived from its timestamps and the clock, never stored, so an
 * expiry takes effect without a job.
 *
 * Precedence is fixed: an accepted invitation stays accepted whatever happened after, and a
 * revoked one is never reported as declined or expired, so the record shows the inviter's
 * deliberate action. An invitation lapses at its expiry instant, not after it. A null expiry
 * never lapses.
 */
enum InvitationState: string
{
    case Pending = 'pending';
    case Accepted = 'accepted';
    case Declined = 'declined';
    case Revoked = 'revoked';
    case Expired = 'expired';

    public static function of(
        ?DateTimeInterface $acceptedAt,
        ?DateTimeInterface $declinedAt,
        ?DateTimeInterface $revokedAt,
        ?DateTimeInterface $expiresAt,
        DateTimeInterface $now,
    ): self {
        return match (true) {
            $acceptedAt !== null => self::Accepted,
            $revokedAt !== null => self::Revoked,
            $declinedAt !== null => self::Declined,
            $expiresAt !== null && $expiresAt <= $now => self::Expired,
            default => self::Pending,
        };
    }

    /** Only a pending invitation can be accepted, declined or revoked. */
    public function isOpen(): bool
    {
        return $this === self::Pending;
    }
}
