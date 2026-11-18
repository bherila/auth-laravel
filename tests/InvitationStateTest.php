<?php

namespace BWH\Auth\Tests;

use BWH\Auth\Invitations\InvitationState;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;

class InvitationStateTest extends TestCase
{
    public function test_an_invitation_lapses_at_its_expiry_instant(): void
    {
        $now = new DateTimeImmutable('2026-11-18 12:00:00');

        $this->assertSame(InvitationState::Pending, InvitationState::of(null, null, null, $now->modify('+1 second'), $now));
        $this->assertSame(InvitationState::Expired, InvitationState::of(null, null, null, $now, $now), 'It lapses at the expiry instant, not after it.');
        $this->assertSame(InvitationState::Expired, InvitationState::of(null, null, null, $now->modify('-1 second'), $now));
    }

    public function test_a_null_expiry_never_lapses(): void
    {
        $now = new DateTimeImmutable('2126-01-01 00:00:00');

        $this->assertSame(InvitationState::Pending, InvitationState::of(null, null, null, null, $now));
    }

    public function test_precedence_is_accepted_then_revoked_then_declined_then_expired(): void
    {
        $now = new DateTimeImmutable('2026-11-18 12:00:00');
        $earlier = $now->modify('-1 day');
        $later = $now->modify('+1 day');

        $this->assertSame(InvitationState::Accepted, InvitationState::of($earlier, $earlier, $earlier, $earlier, $now));
        $this->assertSame(InvitationState::Revoked, InvitationState::of(null, $earlier, $earlier, $earlier, $now));
        $this->assertSame(InvitationState::Declined, InvitationState::of(null, $earlier, null, $earlier, $now));
        $this->assertSame(InvitationState::Declined, InvitationState::of(null, $earlier, null, $later, $now));
        $this->assertSame(InvitationState::Revoked, InvitationState::of(null, null, $earlier, $later, $now));
        $this->assertSame(InvitationState::Accepted, InvitationState::of($earlier, null, null, null, $now));
    }

    public function test_only_a_pending_invitation_is_open(): void
    {
        foreach (InvitationState::cases() as $state) {
            $this->assertSame($state === InvitationState::Pending, $state->isOpen(), $state->value);
        }
    }

    public function test_stored_values_are_stable(): void
    {
        $this->assertSame(
            ['pending', 'accepted', 'declined', 'revoked', 'expired'],
            array_map(static fn (InvitationState $state): string => $state->value, InvitationState::cases()),
        );
    }
}
