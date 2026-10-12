<?php

namespace BWH\Auth\Tests\Feature;

use BWH\Auth\OAuth\Invitations\ApplicationInvitationConflict;
use BWH\Auth\OAuth\Invitations\ApplicationInvitationError;
use BWH\Auth\OAuth\Invitations\ApplicationInvitationException;
use BWH\Auth\OAuth\Invitations\ApplicationInvitationInvalid;
use BWH\Auth\OAuth\Invitations\ApplicationInvitationNotFound;
use BWH\Auth\OAuth\Invitations\ApplicationInvitationRateLimited;
use BWH\Auth\OAuth\Invitations\ApplicationInvitations;
use BWH\Auth\OAuth\Invitations\ApplicationInvitationUnavailable;
use BWH\Auth\OAuth\Invitations\IssuedInvitation;
use BWH\Auth\OAuth\Invitations\RevokedInvitation;
use BWH\Auth\Testing\FakeApplicationInvitations;
use BWH\Auth\Tests\TestCase;
use Illuminate\Support\Facades\Http;
use PHPUnit\Framework\AssertionFailedError;

class FakeApplicationInvitationsTest extends TestCase
{
    private FakeApplicationInvitations $fake;

    protected function setUp(): void
    {
        parent::setUp();
        Http::preventStrayRequests();
        $this->travelTo(new \DateTimeImmutable('2026-10-12T12:00:00Z'));
        $this->fake = FakeApplicationInvitations::swap();
    }

    private function invitations(): ApplicationInvitations
    {
        return app(ApplicationInvitations::class);
    }

    public function test_swap_binds_the_fake_for_the_application(): void
    {
        $this->assertSame($this->fake, $this->invitations());
    }

    public function test_create_returns_a_pending_invitation_with_a_link_and_records_the_call(): void
    {
        $issued = $this->invitations()->create('42', 'Person@Example.test');

        $this->assertSame(1, $issued->id);
        $this->assertSame('pending', $issued->status);
        $this->assertSame('2026-10-19T12:00:00+00:00', $issued->expiresAt->format(DATE_ATOM));
        $this->assertStringStartsWith(FakeApplicationInvitations::LINK_BASE, $issued->link());
        $this->assertTrue($issued->emailSent);
        $this->assertSame([['operation' => 'create', 'actor' => '42', 'email' => 'Person@Example.test', 'invitation_id' => null, 'result' => $issued, 'error' => null]],
            $this->fake->calls());
        $this->fake->assertCreated('Person@Example.test', actor: '42');
        $this->fake->assertRequestCount(1);
    }

    public function test_a_new_invitation_supersedes_the_pending_one_to_the_same_address(): void
    {
        $first = $this->invitations()->create('42', 'person@example.test');
        $other = $this->invitations()->create('42', 'other@example.test');
        $second = $this->invitations()->create('7', 'PERSON@example.test');

        $this->assertNotSame($first->id, $second->id);
        $this->assertSame('revoked', $this->fake->invitation($first->id)['status']);
        $this->assertSame('pending', $this->fake->invitation($other->id)['status']);
        $this->assertSame('pending', $this->fake->invitation($second->id)['status']);
    }

    public function test_resend_issues_a_new_link_and_expiry_and_allows_an_expired_invitation(): void
    {
        $issued = $this->invitations()->create('42', 'person@example.test');
        $this->travelTo(new \DateTimeImmutable('2026-10-20T12:00:00Z'));
        $this->assertSame('expired', $this->fake->invitation($issued->id)['status']);

        $resent = $this->invitations()->resend('42', $issued->id);

        $this->assertSame($issued->id, $resent->id);
        $this->assertNotSame($issued->link(), $resent->link());
        $this->assertSame('2026-10-27T12:00:00+00:00', $resent->expiresAt->format(DATE_ATOM));
        $this->fake->assertResent($issued->id, actor: '42');
    }

    public function test_the_provider_refusals_for_resend_and_revoke(): void
    {
        $this->assertInstanceOf(ApplicationInvitationNotFound::class, $this->refusal(fn () => $this->invitations()->resend('42', 9)));
        $this->assertInstanceOf(ApplicationInvitationNotFound::class, $this->refusal(fn () => $this->invitations()->revoke('42', 9)));

        $revoked = $this->invitations()->create('42', 'person@example.test');
        $this->assertEquals(new RevokedInvitation($revoked->id, 'revoked'), $this->invitations()->revoke('42', $revoked->id));
        $this->assertEquals(new RevokedInvitation($revoked->id, 'revoked'), $this->invitations()->revoke('42', $revoked->id));
        $refused = $this->refusal(fn () => $this->invitations()->resend('42', $revoked->id));
        $this->assertInstanceOf(ApplicationInvitationConflict::class, $refused);
        $this->assertSame(ApplicationInvitationError::InvitationNotPending, $refused->error);

        $accepted = $this->invitations()->create('42', 'other@example.test');
        $this->fake->accept($accepted->id);
        $this->assertSame(ApplicationInvitationError::InvitationAccepted, $this->refusal(fn () => $this->invitations()->revoke('42', $accepted->id))->error);
        $this->assertSame(ApplicationInvitationError::InvitationNotPending, $this->refusal(fn () => $this->invitations()->resend('42', $accepted->id))->error);
        $this->assertSame('accepted', $this->fake->invitation($accepted->id)['status']);
    }

    public function test_an_invalid_address_is_refused_as_the_provider_and_client_refuse_it(): void
    {
        $provider = $this->refusal(fn () => $this->invitations()->create('42', 'not-an-address'));
        $this->assertInstanceOf(ApplicationInvitationInvalid::class, $provider);
        $this->assertSame(422, $provider->status);
        $this->assertArrayHasKey('email', $provider->errors);

        $local = $this->refusal(fn () => $this->invitations()->create('42', ''));
        $this->assertInstanceOf(ApplicationInvitationInvalid::class, $local);
        $this->assertNull($local->status);

        $this->expectException(\InvalidArgumentException::class);
        $this->invitations()->create('042', 'person@example.test');
    }

    public function test_refusals_are_scripted_per_operation_with_the_client_exception(): void
    {
        $this->fake->refuseNext('create', ApplicationInvitationError::RateLimited, retryAfter: 60, limit: 'actor')
            ->refuseNext('create', ApplicationInvitationError::MailUnavailable);

        $limited = $this->refusal(fn () => $this->invitations()->create('42', 'person@example.test'));
        $this->assertInstanceOf(ApplicationInvitationRateLimited::class, $limited);
        $this->assertSame([429, 'actor', 60], [$limited->status, $limited->limit, $limited->retryAfter]);
        $this->assertInstanceOf(ApplicationInvitationUnavailable::class, $this->refusal(fn () => $this->invitations()->create('42', 'person@example.test')));
        // The script is spent: the in-memory provider answers again.
        $this->assertSame(1, $this->invitations()->create('42', 'person@example.test')->id);

        $this->assertSame([ApplicationInvitationError::RateLimited, ApplicationInvitationError::MailUnavailable, null],
            array_column($this->fake->calls('create'), 'error'));
        $this->fake->assertCreated('person@example.test');
    }

    public function test_responses_and_exceptions_can_be_scripted(): void
    {
        $issued = new IssuedInvitation(99, 'pending', new \DateTimeImmutable('2026-10-19T00:00:00Z'), 'https://identity.example.test/invitations/x', false);
        $custom = ApplicationInvitationException::for(ApplicationInvitationError::Unavailable, 502);
        $this->fake->respondNext('resend', $issued)->refuseNext('revoke', $custom);

        $this->assertSame($issued, $this->invitations()->resend('42', 99));
        $this->assertSame($custom, $this->refusal(fn () => $this->invitations()->revoke('42', 99)));

        $this->expectException(\InvalidArgumentException::class);
        $this->fake->respondNext('revoke', $issued);
    }

    public function test_assertions_fail_when_the_call_did_not_happen(): void
    {
        $this->fake->assertNothingRequested();
        $this->fake->assertNotCreated();
        $this->fake->refuseNext('create', ApplicationInvitationError::ConcurrentInvitation);
        $this->refusal(fn () => $this->invitations()->create('42', 'person@example.test'));
        // A refused create is recorded but is not a creation.
        $this->fake->assertNotCreated('person@example.test');

        foreach ([
            fn () => $this->fake->assertCreated('person@example.test'),
            fn () => $this->fake->assertResent(1),
            fn () => $this->fake->assertRevoked(1),
            fn () => $this->fake->assertNothingRequested(),
        ] as $assertion) {
            try {
                $assertion();
                $this->fail('The assertion passed without the call.');
            } catch (AssertionFailedError $failed) {
                $this->assertStringNotContainsString('The assertion passed', $failed->getMessage());
            }
        }
    }

    public function test_the_fake_sends_nothing(): void
    {
        $this->invitations()->create('42', 'person@example.test');

        Http::assertNothingSent();
    }

    private function refusal(\Closure $call): ApplicationInvitationException
    {
        try {
            $call();
        } catch (ApplicationInvitationException $refused) {
            return $refused;
        }
        $this->fail('The call was not refused.');
    }
}
