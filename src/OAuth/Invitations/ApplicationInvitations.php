<?php

namespace BWH\Auth\OAuth\Invitations;

use BWH\Auth\Testing\FakeApplicationInvitations;
use SensitiveParameter;

/**
 * Admission invitations this application asks the identity provider for, to this application's
 * own sign-in client only, with no roles.
 *
 * Resolve this interface from the container. {@see ApplicationInvitationClient} calls the
 * provider; {@see FakeApplicationInvitations} stands in for it in tests.
 *
 * The application decides, before calling, that the actor may invite: the provider relies on that
 * check and verifies only that the actor can sign in to this application. Every call names the
 * actor by their provider subject (the `sub` the provider's user endpoint returned for them).
 */
interface ApplicationInvitations
{
    /**
     * Invite an address. A new invitation supersedes this application's pending one to the same
     * address. The answer is the same whether or not the address has a provider account.
     *
     * @throws ApplicationInvitationException
     * @throws \InvalidArgumentException when the actor subject is not a provider subject
     */
    public function create(string $actorSubject, #[SensitiveParameter] string $email): IssuedInvitation;

    /**
     * Send a pending or expired invitation again, with a new link and expiry; the old link stops
     * working.
     *
     * @throws ApplicationInvitationException
     * @throws \InvalidArgumentException when the actor subject or id is out of range
     */
    public function resend(string $actorSubject, int $invitationId): IssuedInvitation;

    /**
     * Revoke an invitation. Revoking one already revoked answers the same.
     *
     * @throws ApplicationInvitationException
     * @throws \InvalidArgumentException when the actor subject or id is out of range
     */
    public function revoke(string $actorSubject, int $invitationId): RevokedInvitation;
}
