<?php

namespace BWH\Auth\OAuth\Invitations;

/**
 * The person named in the assertion is not an active provider account with a current grant to
 * this application's client.
 */
final class ApplicationInvitationActorNotEligible extends ApplicationInvitationException {}
