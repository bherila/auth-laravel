<?php

namespace BWH\Auth\OAuth\Invitations;

/**
 * The invitation is not in a state that allows the call (`invitation_not_pending`,
 * `invitation_accepted`), or another invitation to the same address was being created at the same
 * moment (`concurrent_invitation`, which may be tried again).
 */
final class ApplicationInvitationConflict extends ApplicationInvitationException {}
