<?php

namespace BWH\Auth\OAuth\Invitations;

/**
 * The provider could not serve the call: it was unreachable, answered outside the contract, cannot
 * send mail, or could not record the assertion for replay. Nothing is known to have changed.
 */
final class ApplicationInvitationUnavailable extends ApplicationInvitationException {}
