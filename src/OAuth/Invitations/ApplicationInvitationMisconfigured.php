<?php

namespace BWH\Auth\OAuth\Invitations;

/**
 * The integration with the identity provider is not set up correctly: missing or invalid settings here, refused client
 * credentials, a token or assertion the provider refused, the application not enabled there, or
 * the provider's key configuration. Retrying does not help; an operator has to act.
 */
final class ApplicationInvitationMisconfigured extends ApplicationInvitationException {}
