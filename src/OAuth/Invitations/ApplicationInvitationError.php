<?php

namespace BWH\Auth\OAuth\Invitations;

/**
 * Every reason an application-requested invitation call can fail.
 *
 * The provider's own `error` codes keep their wire value and the HTTP status the provider answers
 * them with. The last four cases are this package's: they arise before or around the call, and
 * have no provider status.
 */
enum ApplicationInvitationError: string
{
    case InvalidToken = 'invalid_token';
    case InsufficientScope = 'insufficient_scope';
    case ApplicationNotEnabled = 'application_not_enabled';
    case InvalidActorAssertion = 'invalid_actor_assertion';
    case ReplayedActorAssertion = 'replayed_actor_assertion';
    case ActorNotEligible = 'actor_not_eligible';
    case InvalidRequest = 'invalid_request';
    case InvitationNotFound = 'invitation_not_found';
    case InvitationNotPending = 'invitation_not_pending';
    case InvitationAccepted = 'invitation_accepted';
    case ConcurrentInvitation = 'concurrent_invitation';
    case RateLimited = 'rate_limited';
    case MailUnavailable = 'mail_unavailable';
    case InvalidConfiguration = 'invalid_configuration';
    case ReplayStorageUnavailable = 'replay_storage_unavailable';

    /** A required setting is missing or invalid here; nothing was sent. */
    case NotConfigured = 'not_configured';

    /** The provider's token endpoint refused this application's client credentials or the scope. */
    case TokenRefused = 'token_refused';

    /** The provider could not be reached, or answered with a status this contract does not define. */
    case Unavailable = 'unavailable';

    /** The provider answered, but not in the shape this contract defines. */
    case InvalidResponse = 'invalid_response';

    /** The HTTP status the provider answers this code with; null for this package's own cases. */
    public function status(): ?int
    {
        return match ($this) {
            self::InvalidToken, self::InvalidActorAssertion, self::ReplayedActorAssertion => 401,
            self::InsufficientScope, self::ApplicationNotEnabled, self::ActorNotEligible => 403,
            self::InvitationNotFound => 404,
            self::InvitationNotPending, self::InvitationAccepted, self::ConcurrentInvitation => 409,
            self::InvalidRequest => 422,
            self::RateLimited => 429,
            self::MailUnavailable, self::InvalidConfiguration, self::ReplayStorageUnavailable => 503,
            self::NotConfigured, self::TokenRefused, self::Unavailable, self::InvalidResponse => null,
        };
    }

    /** The provider code for this status and wire value, or null when the pair is not in the contract. */
    public static function fromProvider(int $status, mixed $code): ?self
    {
        $error = is_string($code) ? self::tryFrom($code) : null;

        return $error !== null && $error->status() === $status ? $error : null;
    }
}
