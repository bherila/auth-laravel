<?php

namespace BWH\Auth\OAuth\Invitations;

use RuntimeException;
use SensitiveParameter;

/**
 * A refused or failed application-requested invitation call.
 *
 * Catch a subclass for the kind of failure, and read {@see $error} for the exact reason. The
 * message is fixed per reason: an exception never carries the address, the link, a token, the
 * assertion, a response body or the transport's own exception.
 */
abstract class ApplicationInvitationException extends RuntimeException
{
    /**
     * @param  int|null  $status  the provider's HTTP status, or null when nothing was answered
     * @param  int|null  $retryAfter  the provider's `Retry-After` delay in seconds, when it sent one
     */
    public function __construct(
        public readonly ApplicationInvitationError $error,
        public readonly ?int $status = null,
        public readonly ?int $retryAfter = null,
    ) {
        parent::__construct(self::describe($error));
    }

    /**
     * The exception for a reason, of the class every caller (and the test fake) gets for it.
     *
     * @param  int|null  $status  defaults to the provider's status for the reason
     * @param  'application'|'actor'|'recipient'|null  $limit  which limit, for {@see ApplicationInvitationError::RateLimited}
     * @param  array<string, list<string>>  $errors  messages by field, for {@see ApplicationInvitationError::InvalidRequest}
     */
    public static function for(
        ApplicationInvitationError $error,
        ?int $status = null,
        ?int $retryAfter = null,
        ?string $limit = null,
        #[SensitiveParameter] array $errors = [],
    ): self {
        $status ??= $error->status();

        return match ($error) {
            ApplicationInvitationError::NotConfigured,
            ApplicationInvitationError::TokenRefused,
            ApplicationInvitationError::InvalidToken,
            ApplicationInvitationError::InsufficientScope,
            ApplicationInvitationError::ApplicationNotEnabled,
            ApplicationInvitationError::InvalidActorAssertion,
            ApplicationInvitationError::ReplayedActorAssertion,
            ApplicationInvitationError::InvalidConfiguration => new ApplicationInvitationMisconfigured($error, $status, $retryAfter),
            ApplicationInvitationError::ActorNotEligible => new ApplicationInvitationActorNotEligible($error, $status, $retryAfter),
            ApplicationInvitationError::InvalidRequest => new ApplicationInvitationInvalid($error, $status, $retryAfter, $errors),
            ApplicationInvitationError::InvitationNotFound => new ApplicationInvitationNotFound($error, $status, $retryAfter),
            ApplicationInvitationError::InvitationNotPending,
            ApplicationInvitationError::InvitationAccepted,
            ApplicationInvitationError::ConcurrentInvitation => new ApplicationInvitationConflict($error, $status, $retryAfter),
            ApplicationInvitationError::RateLimited => new ApplicationInvitationRateLimited($error, $status, $retryAfter,
                in_array($limit, ApplicationInvitationRateLimited::LIMITS, true) ? $limit : null),
            ApplicationInvitationError::MailUnavailable,
            ApplicationInvitationError::ReplayStorageUnavailable,
            ApplicationInvitationError::Unavailable,
            ApplicationInvitationError::InvalidResponse => new ApplicationInvitationUnavailable($error, $status, $retryAfter),
        };
    }

    private static function describe(ApplicationInvitationError $error): string
    {
        return match ($error) {
            ApplicationInvitationError::InvalidToken => 'The identity provider refused the invitation client access token.',
            ApplicationInvitationError::InsufficientScope => 'The invitation client access token does not carry the invitation scope.',
            ApplicationInvitationError::ApplicationNotEnabled => 'This application is not enabled for invitations at the identity provider.',
            ApplicationInvitationError::InvalidActorAssertion => 'The identity provider refused the actor assertion.',
            ApplicationInvitationError::ReplayedActorAssertion => 'The identity provider has already seen this actor assertion.',
            ApplicationInvitationError::ActorNotEligible => 'The person asking cannot sign in to this application at the identity provider.',
            ApplicationInvitationError::InvalidRequest => 'The invitation request is not valid.',
            ApplicationInvitationError::InvitationNotFound => 'The identity provider has no such invitation for this application.',
            ApplicationInvitationError::InvitationNotPending => 'Only a pending or expired invitation can be sent again.',
            ApplicationInvitationError::InvitationAccepted => 'The invitation was already accepted.',
            ApplicationInvitationError::ConcurrentInvitation => 'Another invitation to the same address was being created at the same moment.',
            ApplicationInvitationError::RateLimited => 'Too many invitations. Try again later.',
            ApplicationInvitationError::MailUnavailable => 'The identity provider cannot send invitation email.',
            ApplicationInvitationError::InvalidConfiguration => 'The identity provider\'s invitation key configuration for this application is invalid.',
            ApplicationInvitationError::ReplayStorageUnavailable => 'The identity provider could not check the request for replay.',
            ApplicationInvitationError::NotConfigured => 'Application invitations are not configured.',
            ApplicationInvitationError::TokenRefused => 'The identity provider refused this application\'s client credentials for invitations.',
            ApplicationInvitationError::Unavailable => 'The identity provider is unavailable for invitations.',
            ApplicationInvitationError::InvalidResponse => 'The identity provider\'s invitation response is invalid.',
        };
    }
}
