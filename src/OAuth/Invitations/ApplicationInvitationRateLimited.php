<?php

namespace BWH\Auth\OAuth\Invitations;

/**
 * The provider's invitation rate limits refused the call (`rate_limited`, HTTP 429).
 *
 * {@see $limit} names the limit when the provider said which: `application` (per calling client),
 * `actor` (per person asking) or `recipient` (per address). It is null for the provider's coarse
 * per-address request throttle. {@see $retryAfter} is the provider's delay in seconds, when sent.
 */
final class ApplicationInvitationRateLimited extends ApplicationInvitationException
{
    public const LIMITS = ['application', 'actor', 'recipient'];

    /** @param  'application'|'actor'|'recipient'|null  $limit */
    public function __construct(
        ApplicationInvitationError $error,
        ?int $status = null,
        ?int $retryAfter = null,
        public readonly ?string $limit = null,
    ) {
        parent::__construct($error, $status, $retryAfter);
    }
}
