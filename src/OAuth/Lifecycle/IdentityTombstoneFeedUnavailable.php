<?php

namespace BWH\Auth\OAuth\Lifecycle;

/**
 * The tombstone feed could not be read, or an acknowledgement could not be confirmed.
 *
 * Never carries a credential, a response body or the transport's exception. Nothing is
 * lost by failing: unacknowledged tombstones stay in the feed.
 */
final class IdentityTombstoneFeedUnavailable extends \RuntimeException
{
    public const NOT_CONFIGURED = 'not_configured';

    public const UNTRUSTED_URL = 'untrusted_url';

    public const UNAVAILABLE = 'unavailable';

    /** HTTP 429; {@see $retryAfter} carries the provider's delay when it sent one. */
    public const THROTTLED = 'throttled';

    /** The provider refused the cursor this read passed (HTTP 422); start again without one. */
    public const CURSOR_REJECTED = 'cursor_rejected';

    public const INVALID = 'invalid';

    public function __construct(
        public readonly string $reason,
        string $message,
        public readonly ?int $retryAfter = null,
    ) {
        parent::__construct($message);
    }
}
