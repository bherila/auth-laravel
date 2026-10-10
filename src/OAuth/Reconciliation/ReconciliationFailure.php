<?php

namespace BWH\Auth\OAuth\Reconciliation;

/**
 * Why a reconciliation request failed, without the transport's own details.
 *
 * Callers translate this into their public exception. It never carries a previous
 * exception, a response body or a credential: transport errors can echo all three.
 *
 * @internal
 */
final class ReconciliationFailure extends \RuntimeException
{
    /** A required oauth_client setting is missing or empty. */
    public const NOT_CONFIGURED = 'not_configured';

    /** The base URL is not HTTPS (or loopback HTTP in local/testing), or carries credentials, a query or a fragment. */
    public const UNTRUSTED_URL = 'untrusted_url';

    /** The request failed in transport or the provider answered with a non-2xx status. */
    public const UNAVAILABLE = 'unavailable';

    /** The body was incomplete, too large, too slow or not a JSON object. */
    public const INVALID = 'invalid';

    /**
     * @param  int|null  $status  the provider's HTTP status, when it answered with a non-2xx one
     * @param  int|null  $retryAfter  a valid Retry-After delay in seconds, when it sent one
     */
    public function __construct(
        public readonly string $reason,
        public readonly ?int $status = null,
        public readonly ?int $retryAfter = null,
    ) {
        parent::__construct('Provider reconciliation request failed: '.$reason.'.');
    }
}
