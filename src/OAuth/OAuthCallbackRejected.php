<?php

namespace BWH\Auth\OAuth;

use Symfony\Component\HttpKernel\Exception\HttpException;

/**
 * An authorization response refused before its code was exchanged.
 *
 * A 403 like the `abort()` it replaces, so an application that does not catch it renders
 * what it always did. The message is fixed: the reason is in {@see $reason}, and nothing
 * from the response other than a well-formed OAuth error code is kept.
 */
final class OAuthCallbackRejected extends HttpException
{
    /**
     * @param  string|null  $providerError  the server's OAuth `error` code, for
     *                                      {@see OAuthCallbackFailure::AuthorizationDenied}, when well formed
     */
    public function __construct(
        public readonly OAuthCallbackFailure $reason,
        public readonly ?string $providerError = null,
    ) {
        parent::__construct(403, 'The OAuth response could not be verified.');
    }
}
