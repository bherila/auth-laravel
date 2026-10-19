<?php

namespace BWH\Auth\OAuth;

use Symfony\Component\HttpKernel\Exception\HttpException;

/**
 * A token request (code exchange or refresh) that did not return a usable token.
 *
 * A 502, as the `abort()` it replaces. {@see $definitive} says whether the server answered
 * at all: false means the request may have been processed (a dropped connection, a 5xx), so
 * a rotated refresh token may already have replaced the one sent. Never retry a refresh
 * with the old token in that case; treat the grant as needing a new authorization.
 */
final class OAuthTokenRequestFailed extends HttpException
{
    /**
     * @param  string|null  $oauthError  the server's OAuth `error` code (for example `invalid_grant`), when well formed
     */
    public function __construct(
        string $message,
        public readonly ?string $oauthError = null,
        public readonly bool $definitive = true,
    ) {
        parent::__construct(502, $message);
    }
}
