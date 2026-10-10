<?php

namespace BWH\Auth\OAuth\Credentials;

use Illuminate\Http\JsonResponse;

final class CredentialOwnerRefused extends \RuntimeException
{
    /** Uncaught (issuing a code or token), the account may not hold credentials. */
    public function render(): JsonResponse
    {
        return new JsonResponse(
            ['error' => 'access_denied', 'message' => 'This account cannot hold API credentials.'],
            403,
            ['Cache-Control' => 'private, no-store'],
        );
    }
}
