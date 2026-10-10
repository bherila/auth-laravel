<?php

namespace BWH\Auth\OAuth\Session;

use Illuminate\Http\JsonResponse;

final class ProviderStatusUnavailable extends \RuntimeException
{
    /**
     * Uncaught (a bearer request, a token exchange), this is a retryable refusal: the
     * credential is kept and nothing protected runs. Callers that catch it decide for
     * themselves, as the browser middleware does.
     */
    public function render(): JsonResponse
    {
        return new JsonResponse(
            ['error' => 'temporarily_unavailable', 'message' => 'Sign-in verification is temporarily unavailable. Please retry.'],
            503,
            ['Retry-After' => '30', 'Cache-Control' => 'private, no-store'],
        );
    }
}
