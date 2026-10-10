<?php

namespace BWH\Auth\OAuth\Session;

use Illuminate\Http\JsonResponse;

final class ProviderSessionExpired extends \RuntimeException
{
    /** Uncaught, the provider identity can no longer act through this credential. */
    public function render(): JsonResponse
    {
        return new JsonResponse(
            ['error' => 'invalid_token', 'message' => 'Your sign-in has ended. Sign in again.'],
            401,
            ['Cache-Control' => 'private, no-store'],
        );
    }
}
