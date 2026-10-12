<?php

namespace BWH\Auth\Tests\Fixtures\IdentityProvider;

use Illuminate\Http\JsonResponse;
use RuntimeException;

/**
 * A refused application-requested invitation call: a stable `error` code, its HTTP status, and a
 * fixed message. Nothing was changed. Never carries the request, the address or a credential.
 */
final class ApplicationInvitationRefused extends RuntimeException
{
    /**
     * @param  array<string, mixed>  $details  extra response members, such as `limit` or `errors`
     * @param  array<string, string>  $headers
     */
    public function __construct(
        public readonly string $error,
        public readonly int $status,
        string $message,
        public readonly array $details = [],
        public readonly array $headers = [],
    ) {
        parent::__construct($message);
    }

    public function render(): JsonResponse
    {
        return response()->json(['error' => $this->error, 'message' => $this->getMessage(), ...$this->details], $this->status,
            ['Cache-Control' => 'no-store', ...$this->headers]);
    }
}
