<?php

namespace BWH\Auth\OAuth\Client;

use Illuminate\Http\Client\PendingRequest;

/**
 * Optional per-client policy for outgoing requests to a named authorization server.
 *
 * Called with the exact destination after the package sets protocol headers/request defaults,
 * immediately before sending. Return a request with the desired network policy (for example,
 * checked DNS resolution, connection pinning, redirect refusal, timeouts and response-size caps).
 * Throw to refuse a destination: the package never retries through another transport.
 *
 * This hook does not validate hosts itself. Implementations must preserve the supplied protocol
 * headers and must not log request credentials. It is not serialized into pending-flow storage.
 */
interface OAuthHttpTransport
{
    public function prepare(PendingRequest $request, string $url): PendingRequest;
}
