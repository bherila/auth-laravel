<?php

namespace BWH\Auth\OAuth\Session;

/**
 * An active version-1 status result: liveness, credential generation and, from a provider
 * that reports one, its recovery epoch.
 *
 * The status endpoint is authenticated by a client credential, not by the person,
 * so it deliberately carries no profile data. Name and email come from the
 * bearer-authenticated login identity response.
 */
final readonly class ProviderIdentityStatus
{
    public function __construct(
        public string $subject,
        public int $credentialVersion,
        public ?int $recoveryEpoch = null,
    ) {}
}
