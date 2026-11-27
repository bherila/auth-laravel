<?php

namespace BWH\Auth\OAuth\Session;

/** The provider's current answer for an active identity, from ProviderSession::observe(). */
final readonly class ProviderObservation
{
    public function __construct(
        public string $provider,
        public string $subject,
        public int $generation,
        public int $checkedAt,
        /** The provider's recovery epoch, or null when it reports none. */
        public ?int $epoch = null,
    ) {}
}
