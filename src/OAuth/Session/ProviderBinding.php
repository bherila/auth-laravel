<?php

namespace BWH\Auth\OAuth\Session;

/** The provider and opaque subject a local account is bound to. Never derived from email. */
final readonly class ProviderBinding
{
    public function __construct(
        public string $provider,
        public string $subject,
    ) {}
}
