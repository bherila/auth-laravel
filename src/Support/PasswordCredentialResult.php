<?php

namespace BWH\Auth\Support;

use Illuminate\Contracts\Auth\Authenticatable;

/** Credential preflight only; a verified result is not an authenticated session. */
final readonly class PasswordCredentialResult
{
    private function __construct(
        public PasswordCredentialStatus $status,
        public ?Authenticatable $user,
    ) {}

    public static function verified(Authenticatable $user): self
    {
        return new self(PasswordCredentialStatus::Verified, $user);
    }

    public static function invalid(?Authenticatable $user = null): self
    {
        return new self(PasswordCredentialStatus::InvalidCredentials, $user);
    }

    public static function disabled(Authenticatable $user): self
    {
        return new self(PasswordCredentialStatus::AccountDisabled, $user);
    }
}
