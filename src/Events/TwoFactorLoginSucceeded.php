<?php

namespace BWH\Auth\Events;

use BWH\Auth\Models\TwoFactorAttempt;
use Illuminate\Contracts\Auth\Authenticatable;

/** An emailed code was verified and the person is now signed in. */
class TwoFactorLoginSucceeded
{
    public function __construct(
        public readonly Authenticatable $user,
        public readonly TwoFactorAttempt $attempt,
    ) {}
}
