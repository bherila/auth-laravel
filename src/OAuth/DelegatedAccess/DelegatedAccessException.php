<?php

namespace BWH\Auth\OAuth\DelegatedAccess;

use RuntimeException;

final class DelegatedAccessException extends RuntimeException
{
    public function __construct(public readonly string $outcome, public readonly int $status = 503)
    {
        parent::__construct('Delegated application access: '.$outcome.'.');
    }
}
