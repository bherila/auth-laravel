<?php

namespace BWH\Auth\OAuth\Server;

/** Immutable authority captured before grant validation/persistence can stall. */
final readonly class CredentialIssueContext
{
    public function __construct(public int $sequence, public ?string $lineageId) {}
}
