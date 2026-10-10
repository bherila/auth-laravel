<?php

namespace BWH\Auth\OAuth\DelegatedAccess;

/**
 * The verified delegated access request, for the duration of one adapter call.
 *
 * Bound in the container while the controller invokes the application's
 * {@see ApplicationAccessAdapter}, so an adapter can take it by constructor
 * injection without a signature change: record `jti` with its transactional
 * audit to correlate the provider's attempt and result records, and resolve
 * `subject` only within `issuer`'s binding namespace. `jti` is a single-use
 * request nonce, not a stable identifier for retrying a mutation; a write's
 * `operationId` is that identifier, the same on every attempt of one action.
 */
final readonly class DelegatedRequestContext
{
    public function __construct(
        public string $issuer,
        public string $subject,
        public string $application,
        public string $jti,
        /** Null until the verified body has been parsed. */
        public ?string $operation,
        /** A write's `operation_id`, stable across retries of one action; null for a read. */
        public ?string $operationId = null,
    ) {}

    public function withOperation(string $operation, ?string $operationId = null): self
    {
        return new self($this->issuer, $this->subject, $this->application, $this->jti, $operation, $operationId);
    }
}
