<?php

namespace BWH\Auth\OAuth\DelegatedAccess;

/**
 * What the endpoint holds for one write's `operation_id`: who asked for what, and, once the
 * adapter has answered, the exact answer that was sent.
 */
final readonly class DelegatedReceipt
{
    public function __construct(
        /** {@see DatabaseReceiptStore::actor()} of the actor who sent the write. */
        public string $actor,
        /** {@see DatabaseReceiptStore::requestHash()} of the write. */
        public string $requestHash,
        /** The status that was sent, or null while the write is still being decided. */
        public ?int $status,
        /** The exact body that was sent, or null while the write is still being decided. */
        public ?string $response,
    ) {}

    /** Whether the write was claimed and its answer is not stored yet: running, or interrupted. */
    public function pending(): bool
    {
        return $this->status === null || $this->response === null;
    }
}
