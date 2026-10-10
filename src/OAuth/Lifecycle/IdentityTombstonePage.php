<?php

namespace BWH\Auth\OAuth\Lifecycle;

/** One validated page of the provider's pending tombstone feed. */
final readonly class IdentityTombstonePage
{
    /**
     * @param  list<IdentityTombstone>  $tombstones  oldest first
     * @param  string|null  $nextCursor  opaque; non-null exactly when there are more pages
     */
    public function __construct(
        public array $tombstones,
        public bool $hasMore,
        public ?string $nextCursor,
    ) {}
}
