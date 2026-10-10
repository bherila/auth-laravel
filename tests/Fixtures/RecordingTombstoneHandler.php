<?php

namespace BWH\Auth\Tests\Fixtures;

use BWH\Auth\OAuth\Lifecycle\IdentityTombstone;
use BWH\Auth\OAuth\Lifecycle\IdentityTombstoneHandler;

/** Records the tombstones it "deleted"; fails for chosen ids with a message naming the subject. */
final class RecordingTombstoneHandler implements IdentityTombstoneHandler
{
    /** @var list<IdentityTombstone> */
    public array $handled = [];

    /** @var array<string, true> */
    public array $failing = [];

    /** @var (\Closure(IdentityTombstone): void)|null */
    public ?\Closure $during = null;

    public function handle(IdentityTombstone $tombstone): void
    {
        if ($this->during !== null) {
            ($this->during)($tombstone);
        }
        if (isset($this->failing[$tombstone->id])) {
            throw new \RuntimeException('Local deletion failed for subject '.$tombstone->subject);
        }
        $this->handled[] = $tombstone;
    }

    /** @return list<string> */
    public function ids(): array
    {
        return array_map(static fn (IdentityTombstone $tombstone): string => $tombstone->id, $this->handled);
    }
}
