<?php

namespace BWH\Auth\OAuth\DelegatedAccess;

use Illuminate\Cache\DatabaseStore;
use Illuminate\Cache\RedisStore;
use Illuminate\Cache\Repository;

final readonly class CacheNonceStore implements NonceStore
{
    public function __construct(private Repository $cache) {}

    public function consume(string $key, int $seconds): bool
    {
        // Repository::add falls back to non-atomic get/put for other stores.
        // Array/process-local caches cannot enforce replay exclusion across requests.
        $store = $this->cache->getStore();
        if (! $store instanceof DatabaseStore && ! $store instanceof RedisStore) {
            throw new DelegatedAccessException('replay_storage_unavailable');
        }

        return $this->cache->add('delegated-access:'.$key, true, $seconds);
    }
}
