<?php

namespace BWH\Auth\OAuth\Client;

use BWH\Auth\OAuth\IdentityNamespace;
use Illuminate\Cache\DatabaseStore;
use Illuminate\Cache\Lock;
use Illuminate\Cache\Repository;
use Illuminate\Contracts\Cache\LockProvider;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Cache;
use Symfony\Component\HttpKernel\Exception\HttpException;
use Symfony\Component\HttpKernel\Exception\HttpExceptionInterface;
use Throwable;

/**
 * Finite named-flow admission using owner-bound cache lock slots, not a mutable counter.
 * A reservation lasts no longer than the flow; only that state's owner may release it.
 * State is spent before inspecting/releasing a reservation or checking any OAuth binding.
 *
 * @internal
 */
final class PendingFlowCache
{
    private const string STATE_PREFIX = 'bherila-auth:oauth-client:pending-flow:';

    private const string SLOT_PREFIX = 'bherila-auth:oauth-client:pending-slot:';

    /** @param array<string, mixed> $binding */
    public static function store(string $state, array $binding, int $ttl): void
    {
        try {
            [$cache, $store] = self::cache();
            $limit = config('bherila-auth.oauth_client.pending_flow_max_active', 10);
            if (! is_int($limit) || $limit < 1
                || ! IdentityNamespace::valid($binding['identity_namespace'] ?? null)
                || ! is_string($binding['user'] ?? null) || $binding['user'] === ''
                || ! is_string($binding['server'] ?? null) || ! is_int($binding['started_at'] ?? null)) {
                self::unavailable();
            }
            $expires = $binding['started_at'] + $ttl;
            $owner = hash('sha256', $state);
            for ($slot = 0; $slot < $limit; $slot++) {
                $remaining = $expires - Carbon::now()->getTimestamp();
                if ($remaining < 1) {
                    self::unavailable();
                }
                $reservation = self::inspectable($store->lock(self::slotKey($binding, $slot), $remaining, $owner));
                if (! $reservation->get()) {
                    // A backend that fails an add without an existing owner is
                    // unavailable, not evidence that the user's quota is full.
                    if ($reservation->isOwnedBy(null)) {
                        self::unavailable();
                    }

                    continue;
                }
                $possiblyPublished = false;
                try {
                    self::owned($reservation);
                    $remaining = $expires - Carbon::now()->getTimestamp();
                    if ($remaining < 1) {
                        self::unavailable();
                    }
                    // add() may write and then throw. Keep the reservation until
                    // any possibly published state is confirmed deleted.
                    $possiblyPublished = true;
                    if (! $cache->add(self::STATE_PREFIX.$owner, [
                        ...$binding, 'admission_slot' => $slot, 'expires_at' => $expires,
                    ], $remaining)) {
                        $possiblyPublished = false;
                        self::unavailable();
                    }
                    // A slow/outage-delayed publication must not redirect to an
                    // expired or reused reservation. No lease is refreshed here.
                    self::owned($reservation);
                    if (Carbon::now()->getTimestamp() >= $expires) {
                        self::unavailable();
                    }

                    return;
                } catch (Throwable $failure) {
                    // Releasing before deleting an ambiguous write would let
                    // repeated failures accumulate unreserved state entries.
                    try {
                        if (! $possiblyPublished || $cache->forget(self::STATE_PREFIX.$owner)) {
                            $reservation->release();
                        }
                    } catch (Throwable) {
                        // Preserve the fixed outage response, not a cache key/error.
                    }
                    throw $failure;
                }
            }

            throw new HttpException(429, 'Too many pending OAuth connections. Complete one or wait before retrying.', null, [
                'Retry-After' => (string) $ttl, 'Cache-Control' => 'private, no-store',
            ]);
        } catch (HttpExceptionInterface $failure) {
            throw $failure;
        } catch (Throwable) {
            self::unavailable();
        }
    }

    /** @return array<string, mixed>|null */
    public static function pull(string $state): ?array
    {
        try {
            [$cache, $store] = self::cache();
            $owner = hash('sha256', $state);
            $key = self::STATE_PREFIX.$owner;
            $consume = self::inspectable($store->lock($key.':consume', 30));
            if (! $consume->get()) {
                return null;
            }
            try {
                self::owned($consume);
                $binding = $cache->get($key);
                if ($binding === null) {
                    return null;
                }
                self::owned($consume);
                if (! $cache->forget($key)) {
                    self::unavailable();
                }
                self::owned($consume);
                if (! is_array($binding)) {
                    return null;
                }
                // Only genuinely legacy bindings omit all admission metadata.
                // They are accepted later solely in the declared legacy realm.
                if (! array_key_exists('identity_namespace', $binding)
                    && ! array_key_exists('admission_slot', $binding) && ! array_key_exists('expires_at', $binding)) {
                    return $binding;
                }
                if (! IdentityNamespace::valid($binding['identity_namespace'] ?? null)
                    || ! is_string($binding['user'] ?? null) || $binding['user'] === ''
                    || ! is_string($binding['server'] ?? null)
                    || ! is_int($binding['admission_slot'] ?? null) || $binding['admission_slot'] < 0
                    || ! is_int($binding['expires_at'] ?? null)
                    || $binding['expires_at'] <= Carbon::now()->getTimestamp()) {
                    return null;
                }
                $reservation = self::inspectable($store->restoreLock(self::slotKey($binding, $binding['admission_slot']), $owner));
                // Inspect the existing lease; get()/block() would reacquire an
                // expired slot and could make an otherwise stale flow valid.
                if (! $reservation->isOwnedByCurrentProcess()) {
                    return null;
                }
                if (! $reservation->release()) {
                    self::unavailable();
                }

                return $binding['expires_at'] > Carbon::now()->getTimestamp() ? $binding : null;
            } finally {
                if (! $consume->release()) {
                    self::unavailable();
                }
            }
        } catch (HttpExceptionInterface $failure) {
            throw $failure;
        } catch (Throwable) {
            self::unavailable();
        }
    }

    /** @return array{Repository, LockProvider} */
    private static function cache(): array
    {
        $cache = Cache::store(config('bherila-auth.oauth_client.pending_flow_cache_store'));
        $store = $cache->getStore();
        if (! $store instanceof LockProvider) {
            self::unavailable();
        }
        // Cache consumption/reservation release must not roll back with a host
        // transaction after a callback rejection or even a completed exchange.
        if ($store instanceof DatabaseStore
            && ($store->getConnection()->transactionLevel() > 0
                || ($store->getLockConnection() ?? $store->getConnection())->transactionLevel() > 0)) {
            self::unavailable();
        }

        return [$cache, $store];
    }

    /** @param array<string, mixed> $binding */
    private static function slotKey(array $binding, int $slot): string
    {
        // PHP's fixed string tuple encoding preserves even binary local IDs;
        // JSON would silently narrow the existing raw identifier contract.
        return self::SLOT_PREFIX.hash('sha256', serialize([
            $binding['identity_namespace'], $binding['user'], $binding['server'],
        ])).':'.$slot;
    }

    private static function inspectable(mixed $lock): Lock
    {
        if (! $lock instanceof Lock) {
            self::unavailable();
        }

        return $lock;
    }

    private static function owned(Lock $lock): void
    {
        if (! $lock->isOwnedByCurrentProcess()) {
            self::unavailable();
        }
    }

    private static function unavailable(): never
    {
        throw new HttpException(503, 'Pending OAuth connection storage is unavailable. Please retry.', null, [
            'Retry-After' => '30', 'Cache-Control' => 'private, no-store',
        ]);
    }
}
