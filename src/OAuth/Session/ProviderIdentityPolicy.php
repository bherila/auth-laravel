<?php

namespace BWH\Auth\OAuth\Session;

use Illuminate\Contracts\Cache\Factory as CacheFactory;
use Illuminate\Contracts\Cache\LockProvider;
use Illuminate\Contracts\Cache\LockTimeoutException;
use Illuminate\Contracts\Cache\Repository;
use Illuminate\Support\Carbon;

/**
 * Whether a provider identity may still act through a credential established at
 * a given generation, independent of what kind of credential that is.
 *
 * Browser sessions and bearer tokens share one observation per provider context
 * and subject, so a person with several sessions and agent connections costs one
 * status request per freshness window rather than one per credential. The
 * provider throttles the status endpoint per client; widening freshness to hide
 * that would weaken offboarding, so capacity comes from sharing instead.
 *
 * The baseline is always the generation recorded when the credential was
 * established. An observation never replaces it: a newer generation ends the
 * older credential rather than being adopted by it.
 */
final readonly class ProviderIdentityPolicy
{
    /** A successful check is fresh for strictly less than this many seconds. */
    public const FRESHNESS_SECONDS = 300;

    public function __construct(
        private ProviderIdentityStatusClient $client,
        private CacheFactory $cache,
    ) {}

    /**
     * Throws ProviderSessionExpired when the identity is inactive or its generation
     * differs from the baseline, and ProviderStatusUnavailable when no sufficiently
     * fresh answer can be obtained. Returns the time of the observation relied on,
     * which callers keep instead of "now" so a shared answer never extends freshness.
     */
    public function verify(string $subject, int $baseline, bool $fresh = false): int
    {
        if ($baseline < 0) {
            throw new ProviderSessionExpired('The provider credential baseline is invalid.');
        }

        $observation = $fresh ? null : $this->cached($subject);
        $observation ??= $this->refresh($subject, $fresh);

        if ($observation['generation'] !== $baseline) {
            throw new ProviderSessionExpired('The provider identity is no longer active for this credential.');
        }

        return $observation['checked_at'];
    }

    /** Whether an observation made at this time is still fresh. Clock rollback is never fresh. */
    public static function isFresh(int $checkedAt): bool
    {
        $now = Carbon::now()->getTimestamp();

        return $checkedAt <= $now && $now - $checkedAt < self::FRESHNESS_SECONDS;
    }

    /**
     * Ask the provider, one caller per subject at a time.
     *
     * Without the lock, every worker that saw the same expired entry would ask at once,
     * and a slow, older answer could overwrite a newer one. A caller that waited re-reads
     * the entry first, so a burst costs one request; a fresh check always asks, but still
     * in turn, so its newer answer is the one kept.
     *
     * @return array{generation: int|null, checked_at: int}
     */
    private function refresh(string $subject, bool $fresh): array
    {
        $ask = function () use ($subject, $fresh): array {
            $observation = $fresh ? null : $this->cached($subject);
            if ($observation !== null) {
                return $observation;
            }
            $status = $this->client->status($subject);
            $observation = ['generation' => $status?->credentialVersion, 'checked_at' => Carbon::now()->getTimestamp()];
            // A store may report a failed write by returning false rather than throwing; an
            // observation nobody else can read would make every caller ask again.
            if (! $this->cache(fn (Repository $store) => $store->put($this->key($subject), $observation, self::FRESHNESS_SECONDS))) {
                throw new ProviderStatusUnavailable('Provider status verification is unavailable.');
            }

            return $observation;
        };

        $store = $this->cache(fn (Repository $store) => $store);
        if (! $store->getStore() instanceof LockProvider) {
            // Without a lock, concurrent refreshes return, and a late older answer could
            // overwrite a disable for the whole window.
            throw new ProviderStatusUnavailable('Provider identity enforcement needs a cache store that supports locks.');
        }
        try {
            // Longer than one status request's own deadline, so a waiting caller normally
            // gets the answer instead of timing out behind a request still in flight.
            return $store->lock($this->key($subject).':refresh', 10)->block(6, $ask);
        } catch (LockTimeoutException $exception) {
            throw new ProviderStatusUnavailable('Provider status verification is busy. Please retry.', previous: $exception);
        } catch (ProviderSessionExpired|ProviderStatusUnavailable $exception) {
            throw $exception;
        } catch (\Throwable $exception) {
            throw new ProviderStatusUnavailable('Provider status verification is unavailable.', previous: $exception);
        }
    }

    /**
     * Run a cache operation, reporting a failing store as unavailable verification: an
     * outage of the shared store must refuse protected work retryably, never authorize it
     * and never surface as an arbitrary error.
     *
     * @template T
     *
     * @param  \Closure(Repository): T  $operation
     * @return T
     */
    private function cache(\Closure $operation): mixed
    {
        try {
            return $operation($this->cache->store(config('bherila-auth.provider_identity.cache_store')));
        } catch (\Throwable $exception) {
            throw new ProviderStatusUnavailable('Provider status verification is unavailable.', previous: $exception);
        }
    }

    /** @return array{generation: int|null, checked_at: int}|null */
    private function cached(string $subject): ?array
    {
        $value = $this->cache(fn (Repository $store) => $store->get($this->key($subject)));
        if (! is_array($value) || ! array_key_exists('generation', $value)
            || ! (is_int($value['generation']) || $value['generation'] === null)
            || ! is_int($value['checked_at'] ?? null) || ! self::isFresh($value['checked_at'])) {
            return null;
        }

        return ['generation' => $value['generation'], 'checked_at' => $value['checked_at']];
    }

    private function key(string $subject): string
    {
        // Pinned to the configured provider and client, so a configuration change
        // never reuses an answer obtained for a different one.
        return 'bherila_auth:provider_identity:'.$this->client->context().':'.hash('sha256', $subject);
    }
}
