<?php

namespace BWH\Auth\OAuth\Session;

use Illuminate\Contracts\Cache\Factory as CacheFactory;
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
        if ($observation === null) {
            $status = $this->client->status($subject);
            $observation = ['generation' => $status?->credentialVersion, 'checked_at' => Carbon::now()->getTimestamp()];
            $this->store()->put($this->key($subject), $observation, self::FRESHNESS_SECONDS);
        }

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

    /** @return array{generation: int|null, checked_at: int}|null */
    private function cached(string $subject): ?array
    {
        $value = $this->store()->get($this->key($subject));
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

    private function store(): Repository
    {
        return $this->cache->store(config('bherila-auth.provider_identity.cache_store'));
    }
}
