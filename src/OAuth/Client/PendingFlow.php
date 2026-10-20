<?php

namespace BWH\Auth\OAuth\Client;

use Illuminate\Cache\Repository;
use Illuminate\Contracts\Cache\LockProvider;
use Illuminate\Contracts\Session\Session;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Cache;

/**
 * An authorization request that has not yet been answered.
 *
 * It records the server and exact issuer, callback, resource, PKCE verifier, required `iss`,
 * signed-in person, start time and requested scope. Named-server flows live in the configured
 * cache independently of session saves, and are consumed under a cache lock before any check
 * or token exchange. Sign-in flows retain their legacy session keys and behavior.
 *
 * @internal
 */
final readonly class PendingFlow
{
    public const string LEGACY_STATE_KEY = 'oauth.login.state';

    public const string LEGACY_VERIFIER_KEY = 'oauth.login.code_verifier';

    public const string LEGACY_BINDING_KEY = 'oauth.login.binding';

    private const string CACHE_PREFIX = 'bherila-auth:oauth-client:pending-flow:';

    public function __construct(
        public string $server,
        public string $issuer,
        public string $callback,
        public ?string $resource,
        public string $verifier,
        public bool $issuerRequired,
        public bool $userBound,
        public ?string $user,
        public ?int $startedAt,
        public ?string $scope = null,
    ) {}

    public function store(Session $session, string $state): void
    {
        if ($this->server === AuthorizationServer::DEFAULT) {
            $session->put([
                self::LEGACY_STATE_KEY => $state,
                self::LEGACY_VERIFIER_KEY => $this->verifier,
                self::LEGACY_BINDING_KEY => $this->binding(),
            ]);

            return;
        }

        self::cache()->put(self::key($state), $this->binding() + ['verifier' => $this->verifier], self::ttl());
    }

    /**
     * Consume a named-server cache entry, or the sign-in provider's legacy session flow.
     *
     * For the sign-in provider, a session holding only the legacy state and verifier (one
     * started before this binding existed, or seeded by an application's test) yields a
     * flow with no user or start time recorded; `$unbound` supplies the rest from the
     * current configuration.
     *
     * @param  callable(string $verifier): self  $unbound
     */
    public static function pull(Session $session, string $server, mixed $state, callable $unbound): ?self
    {
        if ($server === AuthorizationServer::DEFAULT) {
            $expected = $session->pull(self::LEGACY_STATE_KEY);
            $verifier = $session->pull(self::LEGACY_VERIFIER_KEY);
            $binding = $session->pull(self::LEGACY_BINDING_KEY);

            if (! is_string($expected) || ! is_string($state) || ! hash_equals($expected, $state)
                || ! is_string($verifier) || $verifier === '') {
                return null;
            }

            return $binding === null ? $unbound($verifier) : self::fromBinding($binding, $verifier);
        }

        if (! is_string($state) || $state === '') {
            return null;
        }

        $cache = self::cache();
        $store = $cache->getStore();
        abort_unless($store instanceof LockProvider, 503, 'Named OAuth flows require a cache store with atomic locks.');
        // Repository::pull may use get followed by forget; a competing callback must not
        // read the same binding between those operations, even when it later fails a check.
        $key = self::key($state);
        $binding = $store->lock($key.':consume', 10)->get(fn (): mixed => $cache->pull($key));

        return is_array($binding) ? self::fromBinding($binding, $binding['verifier'] ?? null) : null;
    }

    public function isExpired(): bool
    {
        return $this->startedAt !== null && self::expired($this->startedAt);
    }

    /** @return array<string, mixed> */
    private function binding(): array
    {
        return [
            'server' => $this->server,
            'issuer' => $this->issuer,
            'callback' => $this->callback,
            'resource' => $this->resource,
            'issuer_required' => $this->issuerRequired,
            'user' => $this->user,
            'started_at' => $this->startedAt,
            'scope' => $this->scope,
        ];
    }

    private static function fromBinding(mixed $binding, mixed $verifier): ?self
    {
        if (! is_array($binding)
            || ! is_string($binding['server'] ?? null)
            || ! is_string($binding['issuer'] ?? null)
            || ! is_string($binding['callback'] ?? null)
            || ! (is_string($binding['resource'] ?? null) || ($binding['resource'] ?? null) === null)
            || ! is_bool($binding['issuer_required'] ?? null)
            || ! (is_string($binding['user'] ?? null) || ($binding['user'] ?? null) === null)
            || ! is_int($binding['started_at'] ?? null)
            || ! (is_string($binding['scope'] ?? null) || ($binding['scope'] ?? null) === null)
            || ! is_string($verifier) || $verifier === '') {
            return null;
        }

        return new self(
            server: $binding['server'],
            issuer: $binding['issuer'],
            callback: $binding['callback'],
            resource: $binding['resource'],
            verifier: $verifier,
            issuerRequired: $binding['issuer_required'],
            userBound: true,
            user: $binding['user'],
            startedAt: $binding['started_at'],
            scope: $binding['scope'] ?? null,
        );
    }

    private static function key(string $state): string
    {
        return self::CACHE_PREFIX.hash('sha256', $state);
    }

    private static function cache(): Repository
    {
        return Cache::store(config('bherila-auth.oauth_client.pending_flow_cache_store'));
    }

    private static function ttl(): int
    {
        $ttl = config('bherila-auth.oauth_client.pending_flow_ttl', 1800);

        return is_int($ttl) && $ttl > 0 ? $ttl : 1800;
    }

    private static function expired(int $startedAt): bool
    {
        return Carbon::now()->getTimestamp() - $startedAt > self::ttl();
    }
}
