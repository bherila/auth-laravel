<?php

namespace BWH\Auth\OAuth\Client;

use Illuminate\Contracts\Session\Session;
use Illuminate\Support\Carbon;

/**
 * An authorization request this session sent and has not yet seen answered.
 *
 * It records everything the answer is checked against: the server it was sent to (by name
 * and exact issuer), the callback and resource it named, the PKCE verifier, whether `iss`
 * must be present, and who was signed in; and the scope it requested, which is what a token
 * response that omits `scope` was granted (RFC 6749 §5.1). It lives in the session that started it, so a
 * response carried into another browser finds nothing, and it is removed on first use,
 * whatever the outcome, so a response cannot be replayed.
 *
 * Flows to the sign-in provider keep the session keys applications and their tests have
 * always used for the state and verifier, with the rest alongside; flows to other servers
 * are kept by state, so several can be pending at once.
 *
 * @internal
 */
final readonly class PendingFlow
{
    public const string LEGACY_STATE_KEY = 'oauth.login.state';

    public const string LEGACY_VERIFIER_KEY = 'oauth.login.code_verifier';

    public const string LEGACY_BINDING_KEY = 'oauth.login.binding';

    public const string FLOWS_KEY = 'oauth.flows';

    private const int MAX_PENDING = 10;

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

        $flows = $session->get(self::FLOWS_KEY);
        $flows = array_filter(
            is_array($flows) ? $flows : [],
            static fn (mixed $flow): bool => is_array($flow) && is_int($flow['started_at'] ?? null) && ! self::expired($flow['started_at']),
        );
        uasort($flows, static fn (array $a, array $b): int => $a['started_at'] <=> $b['started_at']);
        $flows = array_slice($flows, -(self::MAX_PENDING - 1), null, true);
        $flows[self::key($state)] = $this->binding() + ['verifier' => $this->verifier];

        $session->put(self::FLOWS_KEY, $flows);
    }

    /**
     * Remove and return the flow a response's state names, if this session has one.
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

        $flows = $session->get(self::FLOWS_KEY);
        if (! is_array($flows) || ! array_key_exists(self::key($state), $flows)) {
            return null;
        }

        $binding = $flows[self::key($state)];
        unset($flows[self::key($state)]);
        $session->put(self::FLOWS_KEY, $flows);

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
        return hash('sha256', $state);
    }

    private static function expired(int $startedAt): bool
    {
        $ttl = config('bherila-auth.oauth_client.pending_flow_ttl', 1800);
        $ttl = is_int($ttl) && $ttl > 0 ? $ttl : 1800;

        return Carbon::now()->getTimestamp() - $startedAt > $ttl;
    }
}
