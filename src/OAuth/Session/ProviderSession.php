<?php

namespace BWH\Auth\OAuth\Session;

use BWH\Auth\OAuth\OAuthIdentity;
use Illuminate\Auth\SessionGuard;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Str;

/** Explicit consumer integration: never globally enables middleware or local login. */
final readonly class ProviderSession
{
    private const KEY = 'bherila_auth.provider_session';

    /** Request attribute: the remember tokens prepareRememberedLogin() made safe to record. */
    private const PREPARED = 'bherila_auth.provider_remember_prepared';

    public function __construct(
        private ProviderIdentityStatusClient $client,
        private ProviderIdentityPolicy $policy,
        private RememberedProviderLogins $remembered,
    ) {}

    /**
     * Remember the login generation for the guard that just authenticated.
     *
     * When enforcement is enabled, a login whose generation cannot be remembered is
     * undone (logout, new session, new CSRF token) and reported as unavailable, so the
     * application answers 503 and the person retries. When enforcement is off the
     * baseline is still remembered if the provider supplies one, so turning it on later
     * does not end every existing session at once.
     */
    public function establish(Request $request, OAuthIdentity $identity, StatefulGuard $guard): void
    {
        try {
            $this->remember($request, $identity);
        } catch (ProviderSessionExpired|ProviderStatusUnavailable $exception) {
            if (! app(ProviderIdentityEnforcement::class)->enabled()) {
                // A regenerated session keeps its data, so an earlier login's baseline would
                // otherwise stand in for this one once enforcement is enabled.
                $request->session()->forget(self::KEY);

                return;
            }
            $guard->logout();
            $request->session()->invalidate();
            $request->session()->regenerateToken();

            throw new ProviderStatusUnavailable('Provider session verification is unavailable. Sign in again.', previous: $exception);
        }

        $this->recordRememberedLogin($request, $guard);
    }

    /**
     * Call before `$guard->login($user, remember: true)` when the login sets a remember-me
     * cookie, with the baseline the login is about to establish.
     *
     * Laravel keeps one remember token per account, shared by every device. Unless that token
     * is already recorded under exactly this baseline, it is replaced here, so the cookie this
     * login sets carries a new token and every older cookie, issued under some earlier login,
     * stops working. Only a token prepared here is recorded by {@see establish()} or
     * {@see establishObserved()}; any other remembered login records nothing, and its restored
     * sessions are asked to sign in again once enforcement is on.
     */
    public function prepareRememberedLogin(Request $request, StatefulGuard $guard, Authenticatable $user,
        string $provider, string $subject, ?int $generation, ?int $epoch = null): void
    {
        if (! $guard instanceof SessionGuard) {
            return;
        }

        $token = $user->getRememberToken();
        $row = is_string($token) && $token !== ''
            ? $this->remembered->find($guard->getName(), (string) $user->getAuthIdentifier())
            : null;
        $matches = $row !== null && $generation !== null
            && hash_equals((string) $row->token_hash, RememberedProviderLogins::tokenHash((string) $token))
            && $row->provider === $provider && $row->subject === $subject
            && (int) $row->generation === $generation
            && ($row->epoch === null ? null : (int) $row->epoch) === $epoch;
        if (! $matches) {
            $token = Str::random(60);
            $guard->getProvider()->updateRememberToken($user, $token);
        }

        $prepared = $request->attributes->get(self::PREPARED, []);
        $prepared[$guard->getName()] = RememberedProviderLogins::tokenHash((string) $token);
        $request->attributes->set(self::PREPARED, $prepared);
    }

    /**
     * For a sign-in made now through a method other than this provider (a social login, say)
     * of an account bound to it: the provider's current answer for that identity.
     *
     * A fresh status request, so a sign-in through another method cannot outlive the provider
     * disabling, resetting or ungranting the person. With enforcement on, an ended identity
     * throws ProviderSessionExpired (refuse the sign-in) and an unavailable provider throws
     * ProviderStatusUnavailable (answer 503). With enforcement off, both return null and the
     * sign-in proceeds without a baseline.
     */
    public function observe(ProviderBinding $binding): ?ProviderObservation
    {
        try {
            if ($binding->provider !== config('bherila-auth.oauth_client.provider')) {
                throw new ProviderSessionExpired('The provider session binding is invalid.');
            }
            $observation = $this->policy->current($binding->subject);

            return new ProviderObservation($binding->provider, $binding->subject,
                $observation['generation'], $observation['checked_at'], $observation['epoch']);
        } catch (ProviderSessionExpired|ProviderStatusUnavailable $exception) {
            if (! app(ProviderIdentityEnforcement::class)->enabled()) {
                return null;
            }

            throw $exception;
        }
    }

    /**
     * After `$guard->login()` and `session()->regenerate()` for a sign-in observed by
     * {@see observe()}: record its generation as this session's baseline, as {@see establish()}
     * does for a provider sign-in. The generation is the identity's current one because the
     * sign-in is happening now; a later reset, disable or ungrant ends the session.
     */
    public function establishObserved(Request $request, StatefulGuard $guard, ProviderObservation $observation,
        string $name, string $email): void
    {
        $request->session()->put(self::KEY, [
            'context' => $this->client->context(),
            'provider' => $observation->provider,
            'subject' => $observation->subject,
            'generation' => $observation->generation,
            'epoch' => $observation->epoch,
            'checked_at' => $observation->checkedAt,
            'name' => $name,
            'email' => $email,
        ]);

        $this->recordRememberedLogin($request, $guard);
    }

    /**
     * A session the guard just restored from a remember-me cookie: adopt the baseline recorded
     * for that cookie's token, if it was recorded for this binding. Called by the package's
     * Login listener; the adopted baseline is checked freshly on the next protected request.
     * A restored session no longer has the login-time name and email; the identity it reports
     * carries empty strings for them.
     */
    public function restoreRemembered(SessionGuard $guard, Authenticatable $user, ProviderBinding $binding): void
    {
        $token = $user->getRememberToken();
        if (! is_string($token) || $token === '' || $binding->provider !== config('bherila-auth.oauth_client.provider')) {
            return;
        }
        $row = $this->remembered->find($guard->getName(), (string) $user->getAuthIdentifier());
        if ($row === null || ! hash_equals((string) $row->token_hash, RememberedProviderLogins::tokenHash($token))
            || $row->provider !== $binding->provider || $row->subject !== $binding->subject) {
            return;
        }

        $guard->getSession()->put(self::KEY, [
            'context' => $this->client->context(),
            'provider' => $binding->provider,
            'subject' => $binding->subject,
            'generation' => (int) $row->generation,
            'epoch' => $row->epoch === null ? null : (int) $row->epoch,
            // Never fresh: the restored session's first protected request checks the provider.
            'checked_at' => 0,
            'name' => '',
            'email' => '',
        ]);
    }

    /** Record this login's baseline for the remember token prepareRememberedLogin() made safe. */
    private function recordRememberedLogin(Request $request, StatefulGuard $guard): void
    {
        if (! $guard instanceof SessionGuard || ! $guard->getCookieJar()->hasQueued($guard->getRecallerName())) {
            return;
        }
        $prepared = $request->attributes->get(self::PREPARED, [])[$guard->getName()] ?? null;
        $user = $guard->user();
        $state = $request->session()->get(self::KEY);
        $token = $user?->getRememberToken();
        if (! is_string($prepared) || $user === null || ! is_array($state) || ! is_string($token)
            || ! hash_equals($prepared, RememberedProviderLogins::tokenHash($token))) {
            return;
        }

        try {
            $this->remembered->put($guard->getName(), (string) $user->getAuthIdentifier(),
                $state['provider'], $state['subject'], $state['generation'], $prepared, $state['epoch'] ?? null);
        } catch (\Throwable $exception) {
            // Not recording only means this cookie's restored sessions sign in again later.
            report($exception);
        }
    }

    /** Call only after successful callback binding and local authentication. */
    public function remember(Request $request, OAuthIdentity $identity): void
    {
        if ($identity->credentialVersion === null || $identity->credentialVersion < 0) {
            throw new ProviderStatusUnavailable('The provider does not support session generation checks.');
        }
        if ($identity->provider !== config('bherila-auth.oauth_client.provider')) {
            throw new ProviderSessionExpired('The provider session binding is invalid.');
        }

        $request->session()->put(self::KEY, [
            'context' => $this->client->context(),
            'provider' => $identity->provider,
            'subject' => $identity->subject,
            'generation' => $identity->credentialVersion,
            'epoch' => $identity->recoveryEpoch,
            'checked_at' => Carbon::now()->getTimestamp(),
            'name' => $identity->name,
            'email' => $identity->email,
        ]);
    }

    /**
     * Pass binding values from the authenticated local user, never request input.
     * Consumers must catch Expired to end local auth and Unavailable to return 503.
     * Use fresh=true for privileged writes. Application policy still runs separately.
     *
     * The returned identity is the login-time projection remembered at sign-in. A
     * status check confirms liveness and generation only; it never refreshes name or
     * email, because the status endpoint is authenticated by the client credential
     * rather than by the person. Refresh projections from the next login response.
     */
    public function assertActive(Request $request, string $provider, string $subject, bool $fresh = false): OAuthIdentity
    {
        $state = $request->session()->get(self::KEY);
        if (! is_array($state) || ($state['context'] ?? null) !== $this->client->context()
            || ($state['provider'] ?? null) !== $provider || ($state['subject'] ?? null) !== $subject
            || ! is_int($state['generation'] ?? null) || $state['generation'] < 0
            || ! is_int($state['checked_at'] ?? null)
            || ! is_string($state['name'] ?? null) || ! is_string($state['email'] ?? null)
            || ! self::validEpoch($state['epoch'] ?? null)) {
            $this->expire($request);
        }
        // A session from before the provider reported an epoch has none, and is not compared.
        $epoch = $state['epoch'] ?? null;

        if (! $fresh && ProviderIdentityPolicy::isFresh($state['checked_at'])) {
            return new OAuthIdentity($provider, $subject, $state['name'], $state['email'],
                credentialVersion: $state['generation'], recoveryEpoch: $epoch);
        }

        try {
            // May be answered by an observation another credential of this person made;
            // keeping its time, not now, stops a shared answer from extending freshness.
            $checkedAt = $this->policy->verify($subject, $state['generation'], $fresh, $epoch);
        } catch (ProviderSessionExpired) {
            $this->expire($request);
        }

        // Keep the login generation and epoch immutable. A newer generation, or an epoch a
        // restored provider raised, ends the old session.
        $state['checked_at'] = $checkedAt;
        $request->session()->put(self::KEY, $state);

        return new OAuthIdentity($provider, $subject, $state['name'], $state['email'],
            credentialVersion: $state['generation'], recoveryEpoch: $epoch);
    }

    /**
     * The login generation remembered for this binding, without checking the provider.
     * For recording on credentials issued while enforcement is off; never an authorization.
     */
    public function baseline(Request $request, string $provider, string $subject): ?int
    {
        $state = $request->hasSession() ? $request->session()->get(self::KEY) : null;
        if (! is_array($state) || ($state['context'] ?? null) !== $this->client->context()
            || ($state['provider'] ?? null) !== $provider || ($state['subject'] ?? null) !== $subject
            || ! is_int($state['generation'] ?? null) || $state['generation'] < 0) {
            return null;
        }

        return $state['generation'];
    }

    /**
     * The provider recovery epoch remembered with this binding's baseline, without checking
     * the provider. Null when the session has none. For recording on credentials, like
     * baseline(); never an authorization.
     */
    public function epoch(Request $request, string $provider, string $subject): ?int
    {
        if ($this->baseline($request, $provider, $subject) === null) {
            return null;
        }
        $epoch = $request->session()->get(self::KEY)['epoch'] ?? null;

        return is_int($epoch) && $epoch >= 1 ? $epoch : null;
    }

    private static function validEpoch(mixed $epoch): bool
    {
        return $epoch === null || (is_int($epoch) && $epoch >= 1);
    }

    private function expire(Request $request): never
    {
        $request->session()->forget(self::KEY);
        throw new ProviderSessionExpired('The provider session has ended. Sign in again.');
    }
}
