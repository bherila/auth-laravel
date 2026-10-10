<?php

namespace BWH\Auth\OAuth\Session;

use BWH\Auth\OAuth\OAuthIdentity;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;

/** Explicit consumer integration: never globally enables middleware or local login. */
final readonly class ProviderSession
{
    private const KEY = 'bherila_auth.provider_session';

    public function __construct(
        private ProviderIdentityStatusClient $client,
        private ProviderIdentityPolicy $policy,
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
            if (! config('bherila-auth.provider_identity.enabled', false)) {
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
            || ! is_string($state['name'] ?? null) || ! is_string($state['email'] ?? null)) {
            $this->expire($request);
        }

        if (! $fresh && ProviderIdentityPolicy::isFresh($state['checked_at'])) {
            return new OAuthIdentity($provider, $subject, $state['name'], $state['email'],
                credentialVersion: $state['generation']);
        }

        try {
            // May be answered by an observation another credential of this person made;
            // keeping its time, not now, stops a shared answer from extending freshness.
            $checkedAt = $this->policy->verify($subject, $state['generation'], $fresh);
        } catch (ProviderSessionExpired) {
            $this->expire($request);
        }

        // Keep the login generation immutable. A newer generation ends the old session.
        $state['checked_at'] = $checkedAt;
        $request->session()->put(self::KEY, $state);

        return new OAuthIdentity($provider, $subject, $state['name'], $state['email'],
            credentialVersion: $state['generation']);
    }

    private function expire(Request $request): never
    {
        $request->session()->forget(self::KEY);
        throw new ProviderSessionExpired('The provider session has ended. Sign in again.');
    }
}
