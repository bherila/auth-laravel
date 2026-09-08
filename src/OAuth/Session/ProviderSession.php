<?php

namespace BWH\Auth\OAuth\Session;

use BWH\Auth\OAuth\OAuthIdentity;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;

/** Explicit consumer integration: never globally enables middleware or local login. */
final readonly class ProviderSession
{
    private const KEY = 'bherila_auth.provider_session';

    public function __construct(private ProviderIdentityStatusClient $client) {}

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

        $now = Carbon::now()->getTimestamp();
        if (! $fresh && $state['checked_at'] <= $now && $now - $state['checked_at'] < 300) {
            return new OAuthIdentity($provider, $subject, $state['name'], $state['email'],
                credentialVersion: $state['generation']);
        }

        $identity = $this->client->status($subject);
        if ($identity === null || $identity->credentialVersion !== $state['generation']) {
            $this->expire($request);
        }

        // Keep the login generation immutable. A newer generation ends the old session.
        $state['checked_at'] = $now;
        $state['name'] = $identity->name;
        $state['email'] = $identity->email;
        $request->session()->put(self::KEY, $state);

        return $identity;
    }

    private function expire(Request $request): never
    {
        $request->session()->forget(self::KEY);
        throw new ProviderSessionExpired('The provider session has ended. Sign in again.');
    }
}
