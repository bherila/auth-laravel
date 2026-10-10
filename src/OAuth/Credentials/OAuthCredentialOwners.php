<?php

namespace BWH\Auth\OAuth\Credentials;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Laravel\Passport\Passport;
use RuntimeException;

/**
 * The owners of the OAuth credentials this application issues: resolving them for a
 * stored credential, the optional CredentialOwnerPolicy, and revoking an owner's
 * credentials outright.
 */
final class OAuthCredentialOwners
{
    /** The account a stored credential belongs to, through the bearer guard's user provider. */
    public function find(string|int $userId): ?Authenticatable
    {
        return $this->users()->retrieveById($userId);
    }

    /** Whether the owner of a credential is refused by the application's policy (false when none is bound). */
    public function refused(string|int|null $userId): bool
    {
        if ($userId === null || $userId === '' || ! app()->bound(CredentialOwnerPolicy::class)) {
            return false;
        }
        $owner = $this->find($userId);

        return $owner === null || ! app(CredentialOwnerPolicy::class)->mayHoldCredentials($owner);
    }

    /** Refuse issuing a credential to an owner the application's policy refuses. */
    public function assertMayHold(string|int|null $userId): void
    {
        if ($this->refused($userId)) {
            throw new CredentialOwnerRefused('This account cannot hold API credentials.');
        }
    }

    /**
     * Revoke every authorization code, access token and refresh token an account holds, for
     * an application disabling or deleting it. Revoked rows stay revoked, so re-enabling the
     * account does not revive them. Returns the number of access tokens revoked.
     */
    public function revokeAll(Authenticatable $owner): int
    {
        $id = $owner->getAuthIdentifier();
        $tokenIds = Passport::token()->newQuery()->where('user_id', $id)->pluck('id');
        Passport::refreshToken()->newQuery()->whereIn('access_token_id', $tokenIds)->update(['revoked' => true]);
        Passport::authCode()->newQuery()->where('user_id', $id)->update(['revoked' => true]);

        return Passport::token()->newQuery()->where('user_id', $id)->where('revoked', false)->update(['revoked' => true]);
    }

    private function users(): UserProvider
    {
        $guard = (string) config('bherila-auth.provider_identity.bearer_guard', 'api');
        $provider = config("auth.guards.{$guard}.provider");
        $users = is_string($provider) ? auth()->createUserProvider($provider) : null;
        if ($users === null) {
            throw new RuntimeException('Credential checks need the bearer guard\'s user provider.');
        }

        return $users;
    }
}
