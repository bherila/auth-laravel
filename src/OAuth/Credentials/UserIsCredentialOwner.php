<?php

namespace BWH\Auth\OAuth\Credentials;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use InvalidArgumentException;

/**
 * Default: the signed-in user owns their credentials, or - when
 * `credentials.owner_model` names another model over the same table - that
 * model's row with the same key.
 */
final class UserIsCredentialOwner implements CredentialOwnerResolver
{
    public function owner(Authenticatable $user): Model
    {
        $ownerModel = config('bherila-auth.oauth_server.credentials.owner_model');
        if (is_string($ownerModel) && $ownerModel !== '' && ! $user instanceof $ownerModel) {
            /** @var Model $owner */
            $owner = $ownerModel::query()->whereKey($user->getAuthIdentifier())->firstOrFail();

            return $owner;
        }
        if (! $user instanceof Model || ! method_exists($user, 'createToken') || ! method_exists($user, 'oauthApps')) {
            throw new InvalidArgumentException('The credential owner must be an Eloquent model using Laravel\\Passport\\HasApiTokens; set credentials.owner_model or bind a CredentialOwnerResolver.');
        }

        return $user;
    }
}
