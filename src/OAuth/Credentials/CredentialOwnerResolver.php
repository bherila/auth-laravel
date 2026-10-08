<?php

namespace BWH\Auth\OAuth\Credentials;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;

/**
 * The model that owns a signed-in person's API tokens and OAuth apps.
 *
 * Usually the user itself. An application whose API guard authenticates a
 * different model over the same table (an agent principal, say) binds its own
 * resolver so tokens and apps belong to the model the API guard loads.
 * The returned model must use Laravel\Passport\HasApiTokens.
 */
interface CredentialOwnerResolver
{
    public function owner(Authenticatable $user): Model;
}
