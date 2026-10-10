<?php

namespace BWH\Auth\OAuth\Server;

use Illuminate\Http\Request;
use Laravel\Passport\Events\RefreshTokenCreated;
use Laravel\Passport\Passport;
use Laravel\Passport\Bridge\RefreshTokenRepository as PassportRefreshTokenRepository;
use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use RuntimeException;

/**
 * Keeps refresh-token exchanges on the resource selected for the original grant.
 */
class ResourceRefreshTokenRepository extends PassportRefreshTokenRepository implements RefreshTokenRepositoryInterface
{
    final public function persistNewRefreshToken(RefreshTokenEntityInterface $refreshTokenEntity): void
    {
        $accessToken = $refreshTokenEntity->getAccessToken();
        $request = $this->request();
        $resource = $accessToken instanceof ResourceAccessToken
            ? $accessToken->getResource()
            : ($request === null ? null : OAuthResourceIndicator::validatedFor($request));

        if ($resource !== null) {
            $resource = OAuthResourceIndicator::canonicalize($resource);
            if ($resource === null || ! OAuthResourceIndicator::isConfiguredResource($resource)) {
                throw new RuntimeException('The refresh-token resource is not configured.');
            }
        }
        if (OAuthResourceIndicator::scopesRequireResource($accessToken->getScopes()) && $resource === null) {
            throw new RuntimeException('A protected resource is required for the refresh token.');
        }

        $model = Passport::refreshToken();
        $resourceColumn = $this->resourceColumn();
        $hasResourceColumn = $model->getConnection()->getSchemaBuilder()->hasColumn(
            $model->getTable(),
            $resourceColumn,
        );
        if ($resource !== null && ! $hasResourceColumn) {
            throw new RuntimeException("The {$model->getTable()}.{$resourceColumn} column is required.");
        }

        $this->persistResourceRefreshToken($refreshTokenEntity, $resource, $hasResourceColumn);
    }

    protected function persistResourceRefreshToken(
        RefreshTokenEntityInterface $refreshTokenEntity,
        ?string $resource,
        bool $hasResourceColumn,
    ): void {
        $accessToken = $refreshTokenEntity->getAccessToken();
        $model = Passport::refreshToken();
        $resourceColumn = $this->resourceColumn();
        $attributes = [
            'id' => $id = $refreshTokenEntity->getIdentifier(),
            'access_token_id' => $accessTokenId = $accessToken->getIdentifier(),
            'revoked' => false,
            'expires_at' => $refreshTokenEntity->getExpiryDateTime(),
        ];
        if ($hasResourceColumn) {
            $attributes[$resourceColumn] = $resource;
        }
        $attributes += $this->providerIdentityStamp($model, $accessTokenId);

        $model->forceFill($attributes)->save();

        $this->events->dispatch(new RefreshTokenCreated($id, $accessTokenId));
    }

    final public function isRefreshTokenRevoked(string $tokenId): bool
    {
        if (parent::isRefreshTokenRevoked($tokenId)) {
            return true;
        }

        $refreshToken = Passport::refreshToken()->newQuery()->whereKey($tokenId)->first();
        if ($refreshToken === null) {
            return true;
        }

        $resourceColumn = $this->resourceColumn();
        $storedValue = $refreshToken->getAttribute($resourceColumn);
        $storedResource = $storedValue === null ? null : OAuthResourceIndicator::canonicalize($storedValue);
        $bound = $storedValue !== null;
        $request = $this->request();
        $hasRequestedResource = $request !== null && OAuthResourceIndicator::requestNamesResource($request);
        $requestedResource = $request === null ? null : OAuthResourceIndicator::requestResource($request);

        if (! $bound) {
            // A refresh request cannot add an audience that was absent from the
            // authorization-code grant.
            return $hasRequestedResource || $this->providerIdentityRevoked($refreshToken) || $this->isApplicationRefreshTokenRevoked($tokenId);
        }

        if ($storedResource === null
            || ! OAuthResourceIndicator::isConfiguredResource($storedResource)
            || ! $hasRequestedResource
            || $requestedResource !== $storedResource) {
            // Do not consume the refresh token for a resource mismatch. A client
            // can retry the same token with the resource originally granted.
            return true;
        }
        // A ceiling tightened since the grant applies to the token a refresh mints; refused
        // here, before the grant revokes anything.
        $grant = Passport::token()->newQuery()->whereKey($refreshToken->getAttribute('access_token_id'))->first();
        if ($grant !== null && ! OAuthResourceIndicator::scopesAllowedFor($storedResource, $grant->getAttribute('scopes'))) {
            return true;
        }

        $request?->attributes->set(OAuthResourceIndicator::REQUEST_ATTRIBUTE, $storedResource);

        return $this->providerIdentityRevoked($refreshToken) || $this->isApplicationRefreshTokenRevoked($tokenId);
    }

    /**
     * Renewal checks the person freshly against the stamp of the access token this refresh
     * token belongs to, and hands that stamp to the new token. An unavailable provider
     * throws before the grant revokes anything, so the refresh token is not consumed.
     */
    private function providerIdentityRevoked(\Illuminate\Database\Eloquent\Model $refreshToken): bool
    {
        // The refresh token's own record, which outlives its access token (expired access
        // tokens may be purged long before the refresh token expires).
        $credential = $refreshToken->getAttribute(ProviderIdentityTokens::OWNER_COLUMN) !== null
            ? $refreshToken
            : Passport::token()->newQuery()->whereKey($refreshToken->getAttribute('access_token_id'))->first();
        $tokens = app(ProviderIdentityTokens::class);
        if ($credential === null) {
            return ProviderIdentityTokens::enabled();
        }
        if ($tokens->revoked($credential, fresh: true)) {
            return true;
        }
        $tokens->carry($this->request(), $credential);

        return false;
    }

    /**
     * The owner and stamp of the access token this refresh token was issued with, copied so
     * the refresh token can be checked after that access token is gone.
     *
     * @return array<string, string|int>
     */
    private function providerIdentityStamp(\Illuminate\Database\Eloquent\Model $model, string $accessTokenId): array
    {
        $schema = $model->getConnection()->getSchemaBuilder();
        if (! $schema->hasColumn($model->getTable(), ProviderIdentityTokens::OWNER_COLUMN)) {
            if (ProviderIdentityTokens::enabled()) {
                throw new RuntimeException("The {$model->getTable()} provider identity columns are required.");
            }

            return [];
        }
        $accessToken = Passport::token()->newQuery()->whereKey($accessTokenId)->first();
        if ($accessToken === null || $accessToken->getAttribute('user_id') === null) {
            return [];
        }

        return [
            ProviderIdentityTokens::OWNER_COLUMN => (string) $accessToken->getAttribute('user_id'),
            ProviderIdentityTokens::SUBJECT_COLUMN => $accessToken->getAttribute(ProviderIdentityTokens::SUBJECT_COLUMN),
            ProviderIdentityTokens::GENERATION_COLUMN => $accessToken->getAttribute(ProviderIdentityTokens::GENERATION_COLUMN),
        ];
    }

    /** Application-owned account, grant, or credential-version revocation policy. */
    protected function isApplicationRefreshTokenRevoked(string $tokenId): bool
    {
        return false;
    }

    private function resourceColumn(): string
    {
        $column = config('bherila-auth.oauth_server.refresh_token_resource_column', 'resource_uri');

        return is_string($column) && $column !== '' ? $column : 'resource_uri';
    }

    private function request(): ?Request
    {
        return app()->bound('request') ? app('request') : null;
    }
}
