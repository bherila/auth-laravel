<?php

namespace BWH\Auth\OAuth\Server;

use BWH\Auth\OAuth\Introspection\OAuthIntrospectionValidationContext;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Http\Request;
use Laravel\Passport\Events\AccessTokenCreated;
use Laravel\Passport\Events\AccessTokenRevoked;
use Laravel\Passport\Passport;
use Laravel\Passport\Bridge\AccessTokenRepository as PassportAccessTokenRepository;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use RuntimeException;
use Throwable;

/**
 * Persists and validates Passport access-token resource bindings.
 *
 * Binding is stored in the database as well as in the JWT. The database state
 * lets a resource server reject revoked, legacy, or otherwise incomplete tokens;
 * the signed audience lets it reject a token whose credential was issued for a
 * different resource.
 */
class ResourceAccessTokenRepository extends PassportAccessTokenRepository implements AccessTokenRepositoryInterface
{
    public function __construct(Dispatcher $events)
    {
        parent::__construct($events);
    }

    final public function getNewToken(
        ClientEntityInterface $clientEntity,
        array $scopes,
        ?string $userIdentifier = null,
    ): AccessTokenEntityInterface {
        if (! $this->oauthServerEnabled()) {
            return parent::getNewToken($clientEntity, $scopes, $userIdentifier);
        }

        $token = new ResourceAccessToken($userIdentifier, $scopes, $clientEntity);
        $request = $this->request();
        $requestResource = $this->requestResource($request);
        $resource = $request === null
            ? null
            : (OAuthResourceIndicator::validatedFor($request) ?? $requestResource);

        if ($requestResource !== null && $resource !== $requestResource) {
            throw new RuntimeException('The access-token resource does not match the validated request resource.');
        }

        if ($resource !== null) {
            $token->setResource($resource);
        } elseif (OAuthResourceIndicator::scopesRequireResource($scopes)) {
            throw new RuntimeException('A protected resource is required for the requested scope.');
        }

        return $token;
    }

    final public function persistNewAccessToken(AccessTokenEntityInterface $accessTokenEntity): void
    {
        if (! $this->oauthServerEnabled()) {
            $this->persistUnboundAccessToken($accessTokenEntity);
            // Recorded on this path too, so stale-client pruning never mistakes
            // a client that just got a token for an unused one.
            $this->recordDynamicClientUse($accessTokenEntity->getClient()->getIdentifier());

            return;
        }

        $model = Passport::token();
        $resourceColumn = $this->resourceColumn();
        $hasResourceColumn = $this->hasColumn($model->getTable(), $resourceColumn);
        $request = $this->request();
        $requestResource = $this->requestResource($request);
        $resource = $accessTokenEntity instanceof ResourceAccessToken
            ? $accessTokenEntity->getResource()
            : ($request === null ? null : OAuthResourceIndicator::validatedFor($request));

        if ($resource !== null) {
            $resource = OAuthResourceIndicator::canonicalize($resource);
            if ($resource === null || ! OAuthResourceIndicator::isConfiguredResource($resource)) {
                throw new RuntimeException('The access-token resource is not configured.');
            }
        }
        $validatedResource = $request === null ? null : OAuthResourceIndicator::validatedFor($request);
        if ($validatedResource !== null && ! OAuthResourceIndicator::isConfiguredResource($validatedResource)) {
            throw new RuntimeException('The validated access-token resource is invalid.');
        }
        $requestResource ??= $validatedResource;

        if ($resource !== $requestResource) {
            throw new RuntimeException('The access-token resource does not match the validated request resource.');
        }
        // The last line for a grant whose original scopes are no longer known (a purged access
        // token): a resource never receives a token with scopes outside its ceiling.
        if ($resource !== null && ! OAuthResourceIndicator::scopesAllowedFor($resource, $accessTokenEntity->getScopes())) {
            throw \League\OAuth2\Server\Exception\OAuthServerException::invalidScope(
                implode(' ', OAuthResourceIndicator::scopeIdentifiers($accessTokenEntity->getScopes())),
            );
        }
        if (OAuthResourceIndicator::scopesRequireResource($accessTokenEntity->getScopes()) && $resource === null) {
            throw new RuntimeException('A protected resource is required for the requested scope.');
        }
        if ($resource !== null && ! $hasResourceColumn) {
            throw new RuntimeException("The {$model->getTable()}.{$resourceColumn} column is required.");
        }

        $this->persistResourceAccessToken($accessTokenEntity, $resource, $hasResourceColumn);
    }

    /**
     * Application policy may wrap the already-validated persistence operation in
     * its own transaction, but cannot replace the resource checks above.
     */
    protected function persistResourceAccessToken(
        AccessTokenEntityInterface $accessTokenEntity,
        ?string $resource,
        bool $hasResourceColumn,
    ): void {
        $model = Passport::token();
        $resourceColumn = $this->resourceColumn();
        $attributes = [
            'id' => $id = $accessTokenEntity->getIdentifier(),
            'user_id' => $userId = $accessTokenEntity->getUserIdentifier(),
            'client_id' => $clientId = $accessTokenEntity->getClient()->getIdentifier(),
            'scopes' => $accessTokenEntity->getScopes(),
            'revoked' => false,
            'expires_at' => $accessTokenEntity->getExpiryDateTime(),
        ];
        if ($hasResourceColumn) {
            $attributes[$resourceColumn] = $resource;
        }
        $attributes += $this->providerIdentityStamp($model, $userId);

        $model->forceFill($attributes)->save();
        $this->recordDynamicClientUse($clientId);

        $this->events->dispatch(new AccessTokenCreated($id, $userId, $clientId));
    }

    /** Application policy may also wrap Passport-compatible unbound persistence. */
    protected function persistUnboundAccessToken(AccessTokenEntityInterface $accessTokenEntity): void
    {
        // With the package's server off, Passport's own code and refresh repositories carry no
        // stamp to inherit; record one only if it is available, and never refuse the exchange
        // here. A bound owner's unstamped token is refused at use once enforcement is on.
        try {
            $stamp = $this->providerIdentityStamp(Passport::token(), $accessTokenEntity->getUserIdentifier());
        } catch (RuntimeException) {
            $stamp = [];
        }
        parent::persistNewAccessToken($accessTokenEntity);
        if ($stamp !== []) {
            Passport::token()->newQuery()->whereKey($accessTokenEntity->getIdentifier())->update($stamp);
        }
    }

    /**
     * The provider generation this token inherits: from the code or refresh token it was
     * exchanged for, or from the authorizing session for a personal token.
     *
     * @return array<string, string|int>
     */
    final protected function providerIdentityStamp(\Illuminate\Database\Eloquent\Model $model, string|int|null $userId): array
    {
        $stamp = app(ProviderIdentityTokens::class)->stampForIssue($this->request(), $userId);
        if ($stamp === null) {
            return [];
        }
        if (! $this->hasColumn($model->getTable(), ProviderIdentityTokens::GENERATION_COLUMN)) {
            if (ProviderIdentityTokens::enabled()) {
                throw new RuntimeException("The {$model->getTable()} provider identity columns are required.");
            }

            return [];
        }

        return ProviderIdentityTokens::attributes($stamp);
    }

    final public function revokeAccessToken(string $tokenId): void
    {
        if (Passport::token()->newQuery()->whereKey($tokenId)->update(['revoked' => true])) {
            $this->events->dispatch(new AccessTokenRevoked($tokenId));
        }
    }

    final public function isAccessTokenRevoked(string $tokenId): bool
    {
        $model = Passport::token()->newQuery()->whereKey($tokenId)->first();
        if ($model === null || (bool) $model->getAttribute('revoked')) {
            return true;
        }

        $resourceColumn = $this->resourceColumn();
        // The token row is already loaded. Reading a missing attribute yields
        // null, which is the same fail-closed state as a missing binding, so the
        // bearer hot path does not need a schema-catalog query on every request.
        $storedValue = $model->getAttribute($resourceColumn);
        $storedResource = $storedValue === null ? null : OAuthResourceIndicator::canonicalize($storedValue);
        $scopes = OAuthResourceIndicator::scopeIdentifiers($model->getAttribute('scopes'));
        $bound = $storedValue !== null || OAuthResourceIndicator::scopesRequireResource($scopes);

        $request = $this->request();
        $introspection = app(OAuthIntrospectionValidationContext::class);
        $serializedToken = $introspection->token() ?? $request?->bearerToken();
        $expectedResource = $introspection->resource()
            ?? ($request === null ? null : OAuthResourceIndicator::expectedFor($request));

        if (! $bound) {
            $claims = is_string($serializedToken)
                ? OAuthResourceIndicator::tokenClaims($serializedToken)
                : null;

            // A resource-bearing JWT without its database binding is incomplete;
            // never silently downgrade it to an unbound Passport token.
            if ($expectedResource !== null
                || OAuthResourceIndicator::tokenHasAnyResourceAudience($serializedToken)
                || is_string($claims['resource'] ?? null)) {
                return true;
            }

            // The row is already known to exist and be non-revoked. Preserve
            // Passport's normal unbound-token result without a second query.
            if (! $this->oauthServerEnabled()) {
                return app(ProviderIdentityTokens::class)->revoked($model) || $this->isApplicationAccessTokenRevoked($tokenId);
            }
        }

        try {
            OAuthResourceIndicator::resources();
            $issuer = OAuthResourceIndicator::issuer();
        } catch (Throwable) {
            return true;
        }
        if (! OAuthResourceIndicator::tokenHasIssuer($serializedToken, $issuer)) {
            return true;
        }

        if (! $bound) {
            return app(ProviderIdentityTokens::class)->revoked($model) || $this->isApplicationAccessTokenRevoked($tokenId);
        }

        // A resource-bound token is valid only where application policy has
        // explicitly marked the current route with its expected audience.
        if ($expectedResource === null
            || $storedResource === null
            || ! OAuthResourceIndicator::isConfiguredResource($storedResource)
            || $storedResource !== $expectedResource
            // A ceiling tightened after issuance applies to tokens already out, too.
            || ! OAuthResourceIndicator::scopesAllowedFor($storedResource, $scopes)) {
            return true;
        }

        if (! OAuthResourceIndicator::tokenHasAudience($serializedToken, $storedResource)
            || ! OAuthResourceIndicator::tokenResourceClaimMatches($serializedToken, $storedResource)) {
            return true;
        }

        if ($introspection->resource() === null) {
            $request?->attributes->set(OAuthResourceIndicator::REQUEST_ATTRIBUTE, $storedResource);
        }

        return app(ProviderIdentityTokens::class)->revoked($model) || $this->isApplicationAccessTokenRevoked($tokenId);
    }

    /** Application-owned account, grant, or credential-version revocation policy. */
    protected function isApplicationAccessTokenRevoked(string $tokenId): bool
    {
        return false;
    }

    private function requestResource(?Request $request): ?string
    {
        if ($request === null || ! OAuthResourceIndicator::requestNamesResource($request)) {
            return null;
        }

        $resource = OAuthResourceIndicator::requestResource($request);
        if ($resource === null || ! OAuthResourceIndicator::isConfiguredResource($resource)) {
            throw new RuntimeException('The requested OAuth resource is invalid.');
        }

        return $resource;
    }

    private function resourceColumn(): string
    {
        $column = config('bherila-auth.oauth_server.resource_column', 'resource_uri');

        return is_string($column) && $column !== '' ? $column : 'resource_uri';
    }

    private function hasColumn(string $table, string $column): bool
    {
        return Passport::token()->getConnection()->getSchemaBuilder()->hasColumn($table, $column);
    }

    private function request(): ?Request
    {
        return app()->bound('request') ? app('request') : null;
    }

    private function oauthServerEnabled(): bool
    {
        return (bool) config('bherila-auth.oauth_server.enabled', false);
    }

    private function recordDynamicClientUse(string $clientId): void
    {
        $column = config('bherila-auth.oauth_server.dynamic_clients.last_used_at_column');
        if (! is_string($column) || $column === '') {
            return;
        }

        $client = Passport::client();
        if (! $this->hasColumn($client->getTable(), $column)) {
            return;
        }

        $client->newQuery()->whereKey($clientId)->update([$column => now()]);
    }
}
