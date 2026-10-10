<?php

namespace BWH\Auth\OAuth\Server;

use Illuminate\Http\Request;
use Laravel\Passport\Passport;
use Laravel\Passport\Bridge\AuthCodeRepository as PassportAuthCodeRepository;
use League\OAuth2\Server\Entities\AuthCodeEntityInterface;
use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface;
use RuntimeException;

/**
 * Carries the validated resource from Passport's authorization request into the
 * authorization-code record and checks it again during code exchange.
 */
class ResourceAuthCodeRepository extends PassportAuthCodeRepository implements AuthCodeRepositoryInterface
{
    final public function persistNewAuthCode(AuthCodeEntityInterface $authCodeEntity): void
    {
        $model = Passport::authCode();
        $resourceColumn = $this->resourceColumn();
        $hasResourceColumn = $this->hasColumn($model->getTable(), $resourceColumn);
        $request = $this->request();
        $requestedResource = $request === null ? null : OAuthResourceIndicator::requestResource($request);
        if ($request?->exists('resource') && $requestedResource === null) {
            throw new RuntimeException('The requested OAuth resource is invalid.');
        }
        $resource = OAuthResourceIndicator::validatedFor($request ?? Request::create('/'))
            ?? $requestedResource;
        if ($requestedResource !== null && $resource !== $requestedResource) {
            throw new RuntimeException('The authorization-code resource does not match the request resource.');
        }
        if ($resource !== null && ! OAuthResourceIndicator::isConfiguredResource($resource)) {
            throw new RuntimeException('The authorization-code resource is not configured.');
        }
        $scopes = $authCodeEntity->getScopes();
        $scopeIdentifiers = OAuthResourceIndicator::scopeIdentifiers($scopes);

        if (OAuthResourceIndicator::scopesRequireResource($scopes) && $resource === null) {
            throw new RuntimeException('A protected resource is required for the requested scope.');
        }
        if ($resource !== null && ! $hasResourceColumn) {
            throw new RuntimeException("The {$model->getTable()}.{$resourceColumn} column is required.");
        }

        $this->persistResourceAuthCode(
            $authCodeEntity,
            $resource,
            $hasResourceColumn,
            $scopeIdentifiers,
        );
    }

    /**
     * @param  list<string>  $scopeIdentifiers
     */
    protected function persistResourceAuthCode(
        AuthCodeEntityInterface $authCodeEntity,
        ?string $resource,
        bool $hasResourceColumn,
        array $scopeIdentifiers,
    ): void {
        $model = Passport::authCode();
        $resourceColumn = $this->resourceColumn();
        $attributes = [
            'id' => $authCodeEntity->getIdentifier(),
            'user_id' => $authCodeEntity->getUserIdentifier(),
            'client_id' => $authCodeEntity->getClient()->getIdentifier(),
            'scopes' => $model->hasCast('scopes', ['array', 'json', 'collection'])
                ? $scopeIdentifiers
                : json_encode($scopeIdentifiers, JSON_THROW_ON_ERROR),
            'revoked' => false,
            'expires_at' => $authCodeEntity->getExpiryDateTime(),
        ];
        if ($hasResourceColumn) {
            $attributes[$resourceColumn] = $resource;
        }
        $attributes += $this->providerIdentityStamp($model, $authCodeEntity->getUserIdentifier());

        $model->forceFill($attributes)->save();
    }

    /**
     * The authorizing session's provider generation, stored on the code so the token
     * minted from it inherits it rather than a freshly fetched one.
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

    final public function isAuthCodeRevoked(string $codeId): bool
    {
        if (parent::isAuthCodeRevoked($codeId)) {
            return true;
        }

        $model = Passport::authCode()->newQuery()->whereKey($codeId)->first();
        if ($model === null) {
            return true;
        }

        $resourceColumn = $this->resourceColumn();
        $hasResourceColumn = $this->hasColumn($model->getTable(), $resourceColumn);
        $storedValue = $hasResourceColumn ? $model->getAttribute($resourceColumn) : null;
        $storedResource = $storedValue === null ? null : OAuthResourceIndicator::canonicalize($storedValue);
        $scopes = OAuthResourceIndicator::scopeIdentifiers($model->getAttribute('scopes'));
        $request = $this->request();
        $hasRequestedResource = $request !== null && OAuthResourceIndicator::requestNamesResource($request);
        $requestedResource = $request === null ? null : OAuthResourceIndicator::requestResource($request);
        $bound = $storedValue !== null || OAuthResourceIndicator::scopesRequireResource($scopes);

        if (! $bound) {
            // A token request may not add a resource audience to an unbound code.
            return $hasRequestedResource || $this->providerIdentityRevoked($model) || $this->isApplicationAuthCodeRevoked($codeId);
        }

        if ($storedResource === null
            || $storedResource !== OAuthResourceIndicator::configuredCanonical()
            || ! $hasRequestedResource
            || $requestedResource !== $storedResource) {
            return true;
        }

        $request?->attributes->set(OAuthResourceIndicator::REQUEST_ATTRIBUTE, $storedResource);

        return $this->providerIdentityRevoked($model) || $this->isApplicationAuthCodeRevoked($codeId);
    }

    /** Refuses a code whose person was ended at the provider, and hands its stamp to the token. */
    private function providerIdentityRevoked(\Illuminate\Database\Eloquent\Model $code): bool
    {
        $tokens = app(ProviderIdentityTokens::class);
        if ($tokens->revoked($code, remote: false)) {
            return true;
        }
        $tokens->carry($this->request(), $code);

        return false;
    }

    /** Application-owned account, grant, or credential-version revocation policy. */
    protected function isApplicationAuthCodeRevoked(string $codeId): bool
    {
        return false;
    }

    private function resourceColumn(): string
    {
        $column = config('bherila-auth.oauth_server.auth_code_resource_column', 'resource_uri');

        return is_string($column) && $column !== '' ? $column : 'resource_uri';
    }

    private function hasColumn(string $table, string $column): bool
    {
        return Passport::authCode()->getConnection()->getSchemaBuilder()->hasColumn($table, $column);
    }

    private function request(): ?Request
    {
        return app()->bound('request') ? app('request') : null;
    }
}
