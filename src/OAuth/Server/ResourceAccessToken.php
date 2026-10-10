<?php

namespace BWH\Auth\OAuth\Server;

use DateTimeImmutable;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use League\OAuth2\Server\CryptKeyInterface;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\Traits\TokenEntityTrait;
use RuntimeException;
use SensitiveParameter;

/**
 * Passport's JWT access token with an RFC 8707 protected-resource audience.
 *
 * Passport's normal token puts the client ID in the first `aud` position and its
 * TokenGuard uses that position to resolve the client. The resource is appended as
 * a second audience so Passport compatibility is retained while the resource server
 * can enforce its own audience boundary.
 */
final class ResourceAccessToken implements AccessTokenEntityInterface
{
    use EntityTrait;
    use TokenEntityTrait;

    private ?string $resource = null;

    private CryptKeyInterface $privateKey;

    private Configuration $jwtConfiguration;

    /**
     * @param  non-empty-string|null  $userIdentifier
     * @param  ScopeEntityInterface[]  $scopes
     */
    public function __construct(?string $userIdentifier, array $scopes, ClientEntityInterface $client)
    {
        if ($userIdentifier !== null) {
            $this->setUserIdentifier($userIdentifier);
        }

        foreach ($scopes as $scope) {
            $this->addScope($scope);
        }

        $this->setClient($client);
    }

    public function setResource(?string $resource): void
    {
        if ($resource === null) {
            $this->resource = null;

            return;
        }

        $canonical = OAuthResourceIndicator::canonicalize($resource);
        if ($canonical === null || ! OAuthResourceIndicator::isConfiguredResource($canonical)) {
            throw new RuntimeException('The access-token resource is not configured.');
        }

        $this->resource = $canonical;
    }

    public function getResource(): ?string
    {
        return $this->resource;
    }

    public function setPrivateKey(
        #[SensitiveParameter]
        CryptKeyInterface $privateKey
    ): void {
        $this->privateKey = $privateKey;
    }

    public function initJwtConfiguration(): void
    {
        $privateKeyContents = $this->privateKey->getKeyContents();

        if ($privateKeyContents === '') {
            throw new RuntimeException('Private key is empty');
        }

        $this->jwtConfiguration = Configuration::forAsymmetricSigner(
            new Sha256(),
            InMemory::plainText($privateKeyContents, $this->privateKey->getPassPhrase() ?? ''),
            InMemory::plainText('empty', 'empty'),
        );
    }

    public function toString(): string
    {
        $this->initJwtConfiguration();

        $builder = $this->jwtConfiguration->builder()
            // Passport's TokenGuard reads aud[0] as the client ID.
            ->permittedFor($this->getClient()->getIdentifier())
            ->identifiedBy($this->getIdentifier())
            ->issuedBy(OAuthResourceIndicator::issuer())
            ->issuedAt(new DateTimeImmutable())
            ->canOnlyBeUsedAfter(new DateTimeImmutable())
            ->expiresAt($this->getExpiryDateTime())
            ->relatedTo($this->getSubjectIdentifier())
            ->withClaim('scopes', array_map(
                static fn (ScopeEntityInterface $scope): string => $scope->getIdentifier(),
                $this->getScopes(),
            ));

        if ($this->resource !== null) {
            $builder = $builder
                ->permittedFor($this->resource)
                ->withClaim('resource', $this->resource);
        }

        return $builder
            ->getToken($this->jwtConfiguration->signer(), $this->jwtConfiguration->signingKey())
            ->toString();
    }

    private function getSubjectIdentifier(): string
    {
        return $this->getUserIdentifier() ?? $this->getClient()->getIdentifier();
    }
}
