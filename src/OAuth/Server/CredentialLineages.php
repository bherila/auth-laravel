<?php

namespace BWH\Auth\OAuth\Server;

use Closure;
use Illuminate\Database\Connection;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Support\Str;
use Laravel\Passport\Passport;
use League\OAuth2\Server\Exception\OAuthServerException;
use RuntimeException;
use WeakMap;

/**
 * Durable grant lineage and revocation coordination on Passport's connection.
 *
 * Credential persistence and revocation both lock the owner's guard row before
 * touching a lineage or Passport credential. Only broad revocations serialize
 * on the monotonic clock. Neither cached entries nor wall-clock expiry are used.
 */
final class CredentialLineages
{
    private const string SCOPES = 'oauth_credential_revocations';

    private const string LINEAGES = 'oauth_credential_lineages';

    private const string MEMBERS = 'oauth_credential_members';

    private const string SNAPSHOT = 'bherila_auth.revocation_sequence';

    private const string PARENT = 'bherila_auth.credential_lineage';

    /** @var WeakMap<object, CredentialIssueContext> */
    private WeakMap $issues;

    public function __construct()
    {
        $this->issues = new WeakMap;
    }

    public static function enabled(): bool
    {
        return (bool) config('bherila-auth.oauth_server.revocation.enabled', false);
    }

    /** Wrap a new issuance decision, including any remote identity check. */
    public function duringIssue(Closure $issue): mixed
    {
        if (! self::enabled()) {
            return $issue();
        }
        $request = $this->request();
        if ($request === null) {
            throw new RuntimeException('Credential issuance needs a request context.');
        }
        $previous = $request->attributes->get(self::SNAPSHOT);
        $request->attributes->set(self::SNAPSHOT, $this->sequence());
        try {
            return $issue();
        } finally {
            $request->attributes->remove(self::SNAPSHOT);
            if ($previous !== null) {
                $request->attributes->set(self::SNAPSHOT, $previous);
            }
        }
    }

    /** Entry to an OAuth endpoint: take the snapshot before grant/session checks. */
    public function begin(Request $request): void
    {
        if (self::enabled()) {
            $request->attributes->set(self::SNAPSHOT, $this->sequence());
            $request->attributes->remove(self::PARENT);
        }
    }

    /** Called as each new access-token or auth-code entity is allocated. */
    public function capture(object $entity): void
    {
        if (! self::enabled()) {
            return;
        }
        $request = $this->request();
        $sequence = $request?->attributes->get(self::SNAPSHOT);
        $parent = $request?->attributes->get(self::PARENT);
        $this->issues[$entity] = new CredentialIssueContext(
            is_int($sequence) ? $sequence : $this->sequence(),
            is_string($parent) ? $parent : null,
        );
    }

    /** The callback includes the model save and synchronous Passport events. */
    public function persist(string $kind, object $entity, Model $model, Closure $save): void
    {
        if (! self::enabled()) {
            $save();

            return;
        }
        $context = $this->issues[$entity] ?? throw new RuntimeException('The credential has no captured issuance context.');
        $owner = $entity->getUserIdentifier();
        $owner = $owner === null || $owner === '' ? null : (string) $owner;
        $client = (string) $entity->getClient()->getIdentifier();
        $this->sameConnection($model);
        $this->connection()->transaction(function () use ($kind, $entity, $owner, $client, $context, $save): void {
            $this->lockOwner($owner);
            $lineage = $context->lineageId === null
                ? $this->newLineage($owner, $client, $context->sequence)
                : $this->lineage($context->lineageId, true);
            $this->assertActive($lineage, $owner, $client);
            $this->member($kind, $entity->getIdentifier(), $lineage->id);
            $save();
        });
    }

    /** A refresh token always inherits the new access token's durable lineage. */
    public function persistRefresh(object $entity, Model $model, Closure $save): void
    {
        if (! self::enabled()) {
            $save();

            return;
        }
        $this->sameConnection($model);
        $access = $entity->getAccessToken();
        $owner = $access->getUserIdentifier();
        $owner = $owner === null || $owner === '' ? null : (string) $owner;
        $client = (string) $access->getClient()->getIdentifier();
        $this->connection()->transaction(function () use ($entity, $access, $owner, $client, $save): void {
            $this->lockOwner($owner);
            $member = $this->findMember('access', $access->getIdentifier(), true);
            if ($member === null) {
                throw OAuthServerException::invalidGrant();
            }
            $lineage = $this->lineage($member->lineage_id, true);
            $this->assertActive($lineage, $owner, $client);
            $this->member('refresh', $entity->getIdentifier(), $lineage->id);
            $save();
        });
    }

    /**
     * Validate a parent under the guard, carrying its identity before rotation.
     * Legacy rows are adopted at sequence zero, never into a newer revocation.
     */
    public function carry(string $kind, Model $credential): bool
    {
        if (! self::enabled()) {
            return true;
        }
        $this->sameConnection($credential);
        $owner = $credential->getAttribute('user_id') ?? $credential->getAttribute(ProviderIdentityTokens::OWNER_COLUMN);
        $client = $credential->getAttribute('client_id');
        if ($kind === 'refresh' && ($owner === null || $client === null)) {
            $access = Passport::token()->newQuery()->whereKey($credential->getAttribute('access_token_id'))->first();
            $owner ??= $access?->getAttribute('user_id');
            $client ??= $access?->getAttribute('client_id');
        }
        if ($owner === null || ! is_string($client) || $client === '') {
            return false;
        }
        $owner = (string) $owner;
        try {
            return $this->connection()->transaction(function () use ($kind, $credential, $owner, $client): bool {
                $this->lockOwner($owner);
                $current = $credential->newQuery()->whereKey($credential->getKey())->lockForUpdate()->first();
                if ($current === null || (bool) $current->getAttribute('revoked')) {
                    return false;
                }
                $member = $this->findMember($kind, (string) $credential->getKey(), true);
                if ($member === null && $kind === 'refresh') {
                    $parentId = (string) $current->getAttribute('access_token_id');
                    $parent = $this->findMember('access', $parentId, true);
                    $lineage = $parent === null ? $this->newLineage($owner, $client, 0) : $this->lineage($parent->lineage_id, true);
                    $this->assertActive($lineage, $owner, $client);
                    $this->member('access', $parentId, $lineage->id);
                } else {
                    $lineage = $member === null ? $this->newLineage($owner, $client, 0) : $this->lineage($member->lineage_id, true);
                }
                $this->assertActive($lineage, $owner, $client);
                $this->member($kind, (string) $credential->getKey(), $lineage->id);
                $this->request()?->attributes->set(self::PARENT, $lineage->id);

                return true;
            });
        } catch (OAuthServerException) {
            return false;
        }
    }

    /** Bearer checks retain the durable guard even if an application missed a row. */
    public function revoked(Model $access): bool
    {
        if (! self::enabled()) {
            return false;
        }
        $member = $this->findMember('access', (string) $access->getKey());
        $owner = $access->getAttribute('user_id');
        $owner = $owner === null ? null : (string) $owner;
        $client = (string) $access->getAttribute('client_id');
        if ($member === null) {
            return $this->scopeSequence($this->ownerKey($owner)) > 0
                || $this->scopeSequence($this->clientKey($owner, $client)) > 0;
        }
        try {
            $this->assertActive($this->lineage($member->lineage_id), $owner, $client, false);

            return false;
        } catch (OAuthServerException) {
            return true;
        }
    }

    /**
     * Raise an owner/client barrier and revoke existing rows in one transaction.
     * A later, fresh authorization may create a new connection at the new sequence.
     */
    public function revokingOwner(string|int $owner, ?string $client, Closure $revoke): mixed
    {
        $this->requireEnabled();
        $owner = (string) $owner;

        return $this->connection()->transaction(function () use ($owner, $client, $revoke): mixed {
            $clock = $this->connection()->table(self::SCOPES)->where('scope_key', $this->clockKey())->lockForUpdate()->first();
            if ($clock === null) {
                throw new RuntimeException('The credential revocation migration is required.');
            }
            $next = (int) $clock->sequence + 1;
            $this->connection()->table(self::SCOPES)->where('scope_key', $this->clockKey())->update(['sequence' => $next]);
            $this->lockOwner($owner);
            $scope = $client === null ? $this->ownerKey($owner) : $this->clientKey($owner, $client);
            $this->connection()->table(self::SCOPES)->updateOrInsert(['scope_key' => $scope], ['sequence' => $next]);
            $lineages = $this->connection()->table(self::LINEAGES)->where('owner_key', $this->ownerKey($owner));
            if ($client !== null) {
                $lineages->where('client_key', $this->clientKey($owner, $client));
            }
            $lineages->update(['revoked' => true]);

            return $revoke();
        });
    }

    /** Revoke just this connection and all rotations, preserving sibling logins. */
    public function revokingConnection(string|int $owner, string $accessId, Closure $revoke): mixed
    {
        $this->requireEnabled();
        $owner = (string) $owner;

        return $this->connection()->transaction(function () use ($owner, $accessId, $revoke): mixed {
            $this->lockOwner($owner);
            $member = $this->findMember('access', $accessId, true);
            if ($member === null) {
                $token = Passport::token()->newQuery()->where('user_id', $owner)->whereKey($accessId)->lockForUpdate()->first();
                if ($token !== null) {
                    $lineage = $this->newLineage($owner, (string) $token->getAttribute('client_id'), 0, false);
                    $this->member('access', $accessId, $lineage->id);
                    $member = $this->findMember('access', $accessId, true);
                }
            }
            $family = [$accessId];
            if ($member !== null) {
                $lineage = $this->lineage($member->lineage_id, true);
                if ($lineage->owner_key !== $this->ownerKey($owner)) {
                    throw OAuthServerException::invalidGrant();
                }
                $this->connection()->table(self::LINEAGES)->where('id', $lineage->id)->update(['revoked' => true]);
                $family = $this->connection()->table(self::MEMBERS)->where('lineage_id', $lineage->id)->where('kind', 'access')->lockForUpdate()->pluck('credential_id')->all();
            }

            return $revoke($family);
        });
    }

    private function newLineage(?string $owner, string $client, int $sequence, bool $validate = true): object
    {
        $lineage = (object) [
            'id' => (string) Str::uuid(), 'owner_key' => $this->ownerKey($owner), 'client_key' => $this->clientKey($owner, $client),
            'owner_id' => $owner, 'client_id' => $client, 'issued_sequence' => $sequence, 'revoked' => false,
        ];
        if ($validate) {
            $this->assertActive($lineage, $owner, $client);
        }
        $this->connection()->table(self::LINEAGES)->insert((array) $lineage);

        return $lineage;
    }

    private function assertActive(object $lineage, ?string $owner, string $client, bool $current = true): void
    {
        if ((bool) $lineage->revoked || $lineage->owner_key !== $this->ownerKey($owner) || $lineage->client_key !== $this->clientKey($owner, $client)
            || $this->scopeSequence($lineage->owner_key, $current) > (int) $lineage->issued_sequence
            || $this->scopeSequence($lineage->client_key, $current) > (int) $lineage->issued_sequence) {
            throw OAuthServerException::invalidGrant();
        }
    }

    private function lineage(string $id, bool $current = false): object
    {
        return $this->connection()->table(self::LINEAGES)->where('id', $id)->when($current, fn ($query) => $query->lockForUpdate())->first() ?? throw OAuthServerException::invalidGrant();
    }

    private function member(string $kind, string $id, string $lineage): void
    {
        $existing = $this->findMember($kind, $id, true);
        if ($existing !== null) {
            if ($existing->lineage_id !== $lineage) {
                throw OAuthServerException::invalidGrant();
            }

            return;
        }
        $this->connection()->table(self::MEMBERS)->insert([
            'credential_key' => $this->credentialKey($kind, $id), 'kind' => $kind, 'credential_id' => $id, 'lineage_id' => $lineage,
        ]);
    }

    private function findMember(string $kind, string $id, bool $current = false): ?object
    {
        return $this->connection()->table(self::MEMBERS)->where('credential_key', $this->credentialKey($kind, $id))->when($current, fn ($query) => $query->lockForUpdate())->first();
    }

    private function lockOwner(?string $owner): void
    {
        $key = $this->ownerKey($owner);
        $this->connection()->table(self::SCOPES)->insertOrIgnore(['scope_key' => $key, 'sequence' => 0]);
        $this->connection()->table(self::SCOPES)->where('scope_key', $key)->lockForUpdate()->firstOrFail();
    }

    private function sequence(): int
    {
        $sequence = $this->connection()->table(self::SCOPES)->where('scope_key', $this->clockKey())->value('sequence');

        return $sequence === null ? throw new RuntimeException('The credential revocation migration is required.') : (int) $sequence;
    }

    private function scopeSequence(string $key, bool $current = false): int
    {
        return (int) ($this->connection()->table(self::SCOPES)->where('scope_key', $key)->when($current, fn ($query) => $query->lockForUpdate())->value('sequence') ?? 0);
    }

    private function ownerKey(?string $owner): string
    {
        return hash('sha256', json_encode(['owner', $owner], JSON_THROW_ON_ERROR));
    }

    private function clientKey(?string $owner, string $client): string
    {
        return hash('sha256', json_encode(['client', $owner, $client], JSON_THROW_ON_ERROR));
    }

    private function credentialKey(string $kind, string $id): string
    {
        return hash('sha256', json_encode(['credential', $kind, $id], JSON_THROW_ON_ERROR));
    }

    private function clockKey(): string
    {
        return hash('sha256', 'bherila-auth.revocation-clock');
    }

    private function connection(): Connection
    {
        return Passport::token()->getConnection();
    }

    private function request(): ?Request
    {
        return app()->bound('request') ? app('request') : null;
    }

    private function sameConnection(Model $model): void
    {
        if ($model->getConnection()->getName() !== $this->connection()->getName()) {
            throw new RuntimeException('Durable OAuth credentials must share Passport\'s database connection.');
        }
    }

    private function requireEnabled(): void
    {
        if (! self::enabled()) {
            throw new RuntimeException('Durable credential revocation is disabled.');
        }
        $this->sameConnection(Passport::authCode());
        $this->sameConnection(Passport::refreshToken());
    }
}
