<?php

namespace BWH\Auth\OAuth\Credentials;

use BWH\Auth\OAuth\Server\CredentialLineages;
use BWH\Auth\OAuth\Server\OAuthResourceIndicator;
use BWH\Auth\OAuth\Server\ProviderIdentityTokens;
use Carbon\CarbonImmutable;
use DateInterval;
use DomainException;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Date;
use Laravel\Passport\Bridge\AccessTokenRepository;
use Laravel\Passport\Client;
use Laravel\Passport\ClientRepository;
use Laravel\Passport\Passport;
use Laravel\Passport\Token;
use RuntimeException;
use Throwable;

/**
 * A person's credentials for agents that use the REST API rather than MCP.
 *
 * Two kinds, both owned by the signed-in person and both bound to this
 * server's protected resource:
 *
 * - **personal API tokens** - chosen scopes, a lifetime from the configured
 *   set, for a connector that asks for "an API key";
 * - **OAuth apps** - exact HTTPS or loopback redirect URIs, public (PKCE only)
 *   or confidential (a secret returned once), and a scope ceiling that consent
 *   enforces, for a connector that runs the authorization-code flow.
 *
 * Issue these only from a signed-in browser session, never through an API or
 * OAuth token, so no credential can mint another. Callers return each secret
 * once, in a no-store response body; nothing here stores it readable.
 *
 * Neither kind carries an MCP connection scope (`resource_required_scopes`)
 * by default. An application may opt personal API tokens in, scope by scope,
 * with `credentials.personal_token_connection_scopes`, for connectors that
 * reach an MCP endpoint only with a static bearer key; such a token is held to
 * `credentials.personal_token_connection_max_lifetime`. OAuth apps never are:
 * they reach a connection through the authorization-code flow and its consent.
 *
 * It also lists the OAuth clients a person has connected - including clients
 * that registered themselves dynamically, as MCP agents do - and disconnects
 * one, revoking only that person's grants to it.
 */
final class ApiCredentialService
{
    /** A client that registered itself through dynamic client registration (RFC 7591). */
    public const string KIND_DYNAMIC = 'dynamic';

    /** A client a signed-in person registered: the person who connected it, or someone else. */
    public const string KIND_USER_REGISTERED = 'user_registered';

    /** An ownerless client the application itself provisioned. */
    public const string KIND_FIRST_PARTY = 'first_party';

    public function __construct(
        private readonly ClientRepository $clients,
        private readonly CredentialOwnerResolver $owners,
        private readonly GrantableScopes $grantable,
        private readonly AccessTokenRepository $accessTokens,
    ) {}

    /** @return array<string, string> */
    public function grantableScopes(): array
    {
        return $this->grantable->scopes();
    }

    /**
     * The bound ScopePresentation's groups, resolved against one surface's
     * `id => description` map (every offered scope exactly once; empty without groups).
     *
     * @param  array<string, string>  $offered
     * @return list<array{id: string, label: string, description: ?string, sensitive: bool, scopes: list<string>}>
     */
    public function scopeGroups(array $offered): array
    {
        return app(ScopePresentationResolver::class)->groups($offered);
    }

    /**
     * The bound presets whose every scope is offered on this surface.
     *
     * @param  array<string, string>  $offered
     * @return list<array{id: string, label: string, description: string, scopes: list<string>}>
     */
    public function scopePresets(array $offered): array
    {
        return app(ScopePresentationResolver::class)->presets($offered);
    }

    /**
     * The declared scope implications (transitive, catalog order) restricted to one surface.
     * Empty unless the bound presentation implements DeclaresScopeImplications.
     *
     * @param  array<string, string>  $offered
     * @return array<string, list<string>>
     */
    public function scopeImplications(array $offered): array
    {
        return app(ScopePresentationResolver::class)->implications($offered);
    }

    /** Whether the application bound any scope group or preset. */
    public function scopePresentationActive(): bool
    {
        return app(ScopePresentationResolver::class)->active();
    }

    /**
     * The connection scopes a personal API token may carry, `identifier =>
     * description`: empty unless the application opted in.
     *
     * Each is named in `credentials.personal_token_connection_scopes`, is one of
     * `resource_required_scopes`, is in the scope catalog and is not in
     * `credentials.excluded_scopes`. None is offered when no configured lifetime
     * fits under the connection maximum, since no such token could be issued.
     *
     * @return array<string, string>
     */
    public function connectionScopes(): array
    {
        if ($this->connectionLifetimes() === []) {
            return [];
        }
        $catalog = ConfiguredGrantableScopes::catalog();
        $required = OAuthResourceIndicator::requiredScopes();
        $excluded = ConfiguredGrantableScopes::excludedScopes();

        $scopes = [];
        foreach ($this->configuredConnectionScopes() as $id) {
            if (in_array($id, $required, true) && array_key_exists($id, $catalog) && ! in_array($id, $excluded, true)) {
                $scopes[$id] = $catalog[$id];
            }
        }

        return $scopes;
    }

    /** Whether the application opted personal API tokens in to any connection scope. */
    public function connectionScopesEnabled(): bool
    {
        return $this->configuredConnectionScopes() !== [];
    }

    /**
     * Every scope a personal API token may carry: the grantable scopes, plus the
     * opted-in connection scopes. OAuth apps are offered only the former.
     *
     * @return array<string, string>
     */
    public function tokenScopes(): array
    {
        // Only scopes the personal-token resource admits, so every offered choice can be issued.
        $resource = $this->credentialResource();

        return array_filter(
            $this->grantableScopes() + $this->connectionScopes(),
            static fn (string $scope): bool => OAuthResourceIndicator::scopesAllowedFor($resource, [$scope]),
            ARRAY_FILTER_USE_KEY,
        );
    }

    /**
     * The offered lifetimes a token that opens a connection may have: those no
     * longer than `credentials.personal_token_connection_max_lifetime`. Empty
     * while the opt-in is off, and when the maximum is not a valid ISO-8601
     * duration (fail closed).
     *
     * @return list<string>
     */
    public function connectionLifetimes(): array
    {
        $maximum = $this->connectionScopesEnabled() ? $this->connectionMaxLifetime() : null;
        if ($maximum === null) {
            return [];
        }
        $now = CarbonImmutable::instance(Date::now());
        $limit = $now->add($maximum);

        return array_values(array_filter(
            $this->lifetimes(),
            static fn (string $spec): bool => $now->add(new DateInterval($spec)) <= $limit,
        ));
    }

    /**
     * Whether these scopes open an MCP connection (any `resource_required_scopes`
     * entry), however the scope came to be granted.
     *
     * @param  list<string>  $scopes
     */
    public function carriesConnectionScope(array $scopes): bool
    {
        return OAuthResourceIndicator::scopesRequireResource($scopes);
    }

    /**
     * The token lifetimes on offer, as ISO-8601 durations (PT4H, P30D...).
     *
     * @return list<string>
     */
    public function lifetimes(): array
    {
        $configured = config('bherila-auth.oauth_server.credentials.token_lifetimes', ['P30D', 'P90D', 'P365D']);

        return array_values(array_filter(array_map('strval', (array) $configured), static function (string $spec): bool {
            try {
                new DateInterval($spec);

                return true;
            } catch (Throwable) {
                return false;
            }
        }));
    }

    /**
     * @param  list<string>  $scopes
     * @return array{id: string, token: string, expires_at: string}
     */
    public function issueToken(Authenticatable $user, string $name, array $scopes, string $lifetime): array
    {
        $this->assertOffered($scopes, $this->tokenScopes());
        if (! in_array($lifetime, $this->lifetimes(), true)) {
            throw new DomainException('Choose one of the offered token lifetimes.');
        }
        // Once opted in, every connection-carrying token is capped - including
        // one whose scope a custom GrantableScopes binding already offered.
        if ($this->connectionScopesEnabled()
            && $this->carriesConnectionScope($scopes)
            && ! in_array($lifetime, $this->connectionLifetimes(), true)) {
            throw new DomainException('A token that can open a connection must have a shorter lifetime.');
        }
        if (! OAuthResourceIndicator::scopesAllowedFor($this->credentialResource(), $scopes)) {
            throw new DomainException('A personal token cannot carry a scope its resource does not admit.');
        }
        $owner = $this->owners->owner($user);
        $this->ensurePersonalClient();
        $expiresAt = CarbonImmutable::instance(Date::now())->add(new DateInterval($lifetime));

        $request = request();
        $resource = $this->credentialResource();
        $request->attributes->set(OAuthResourceIndicator::REQUEST_ATTRIBUTE, $resource);
        $previous = Passport::$personalAccessTokensExpireIn;
        Passport::personalAccessTokensExpireIn($expiresAt);
        try {
            /** @var \Laravel\Passport\PersonalAccessTokenResult $issued */
            $issued = $owner->createToken($this->prefix().trim($name), array_values(array_unique($scopes)));
        } finally {
            Passport::$personalAccessTokensExpireIn = $previous;
            $request->attributes->remove(OAuthResourceIndicator::REQUEST_ATTRIBUTE);
        }

        // Never hand out a credential that is not what this says it is: issued
        // to this owner and bound to this resource.
        Passport::token()->newQuery()
            ->whereKey($issued->accessTokenId)
            ->where('user_id', $owner->getAuthIdentifier())
            // The repository persists the canonical form of the configured resource.
            ->where($this->resourceColumn(), $resource)
            ->firstOrFail();

        return ['id' => (string) $issued->accessTokenId, 'token' => (string) $issued->accessToken, 'expires_at' => $expiresAt->toIso8601String()];
    }

    /** @return list<array{id: string, name: string, scopes: list<string>, created_at: string|null, expires_at: string|null}> */
    public function tokens(Authenticatable $user): array
    {
        $owner = $this->owners->owner($user);

        return array_values(Passport::token()->newQuery()
            ->where('user_id', $owner->getAuthIdentifier())
            ->where('revoked', false)
            ->where('expires_at', '>', Date::now())
            ->orderByDesc('created_at')
            ->get()
            // A literal prefix check, not SQL LIKE: `%` or `_` in a configured
            // prefix must not sweep in tokens this service never issued.
            ->filter(fn (Token $token): bool => str_starts_with((string) $token->name, $this->prefix()))
            ->map(fn (Token $token): array => [
                'id' => (string) $token->getKey(),
                'name' => substr((string) $token->name, strlen($this->prefix())),
                'scopes' => array_values(array_map('strval', (array) $token->scopes)),
                'created_at' => $token->created_at?->toIso8601String(),
                'expires_at' => $token->expires_at?->toIso8601String(),
            ])
            ->all());
    }

    public function revokeToken(Authenticatable $user, string $tokenId): void
    {
        $owner = $this->owners->owner($user);
        $token = Passport::token()->newQuery()
            ->whereKey($tokenId)
            ->where('user_id', $owner->getAuthIdentifier())
            ->where('revoked', false)
            ->first();
        abort_unless($token instanceof Token && str_starts_with((string) $token->name, $this->prefix()), 404);

        // Through Passport's repository, which dispatches AccessTokenRevoked for
        // listeners that invalidate caches or audit revocations.
        $this->accessTokens->revokeAccessToken($tokenId);
    }

    /**
     * @param  list<string>  $redirectUris
     * @param  list<string>  $scopes
     * @return array{client: Client, secret: string|null}
     */
    public function registerApp(Authenticatable $user, string $name, array $redirectUris, bool $confidential, array $scopes): array
    {
        $this->assertOffered($scopes, $this->grantableScopes());
        if ($redirectUris === []) {
            throw new DomainException('Give at least one redirect URI.');
        }
        foreach ($redirectUris as $uri) {
            if (! self::validRedirectUri($uri)) {
                throw new DomainException('Redirect URIs must be https, or http on a loopback address, with no fragment or credentials.');
            }
        }
        $owner = $this->owners->owner($user);

        // On Passport's own connection, which need not be the default one.
        return Passport::client()->getConnection()->transaction(function () use ($owner, $name, $redirectUris, $confidential, $scopes): array {
            // Created with its owner: Passport treats an ownerless client as
            // first-party, which an app a person registers must never be.
            $client = $this->clients->createAuthorizationCodeGrantClient(
                trim($name),
                array_values(array_unique($redirectUris)),
                $confidential,
                $owner,
            );
            // Read once, here: the stored secret is hashed.
            $secret = $confidential ? $client->plainSecret : null;
            // The consent ceiling (EnforceOAuthResourceIndicator holds any client to
            // its stored scopes). Encoded by hand where the model does not cast the
            // column, as the registration controller does.
            $column = $this->scopesColumn();
            $ceiling = array_values(array_unique($scopes));
            $client->forceFill([$column => $client->hasCast($column, ['array', 'json', 'collection'])
                ? $ceiling
                : json_encode($ceiling, JSON_THROW_ON_ERROR)])->save();

            return ['client' => $client, 'secret' => $secret];
        });
    }

    /** @return list<array{id: string, name: string, confidential: bool, redirect_uris: list<string>, scopes: list<string>, created_at: string|null}> */
    public function apps(Authenticatable $user): array
    {
        $owner = $this->owners->owner($user);

        return array_values($this->ownedClients($owner)
            ->where('revoked', false)
            ->orderBy('name')
            ->get()
            ->map(fn (Client $client): array => [
                'id' => (string) $client->getKey(),
                'name' => (string) $client->name,
                'confidential' => $client->confidential(),
                'redirect_uris' => array_values(array_map('strval', (array) $client->getAttribute('redirect_uris'))),
                'scopes' => $this->storedScopes($client->getAttribute($this->scopesColumn())),
                'created_at' => $client->created_at?->toIso8601String(),
            ])
            ->all());
    }

    /** Revoke the app and every access and refresh token issued to it. */
    public function deleteApp(Authenticatable $user, string $clientId): void
    {
        $owner = $this->owners->owner($user);
        $client = $this->ownedClients($owner)->where('revoked', false)->whereKey($clientId)->first();
        abort_unless($client instanceof Client, 404);

        Passport::token()->getConnection()->transaction(function () use ($client): void {
            $tokenIds = Passport::token()->newQuery()->where('client_id', $client->getKey())->pluck('id');
            $refreshTokens = Passport::refreshToken();
            $refresh = $refreshTokens->newQuery()->whereIn('access_token_id', $tokenIds);
            // Keep the linked-access fallback for older schemas and unstamped legacy rows.
            // The refresh token's own client record survives an access-token purge.
            if ($refreshTokens->getConnection()->getSchemaBuilder()->hasColumn($refreshTokens->getTable(), 'client_id')) {
                $refresh->orWhere('client_id', (string) $client->getKey());
            }
            $refresh->update(['revoked' => true]);
            foreach (Passport::token()->newQuery()->where('client_id', $client->getKey())->where('revoked', false)->pluck('id') as $tokenId) {
                // One at a time through the repository so AccessTokenRevoked fires.
                $this->accessTokens->revokeAccessToken((string) $tokenId);
            }
            $client->forceFill(['revoked' => true])->save();
        });
    }

    /**
     * Every OAuth client that holds a live grant for this person: an unrevoked,
     * unexpired access token, or an unrevoked, unexpired refresh token (also one
     * whose access-token row has been purged). Dynamically registered clients are
     * included. Personal-access clients are not - personal tokens are listed and
     * revoked one by one through tokens() - and neither are revoked clients, whose
     * tokens Passport already refuses.
     *
     * `scopes` is the union of the scopes on the person's live grants that still
     * name them. `created_at` is when the client was registered. `last_issued_at`
     * is when a token was last issued to this person for the client, by
     * authorization or refresh: Passport does not record each bearer use, so this
     * is the latest point the client is known to have been active. No client
     * secret, hashed or otherwise, is ever returned.
     *
     * @return list<array{id: string, name: string, kind: 'dynamic'|'user_registered'|'first_party', scopes: list<string>, redirect_uris: list<string>, created_at: string|null, last_issued_at: string|null}>
     */
    public function connectedClients(Authenticatable $user): array
    {
        $ownerId = $this->owners->owner($user)->getAuthIdentifier();
        $now = Date::now();
        /** @var array<string, array{scopes: list<string>, last: CarbonImmutable|null}> $grants */
        $grants = [];
        $remember = function (string $clientId, mixed $scopes, mixed $issuedAt) use (&$grants): void {
            $grant = $grants[$clientId] ?? ['scopes' => [], 'last' => null];
            $grant['scopes'] = array_values(array_unique([...$grant['scopes'], ...$this->storedScopes($scopes)]));
            if ($issuedAt !== null && $issuedAt !== '') {
                $issued = CarbonImmutable::parse($issuedAt);
                $grant['last'] = $grant['last'] === null || $issued->greaterThan($grant['last']) ? $issued : $grant['last'];
            }
            $grants[$clientId] = $grant;
        };

        $tokens = Passport::token();
        foreach ($tokens->newQuery()->toBase()
            ->where('user_id', $ownerId)
            ->where('revoked', false)
            ->where('expires_at', '>', $now)
            ->get(['client_id', 'scopes', 'created_at']) as $row) {
            $remember((string) $row->client_id, $row->scopes, $row->created_at);
        }

        $refreshTokens = Passport::refreshToken();
        $refreshTable = $refreshTokens->getTable();
        $hasClient = $this->hasColumn($refreshTokens, 'client_id');
        $hasOwner = $this->hasColumn($refreshTokens, ProviderIdentityTokens::OWNER_COLUMN);
        $refresh = $refreshTokens->getConnection()->table($refreshTable.' as refresh')
            ->leftJoin($tokens->getTable().' as access', 'access.'.$tokens->getKeyName(), '=', 'refresh.access_token_id')
            ->where('refresh.revoked', false)
            ->where('refresh.expires_at', '>', $now)
            ->where(function ($query) use ($ownerId, $hasOwner): void {
                $query->where('access.user_id', $ownerId);
                if ($hasOwner) {
                    // The refresh token's own owner record outlives a purged access row.
                    $query->orWhere('refresh.'.ProviderIdentityTokens::OWNER_COLUMN, (string) $ownerId);
                }
            });
        $columns = ['access.client_id as access_client_id', 'access.user_id as access_user_id', 'access.scopes as access_scopes', 'access.created_at as access_created_at'];
        if ($hasClient) {
            $columns[] = 'refresh.client_id as refresh_client_id';
        }
        foreach ($refresh->get($columns) as $row) {
            // A linked access row names its owner; never take another person's grant on the
            // strength of a refresh-token owner record that disagrees with it.
            if ($row->access_user_id !== null && (string) $row->access_user_id !== (string) $ownerId) {
                continue;
            }
            $clientId = $hasClient && $row->refresh_client_id !== null ? $row->refresh_client_id : $row->access_client_id;
            if ($clientId !== null && $clientId !== '') {
                $remember((string) $clientId, $row->access_scopes, $row->access_created_at);
            }
        }

        if ($grants === []) {
            return [];
        }

        $connected = [];
        foreach (Passport::client()->newQuery()->whereKey(array_map('strval', array_keys($grants)))->where('revoked', false)->get() as $client) {
            if ($client->hasGrantType('personal_access')) {
                continue;
            }
            $grant = $grants[(string) $client->getKey()];
            $scopes = $grant['scopes'];
            sort($scopes);
            $connected[] = [
                'id' => (string) $client->getKey(),
                'name' => (string) $client->name,
                'kind' => $this->registrationKind($client),
                'scopes' => $scopes,
                'redirect_uris' => array_values(array_map('strval', (array) $client->getAttribute('redirect_uris'))),
                'created_at' => $client->created_at?->toIso8601String(),
                'last_issued_at' => $grant['last']?->toIso8601String(),
            ];
        }
        usort($connected, static fn (array $a, array $b): int => [$b['last_issued_at'] ?? '', $a['name'], $a['id']] <=> [$a['last_issued_at'] ?? '', $b['name'], $b['id']]);

        return $connected;
    }

    /**
     * Disconnect a client from this person: revoke every authorization code,
     * access token and refresh token of theirs it holds, effective on the next
     * request. Other people's grants to the same client and the client's
     * registration are left alone, so the person can connect it again later.
     * Idempotent: an unknown client, one already disconnected, or a personal-access
     * client (whose tokens revokeToken() handles) changes nothing.
     * With durable revocation enabled, it also raises the owner/client barrier so
     * a grant already in flight cannot be persisted afterwards.
     *
     * Returns how many live access tokens it revoked.
     */
    public function disconnectClient(Authenticatable $user, string $clientId): int
    {
        $ownerId = $this->owners->owner($user)->getAuthIdentifier();
        $client = Passport::client()->newQuery()->whereKey($clientId)->first();
        // Personal tokens are revoked one by one through revokeToken(), never wholesale.
        if (! $client instanceof Client || $client->hasGrantType('personal_access')) {
            return 0;
        }
        $clientId = (string) $client->getKey();
        $revoke = fn (): int => $this->revokeClientGrants($ownerId, $clientId);

        if (CredentialLineages::enabled()) {
            return app(CredentialLineages::class)->revokingOwner($ownerId, $clientId, $revoke);
        }

        return Passport::token()->getConnection()->transaction($revoke);
    }

    private function revokeClientGrants(string|int $ownerId, string $clientId): int
    {
        $tokens = Passport::token();
        $owned = fn () => $tokens->newQuery()->where('user_id', $ownerId)->where('client_id', $clientId);

        $refreshTokens = Passport::refreshToken();
        $refresh = $refreshTokens->newQuery()->where('revoked', false)->where(function ($query) use ($owned, $refreshTokens, $ownerId, $clientId): void {
            $query->whereIn('access_token_id', $owned()->select(Passport::token()->getKeyName()));
            // A refresh token whose access row was purged, by its own owner and client records.
            // Only once that row is gone: a linked access row names its owner, and one that
            // names someone else outranks an owner record that disagrees with it.
            if ($this->hasColumn($refreshTokens, 'client_id') && $this->hasColumn($refreshTokens, ProviderIdentityTokens::OWNER_COLUMN)) {
                $tokens = Passport::token();
                $query->orWhere(fn ($orphan) => $orphan
                    ->where('client_id', $clientId)
                    ->where(ProviderIdentityTokens::OWNER_COLUMN, (string) $ownerId)
                    ->whereNotExists(fn ($access) => $access
                        ->from($tokens->getTable())
                        ->whereColumn($tokens->getTable().'.'.$tokens->getKeyName(), $refreshTokens->getTable().'.access_token_id')));
            }
        });
        $refresh->update(['revoked' => true]);
        Passport::authCode()->newQuery()->where('user_id', $ownerId)->where('client_id', $clientId)->where('revoked', false)->update(['revoked' => true]);

        $live = $owned()->where('revoked', false)->pluck($tokens->getKeyName());
        foreach ($live as $tokenId) {
            // One at a time through the repository so AccessTokenRevoked fires.
            $this->accessTokens->revokeAccessToken((string) $tokenId);
        }

        return $live->count();
    }

    /** @return self::KIND_* */
    private function registrationKind(Client $client): string
    {
        $registeredAt = config('bherila-auth.oauth_server.dynamic_clients.registered_at_column', 'dynamically_registered_at');
        if (is_string($registeredAt) && $registeredAt !== '' && ($client->getAttributes()[$registeredAt] ?? null) !== null) {
            return self::KIND_DYNAMIC;
        }

        return $client->firstParty() ? self::KIND_FIRST_PARTY : self::KIND_USER_REGISTERED;
    }

    private function hasColumn(Model $model, string $column): bool
    {
        return $model->getConnection()->getSchemaBuilder()->hasColumn($model->getTable(), $column);
    }

    /**
     * The owner's clients, on either Passport schema: the `owner` morph, or a
     * retained legacy `user_id` column - which Passport's own repository also
     * detects and writes through when it registers the app.
     *
     * @return \Illuminate\Database\Eloquent\Builder<Client>|\Illuminate\Database\Eloquent\Relations\MorphMany<Client, Model>
     */
    private function ownedClients(Model $owner): \Illuminate\Database\Eloquent\Builder|\Illuminate\Database\Eloquent\Relations\MorphMany
    {
        $client = Passport::client();
        if ($client->getConnection()->getSchemaBuilder()->hasColumn($client->getTable(), 'user_id')) {
            return $client->newQuery()->where('user_id', $owner->getAuthIdentifier());
        }

        return $owner->oauthApps();
    }

    public static function validRedirectUri(string $uri): bool
    {
        if (strlen($uri) > 2048 || filter_var($uri, FILTER_VALIDATE_URL) === false) {
            return false;
        }
        $parts = parse_url($uri);
        if (! is_array($parts) || isset($parts['fragment']) || isset($parts['user']) || isset($parts['pass'])) {
            return false;
        }
        $scheme = strtolower((string) ($parts['scheme'] ?? ''));
        $host = strtolower(trim((string) ($parts['host'] ?? ''), '[]'));

        return ($scheme === 'https' && $host !== '')
            || ($scheme === 'http' && in_array($host, ['127.0.0.1', '::1', 'localhost'], true));
    }

    /**
     * @param  list<string>  $scopes
     * @param  array<string, string>  $offered
     */
    private function assertOffered(array $scopes, array $offered): void
    {
        if ($scopes === [] || array_diff($scopes, array_keys($offered)) !== []) {
            throw new DomainException('Choose at least one of the offered permissions.');
        }
    }

    /** @return list<string> */
    private function configuredConnectionScopes(): array
    {
        $configured = config('bherila-auth.oauth_server.credentials.personal_token_connection_scopes', []);

        $scopes = [];
        foreach (is_array($configured) ? $configured : [] as $scope) {
            if (is_string($scope) && trim($scope) !== '') {
                $scopes[] = trim($scope);
            }
        }

        return array_values(array_unique($scopes));
    }

    private function connectionMaxLifetime(): ?DateInterval
    {
        $spec = config('bherila-auth.oauth_server.credentials.personal_token_connection_max_lifetime', 'P30D');
        if (! is_string($spec) || $spec === '') {
            return null;
        }
        try {
            return new DateInterval($spec);
        } catch (Throwable) {
            return null;
        }
    }

    /**
     * Passport issues every personal token through the newest personal-access
     * client for the provider - which may be another caller's - so tokens here
     * are told apart by owner and name, never by client. One is created only
     * when none exists, so it is never newer than a client another caller
     * relies on being newest.
     */
    private function ensurePersonalClient(): void
    {
        $provider = $this->provider();
        try {
            $this->clients->personalAccessClient($provider);
        } catch (RuntimeException) {
            $this->clients->createPersonalAccessGrantClient(
                (string) config('bherila-auth.oauth_server.credentials.personal_client_name', 'Personal access tokens'),
                $provider,
            );
        }
    }

    private function provider(): string
    {
        $provider = config('bherila-auth.oauth_server.credentials.provider') ?? config('auth.guards.api.provider', 'users');

        return is_string($provider) && $provider !== '' ? $provider : 'users';
    }

    /** @return list<string> */
    private function storedScopes(mixed $value): array
    {
        if (is_string($value)) {
            $decoded = json_decode($value, true);
            $value = is_array($decoded) ? $decoded : [];
        }
        if ($value instanceof \Illuminate\Support\Collection) {
            $value = $value->all();
        }

        return array_values(array_map('strval', is_array($value) ? $value : []));
    }

    private function prefix(): string
    {
        return (string) config('bherila-auth.oauth_server.credentials.token_name_prefix', 'api-token: ');
    }

    private function scopesColumn(): string
    {
        $column = config('bherila-auth.oauth_server.dynamic_clients.scopes_column', 'scopes');

        return is_string($column) && $column !== '' ? $column : 'scopes';
    }

    /**
     * The resource personal tokens are bound to: `credentials.resource` names one, otherwise
     * the default resource. Personal tokens are REST credentials.
     */
    private function credentialResource(): string
    {
        $name = config('bherila-auth.oauth_server.credentials.resource');

        return OAuthResourceIndicator::resource(is_string($name) && $name !== '' ? $name : null);
    }

    private function resourceColumn(): string
    {
        $column = config('bherila-auth.oauth_server.resource_column', 'resource_uri');

        return is_string($column) && $column !== '' ? $column : 'resource_uri';
    }
}
