<?php

namespace BWH\Auth\OAuth\Credentials;

use BWH\Auth\OAuth\Server\OAuthResourceIndicator;
use Carbon\CarbonImmutable;
use DateInterval;
use DomainException;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Date;
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
 */
final class ApiCredentialService
{
    public function __construct(
        private readonly ClientRepository $clients,
        private readonly CredentialOwnerResolver $owners,
        private readonly GrantableScopes $grantable,
    ) {}

    /** @return array<string, string> */
    public function grantableScopes(): array
    {
        return $this->grantable->scopes();
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
        $this->assertGrantable($scopes);
        if (! in_array($lifetime, $this->lifetimes(), true)) {
            throw new DomainException('Choose one of the offered token lifetimes.');
        }
        $owner = $this->owners->owner($user);
        $this->ensurePersonalClient();
        $expiresAt = CarbonImmutable::instance(Date::now())->add(new DateInterval($lifetime));

        $request = request();
        $request->attributes->set(OAuthResourceIndicator::REQUEST_ATTRIBUTE, OAuthResourceIndicator::configuredCanonical());
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
            ->where('user_id', $owner->getKey())
            ->where($this->resourceColumn(), OAuthResourceIndicator::resource())
            ->firstOrFail();

        return ['id' => (string) $issued->accessTokenId, 'token' => (string) $issued->accessToken, 'expires_at' => $expiresAt->toIso8601String()];
    }

    /** @return list<array{id: string, name: string, scopes: list<string>, created_at: string|null, expires_at: string|null}> */
    public function tokens(Authenticatable $user): array
    {
        $owner = $this->owners->owner($user);

        return array_values(Passport::token()->newQuery()
            ->where('user_id', $owner->getKey())
            ->where('revoked', false)
            ->where('expires_at', '>', Date::now())
            ->where('name', 'like', $this->prefix().'%')
            ->orderByDesc('created_at')
            ->get()
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
        $revoked = Passport::token()->newQuery()
            ->whereKey($tokenId)
            ->where('user_id', $owner->getKey())
            ->where('revoked', false)
            ->where('name', 'like', $this->prefix().'%')
            ->update(['revoked' => true, 'updated_at' => Date::now()]);
        abort_if($revoked === 0, 404);
    }

    /**
     * @param  list<string>  $redirectUris
     * @param  list<string>  $scopes
     * @return array{client: Client, secret: string|null}
     */
    public function registerApp(Authenticatable $user, string $name, array $redirectUris, bool $confidential, array $scopes): array
    {
        $this->assertGrantable($scopes);
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

        return array_values($owner->oauthApps()
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
        $client = $owner->oauthApps()->where('revoked', false)->whereKey($clientId)->first();
        abort_unless($client instanceof Client, 404);

        Passport::token()->getConnection()->transaction(static function () use ($client): void {
            $tokenIds = Passport::token()->newQuery()->where('client_id', $client->getKey())->pluck('id');
            Passport::refreshToken()->newQuery()->whereIn('access_token_id', $tokenIds)->update(['revoked' => true]);
            Passport::token()->newQuery()->where('client_id', $client->getKey())->update(['revoked' => true, 'updated_at' => Date::now()]);
            $client->forceFill(['revoked' => true])->save();
        });
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

    /** @param list<string> $scopes */
    private function assertGrantable(array $scopes): void
    {
        if ($scopes === [] || array_diff($scopes, array_keys($this->grantableScopes())) !== []) {
            throw new DomainException('Choose at least one of the offered permissions.');
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

    private function resourceColumn(): string
    {
        $column = config('bherila-auth.oauth_server.resource_column', 'resource_uri');

        return is_string($column) && $column !== '' ? $column : 'resource_uri';
    }
}
