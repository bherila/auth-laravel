<?php

namespace BWH\Auth\OAuth;

use BWH\Auth\OAuth\Client\AuthorizationServer;
use BWH\Auth\OAuth\Client\AuthorizationServerMetadata;
use BWH\Auth\OAuth\Client\OAuthHttpTransport;
use BWH\Auth\OAuth\Client\PendingFlow;
use Carbon\CarbonImmutable;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Client\Response;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;
use InvalidArgumentException;
use SensitiveParameter;
use Stringable;
use Symfony\Component\HttpFoundation\HeaderUtils;

/**
 * Authorization-code + S256 PKCE client for the sign-in provider and, optionally, other
 * authorization servers this application calls APIs on for a person.
 *
 * The container's instance is the sign-in provider (`oauth_client`); {@see forServer()}
 * gives one for an entry of `oauth_client.servers`. Each server has its own static
 * callback, and every pending flow is bound to the person that started it, the
 * server (and exact issuer) it was sent to, the callback, the resource and the verifier.
 * A response is checked against all of them, and against RFC 9207 `iss`, before its code is
 * exchanged. Named flows live in cache; the sign-in provider retains its session binding.
 */
final class OAuthClient
{
    private readonly AuthorizationServer $explicitServer;

    private readonly ?OAuthHttpTransport $transport;

    public function __construct(private readonly ?string $server = null) {}

    /**
     * Whether a client has been issued for this application at the provider, or, given a
     * name, whether that entry of `oauth_client.servers` has a client id and issuer.
     *
     * Every other method here aborts 503 on a missing setting, which is the right answer
     * for a half-configured deploy but the wrong one for an application that is meant to
     * run without a provider at all — local development, or a deploy that has not been
     * registered yet. Asking first lets a relying party fall back to its own sign-in, or
     * 404 the OAuth routes, instead of presenting an outage.
     *
     * `base_url` carries a default, so in practice this is a question about `client_id`;
     * both are checked because a blanked-out base URL would fail later and less clearly.
     */
    public static function isConfigured(?string $server = null): bool
    {
        return AuthorizationServer::isConfigured($server);
    }

    /** The client for a named entry of `oauth_client.servers` (not `default`, the sign-in provider). */
    public function forServer(string $name): self
    {
        return new self($name);
    }

    /**
     * A new named client with an immutable settings snapshot, without changing configuration.
     * The caller supplies these same trusted settings again for the callback and refresh.
     *
     * @param  array<string, mixed>  $settings
     */
    public function forServerSettings(string $name, #[SensitiveParameter] array $settings, ?OAuthHttpTransport $transport = null): self
    {
        $client = new self($name);
        $client->explicitServer = AuthorizationServer::fromSettings($name, $settings);
        $client->transport = $transport;

        return $client;
    }

    /** @return array{server: string} */
    public function __debugInfo(): array
    {
        return ['server' => $this->serverName()];
    }

    /** `default` for the sign-in provider, else the named server's key. */
    public function serverName(): string
    {
        return $this->server ?? AuthorizationServer::DEFAULT;
    }

    /** The exact issuer this server's authorization responses must name in `iss`. */
    public function issuer(): string
    {
        return $this->authorizationServer()->issuer();
    }

    public function redirect(Request $request): RedirectResponse
    {
        $server = $this->authorizationServer();
        $user = $this->userKey($request);
        abort_unless($server->isDefault() || ($user !== null && $user !== ''), 403, 'Sign in before connecting an authorization server.');
        $state = Str::random(40);
        $verifier = Str::random(96);
        $challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');

        $flow = new PendingFlow(
            server: $server->name,
            issuer: $server->issuer(),
            callback: $server->value('redirect_uri'),
            resource: $server->resource(),
            verifier: $verifier,
            issuerRequired: $this->issuerRequired($server),
            userBound: true,
            user: $user,
            startedAt: Carbon::now()->getTimestamp(),
            scope: $server->value('scope'),
        );

        $authorize = $server->endpoint('authorize_path');
        $parameters = array_filter([
            'client_id' => $server->value('client_id'),
            'redirect_uri' => $flow->callback,
            'response_type' => 'code',
            'scope' => $flow->scope,
            'state' => $state,
            'code_challenge' => $challenge,
            'code_challenge_method' => 'S256',
            'resource' => $flow->resource,
        ], static fn (?string $value): bool => $value !== null);

        $flow->store($request->session(), $state);

        return redirect()->away($authorize.'?'.http_build_query($parameters));
    }

    /**
     * Verify an authorization response and exchange its code for tokens.
     *
     * Every check runs before the code leaves this application: a pending flow for this
     * `state` in the named-flow cache or legacy sign-in session (consumed whatever happens
     * next), not expired, started for
     * this server with its current issuer, callback and resource, arriving at this server's
     * callback (named servers), from the same signed-in person, then RFC 9207 `iss`.
     *
     * @throws OAuthCallbackRejected (403) when the response is refused
     * @throws OAuthTokenRequestFailed (502) when the server does not return a usable token
     */
    public function tokensFromCallback(Request $request): OAuthTokens
    {
        $server = $this->authorizationServer();
        [$flow, $code] = $this->verifiedResponse($request, $server);

        return $this->requestTokens($server, $flow->issuer, $flow->resource, [
            'grant_type' => 'authorization_code',
            'client_id' => $server->value('client_id'),
            'client_secret' => $server->value('client_secret'),
            'redirect_uri' => $flow->callback,
            'code' => $code,
            'code_verifier' => $flow->verifier,
        ], 'The identity provider rejected the authorization code.',
            // What the flow requested, not today's setting; unknown for a flow that predates it.
            $flow->scope === null ? null : self::scopeList($flow->scope),
        );
    }

    /**
     * Exchange a refresh token at this server's configured token endpoint, for its
     * configured resource.
     *
     * Servers that rotate refresh tokens revoke the whole family when an old one is reused,
     * so persist the returned refresh token in the same transaction that sent the old one.
     * When {@see OAuthTokenRequestFailed::$definitive} is false the server may have rotated
     * already: do not retry with the old token.
     *
     * A refresh response that omits `scope` leaves the grant unchanged (RFC 6749 §6), so
     * pass the scopes granted so far: they are what {@see OAuthTokens::$scopes} reports then.
     * Without them it is null, never the configured request, which may be broader than what
     * was granted.
     *
     * @param  list<string>|null  $grantedScopes  the scopes the grant currently carries
     *
     * @throws OAuthTokenRequestFailed (502)
     * @throws InvalidArgumentException when $refreshToken is not a non-empty 1*VSCHAR token, or
     *                                  $grantedScopes is not a list of scope tokens; nothing is sent
     */
    public function refreshTokens(#[SensitiveParameter] string $refreshToken, ?array $grantedScopes = null): OAuthTokens
    {
        if (! self::isToken($refreshToken)) {
            throw new InvalidArgumentException('The refresh token is not a valid OAuth token.');
        }

        if ($grantedScopes !== null && (! array_is_list($grantedScopes) || array_filter(
            $grantedScopes,
            static fn (mixed $scope): bool => ! is_string($scope) || preg_match('/^[\x21\x23-\x5B\x5D-\x7E]+\z/', $scope) !== 1,
        ) !== [])) {
            throw new InvalidArgumentException('Granted scopes must be a list of OAuth scope tokens.');
        }

        $server = $this->authorizationServer();

        return $this->requestTokens($server, $server->issuer(), $server->resource(), [
            'grant_type' => 'refresh_token',
            'client_id' => $server->value('client_id'),
            'client_secret' => $server->value('client_secret'),
            'refresh_token' => $refreshToken,
        ], 'The authorization server refused the refresh token.', $grantedScopes, $refreshToken);
    }

    public function identityFromCallback(Request $request): OAuthIdentity
    {
        $tokens = $this->tokensFromCallback($request);

        $url = $this->authorizationServer()->endpoint('identity_path');
        $request = Http::acceptJson()->withToken($tokens->accessToken);
        $outbound = ($this->transport ?? null)?->prepare($request, $url) ?? $request;
        $identityResponse = $outbound->get($url);

        return $this->validatedIdentity($identityResponse);
    }

    /**
     * @return array{PendingFlow, string}
     */
    private function verifiedResponse(Request $request, AuthorizationServer $server): array
    {
        $query = $request->query;
        $flow = PendingFlow::pull(
            $request->session(),
            $server->name,
            $query->all()['state'] ?? null,
            fn (string $verifier): PendingFlow => new PendingFlow(
                server: $server->name,
                issuer: $server->issuer(),
                callback: $server->value('redirect_uri'),
                resource: $server->resource(),
                verifier: $verifier,
                issuerRequired: $this->issuerRequired($server),
                userBound: false,
                user: null,
                startedAt: null,
            ),
        );

        $reject = static fn (OAuthCallbackFailure $reason, ?string $error = null) => new OAuthCallbackRejected($reason, $error);

        if ($flow === null) {
            throw $reject(OAuthCallbackFailure::StateMismatch);
        }
        if ($flow->isExpired()) {
            throw $reject(OAuthCallbackFailure::Expired);
        }
        if ($flow->server !== $server->name
            || $flow->issuer !== $server->issuer()
            || $flow->callback !== $server->value('redirect_uri')
            || $flow->resource !== $server->resource()) {
            throw $reject(OAuthCallbackFailure::ServerMismatch);
        }
        // The sign-in provider's callback route has never been checked against its setting,
        // and applications (and their tests) mount it at other paths; it is distinguished by
        // its own session keys instead.
        if (! $server->isDefault() && $request->getBaseUrl().$request->getPathInfo() !== $server->callbackPath()) {
            throw $reject(OAuthCallbackFailure::CallbackMismatch);
        }
        $user = $this->userKey($request);
        if ((! $server->isDefault() && ($user === null || $user === '')) || ($flow->userBound && $flow->user !== $user)) {
            throw $reject(OAuthCallbackFailure::UserMismatch);
        }

        // RFC 9207 §2.4: an `iss` that is present must be the issuer the request went to, on
        // error responses too; one that is expected must be present. Read from the raw query
        // string, so input middleware that trims or nulls values cannot make one match.
        $raw = $request->server->get('QUERY_STRING');
        $raw = is_string($raw) ? HeaderUtils::parseQuery($raw) : $query->all();
        if (array_key_exists('iss', $raw)) {
            if ($raw['iss'] !== $flow->issuer) {
                throw $reject(OAuthCallbackFailure::IssuerMismatch);
            }
        } elseif ($flow->issuerRequired) {
            throw $reject(OAuthCallbackFailure::IssuerMissing);
        }

        if (array_key_exists('error', $raw)) {
            $error = $raw['error'];

            throw $reject(
                OAuthCallbackFailure::AuthorizationDenied,
                self::oauthError($error),
            );
        }

        $code = $query->all()['code'] ?? null;
        if (! is_string($code) || $code === '') {
            throw $reject(OAuthCallbackFailure::CodeMissing);
        }

        return [$flow, $code];
    }

    /**
     * @param  array<string, string>  $parameters  carries the client secret and the code or
     *                                             refresh token, so it never appears in a trace
     * @param  list<string>|null  $scopesWhenOmitted  what a response without `scope` was granted
     * @param  string|null  $refreshTokenWhenOmitted  the refresh token sent, which stays valid when a
     *                                                refresh response does not rotate it (RFC 6749 §6)
     */
    private function requestTokens(
        AuthorizationServer $server,
        string $issuer,
        ?string $resource,
        #[SensitiveParameter] array $parameters,
        string $refusal,
        ?array $scopesWhenOmitted,
        #[SensitiveParameter] ?string $refreshTokenWhenOmitted = null,
    ): OAuthTokens {
        if ($resource !== null) {
            $parameters['resource'] = $resource;
        }

        try {
            $url = $server->endpoint('token_path');
            $request = Http::asForm()->acceptJson();
            $request = ($this->transport ?? null)?->prepare($request, $url) ?? $request;
            $response = $request->post($url, $parameters);
        } catch (ConnectionException) {
            throw new OAuthTokenRequestFailed('The authorization server could not be reached.', definitive: false);
        }

        if (! $response->successful()) {
            $error = $response->json('error');

            throw new OAuthTokenRequestFailed(
                $refusal,
                self::oauthError($error),
                definitive: $response->status() < 500,
            );
        }

        $accessToken = $response->json('access_token');
        $tokenType = $response->json('token_type');
        $refreshToken = $response->json('refresh_token');
        $expiresIn = $response->json('expires_in');
        $expiresIn = is_string($expiresIn) && ctype_digit($expiresIn) ? (int) $expiresIn : $expiresIn;
        $scope = $response->json('scope');

        if (! self::isToken($accessToken)
            || ($tokenType !== null && (! is_string($tokenType) || Str::lower($tokenType) !== 'bearer'))
            || ($refreshToken !== null && ! self::isToken($refreshToken))
            || ($expiresIn !== null && (! is_int($expiresIn) || $expiresIn <= 0))
            || ($scope !== null && ! is_string($scope))) {
            // The server answered success, so it may have used the code or rotated the refresh
            // token sent: as uncertain as no answer at all.
            throw new OAuthTokenRequestFailed('The identity provider returned an invalid token.', definitive: false);
        }

        return new OAuthTokens(
            server: $server->name,
            issuer: $issuer,
            resource: $resource,
            accessToken: $accessToken,
            refreshToken: $refreshToken ?? $refreshTokenWhenOmitted,
            expiresAt: $expiresIn === null ? null : CarbonImmutable::now()->addSeconds($expiresIn),
            scopes: $scope === null ? $scopesWhenOmitted : self::scopeList($scope),
        );
    }

    /** @return list<string> */
    private static function scopeList(string $scope): array
    {
        return array_values(array_filter(explode(' ', $scope), static fn (string $value): bool => $value !== ''));
    }

    /**
     * An OAuth `error` value as RFC 6749 defines it (1*NQSCHAR: printable ASCII other than
     * `"` and `\`), at most 64 characters; anything else is dropped. It is still data from
     * another server: escape it wherever it is displayed.
     */
    private static function oauthError(mixed $error): ?string
    {
        return is_string($error) && preg_match('/^[\x20\x21\x23-\x5B\x5D-\x7E]{1,64}\z/', $error) === 1 ? $error : null;
    }

    /** RFC 6749 Appendix A.12/A.17: an access or refresh token is 1*VSCHAR (%x20-7E). */
    private static function isToken(mixed $token): bool
    {
        return is_string($token) && preg_match('/^[\x20-\x7E]+\z/', $token) === 1;
    }

    private function issuerRequired(AuthorizationServer $server): bool
    {
        return match ($server->issuerParameter()) {
            AuthorizationServer::ISS_REQUIRED => true,
            AuthorizationServer::ISS_ADVERTISED => AuthorizationServerMetadata::issuerParameterSupported($server, $this->transport ?? null),
            default => false,
        };
    }

    /** The signed-in person, as a string, or null for a guest. */
    private function userKey(Request $request): ?string
    {
        $identifier = $request->user()?->getAuthIdentifier();

        return is_scalar($identifier) || $identifier instanceof Stringable ? (string) $identifier : null;
    }

    private function authorizationServer(): AuthorizationServer
    {
        return $this->explicitServer ?? AuthorizationServer::resolve($this->server);
    }

    public function providerName(): string
    {
        return $this->authorizationServer()->value('provider');
    }

    public function providerBaseUrl(): string
    {
        return $this->authorizationServer()->value('base_url');
    }

    private function validatedIdentity(Response $response): OAuthIdentity
    {
        abort_unless($response->successful(), 502, 'The identity provider did not return an account.');

        $identity = $response->json();
        abort_unless(
            is_array($identity)
            && is_string($identity['sub'] ?? null)
            && $identity['sub'] !== ''
            && strlen($identity['sub']) <= 191
            && is_string($identity['name'] ?? null)
            && trim($identity['name']) !== ''
            && is_string($identity['email'] ?? null)
            && filter_var($identity['email'], FILTER_VALIDATE_EMAIL) !== false,
            502,
            'The identity provider returned an invalid account.',
        );

        $generation = $identity['credential_version'] ?? null;
        abort_unless($generation === null || (is_int($generation) && $generation >= 0),
            502, 'The identity provider returned an invalid credential generation.');

        return new OAuthIdentity(
            provider: $this->providerName(),
            subject: $identity['sub'],
            name: trim($identity['name']),
            email: Str::lower($identity['email']),
            apps: $this->applications($identity['apps'] ?? null),
            credentialVersion: $generation,
        );
    }

    /**
     * The applications the provider says this person can move between.
     *
     * Malformed entries are dropped rather than rejected. This list is chrome: a provider
     * that grows a field, or one entry with a broken URL, must not be able to stop somebody
     * signing in — which is what aborting here would do, since this runs inside the callback.
     *
     * @return list<array{key: string, name: string, url: string}>
     */
    private function applications(mixed $apps): array
    {
        if (! is_array($apps)) {
            return [];
        }

        $valid = [];

        foreach ($apps as $app) {
            if (! is_array($app)) {
                continue;
            }

            $key = $app['key'] ?? null;
            $name = $app['name'] ?? null;
            $url = $app['url'] ?? null;

            if (! is_string($key) || ! is_string($name) || ! is_string($url)) {
                continue;
            }

            if ($key === '' || trim($name) === '' || filter_var($url, FILTER_VALIDATE_URL) === false) {
                continue;
            }

            // Only ever a link the browser will follow. A `javascript:` or `data:` URL passes
            // FILTER_VALIDATE_URL, so the scheme is checked rather than assumed.
            if (! in_array(Str::lower((string) parse_url($url, PHP_URL_SCHEME)), ['http', 'https'], true)) {
                continue;
            }

            $valid[] = ['key' => $key, 'name' => trim($name), 'url' => $url];
        }

        return $valid;
    }

    /**
     * Where to send someone so that signing out here also signs them out of the provider.
     *
     * Without this an application can only end its own session; the provider still knows the
     * person, and the next authorization request hands them straight back, which reads as a
     * sign-out that did nothing. The provider validates `$returnTo` against this client's
     * registered redirects, so a value it does not recognise lands on the provider instead.
     */
    public function endSessionUrl(string $returnTo): string
    {
        $server = $this->authorizationServer();

        return $server->endpoint('end_session_path').'?'.http_build_query([
            'client_id' => $server->value('client_id'),
            'post_logout_redirect_uri' => $returnTo,
        ]);
    }
}
