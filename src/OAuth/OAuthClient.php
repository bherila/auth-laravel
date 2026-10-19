<?php

namespace BWH\Auth\OAuth;

use BWH\Auth\OAuth\Client\AuthorizationServer;
use BWH\Auth\OAuth\Client\AuthorizationServerMetadata;
use BWH\Auth\OAuth\Client\PendingFlow;
use Carbon\CarbonImmutable;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Client\Response;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;
use Symfony\Component\HttpFoundation\HeaderUtils;

/**
 * Authorization-code + S256 PKCE client for the sign-in provider and, optionally, other
 * authorization servers this application calls APIs on for a person.
 *
 * The container's instance is the sign-in provider (`oauth_client`); {@see forServer()}
 * gives one for an entry of `oauth_client.servers`. Each server has its own static
 * callback, and every pending flow is bound to the session and person that started it, the
 * server (and exact issuer) it was sent to, the callback, the resource and the verifier.
 * A response is checked against all of them, and against RFC 9207 `iss`, before its code is
 * exchanged.
 */
final class OAuthClient
{
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

    /** `default` for the sign-in provider, else the `oauth_client.servers` key. */
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
            user: $this->userKey($request),
            startedAt: Carbon::now()->getTimestamp(),
        );

        $authorize = $server->endpoint('authorize_path');
        $parameters = array_filter([
            'client_id' => $server->value('client_id'),
            'redirect_uri' => $flow->callback,
            'response_type' => 'code',
            'scope' => $server->value('scope'),
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
     * `state` in this session (consumed whatever happens next), not expired, started for
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
        ], 'The identity provider rejected the authorization code.');
    }

    public function identityFromCallback(Request $request): OAuthIdentity
    {
        $tokens = $this->tokensFromCallback($request);

        $identityResponse = Http::acceptJson()
            ->withToken($tokens->accessToken)
            ->get($this->authorizationServer()->endpoint('identity_path'));

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
        if ($flow->userBound && $flow->user !== $this->userKey($request)) {
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

        if ($query->has('error')) {
            $error = $query->all()['error'];

            throw $reject(
                OAuthCallbackFailure::AuthorizationDenied,
                is_string($error) && preg_match('/^[a-z_]{1,64}$/', $error) === 1 ? $error : null,
            );
        }

        $code = $query->all()['code'] ?? null;
        if (! is_string($code) || $code === '') {
            throw $reject(OAuthCallbackFailure::CodeMissing);
        }

        return [$flow, $code];
    }

    /**
     * @param  array<string, string>  $parameters
     */
    private function requestTokens(
        AuthorizationServer $server,
        string $issuer,
        ?string $resource,
        array $parameters,
        string $refusal,
    ): OAuthTokens {
        if ($resource !== null) {
            $parameters['resource'] = $resource;
        }

        try {
            $response = Http::asForm()->acceptJson()->post($server->endpoint('token_path'), $parameters);
        } catch (ConnectionException) {
            throw new OAuthTokenRequestFailed('The authorization server could not be reached.', definitive: false);
        }

        if (! $response->successful()) {
            $error = $response->json('error');

            throw new OAuthTokenRequestFailed(
                $refusal,
                is_string($error) && preg_match('/^[a-z_]{1,64}$/', $error) === 1 ? $error : null,
                definitive: $response->status() < 500,
            );
        }

        $accessToken = $response->json('access_token');
        $tokenType = $response->json('token_type');
        $refreshToken = $response->json('refresh_token');
        $expiresIn = $response->json('expires_in');
        $scope = $response->json('scope');

        if (! is_string($accessToken) || $accessToken === ''
            || ($tokenType !== null && (! is_string($tokenType) || Str::lower($tokenType) !== 'bearer'))
            || ($refreshToken !== null && (! is_string($refreshToken) || $refreshToken === ''))
            || ($expiresIn !== null && (! is_int($expiresIn) || $expiresIn <= 0))
            || ($scope !== null && ! is_string($scope))) {
            throw new OAuthTokenRequestFailed('The identity provider returned an invalid token.');
        }

        return new OAuthTokens(
            server: $server->name,
            issuer: $issuer,
            resource: $resource,
            accessToken: $accessToken,
            refreshToken: $refreshToken,
            expiresAt: $expiresIn === null ? null : CarbonImmutable::now()->addSeconds($expiresIn),
            scopes: array_values(array_filter(
                explode(' ', $scope ?? $server->requestedScope()),
                static fn (string $value): bool => $value !== '',
            )),
        );
    }

    private function issuerRequired(AuthorizationServer $server): bool
    {
        return match ($server->issuerParameter()) {
            AuthorizationServer::ISS_REQUIRED => true,
            AuthorizationServer::ISS_ADVERTISED => AuthorizationServerMetadata::issuerParameterSupported($server),
            default => false,
        };
    }

    /** The signed-in person, as a string, or null for a guest. */
    private function userKey(Request $request): ?string
    {
        $identifier = $request->user()?->getAuthIdentifier();

        return is_scalar($identifier) ? (string) $identifier : null;
    }

    private function authorizationServer(): AuthorizationServer
    {
        return AuthorizationServer::resolve($this->server);
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
