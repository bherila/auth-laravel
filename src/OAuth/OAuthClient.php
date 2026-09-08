<?php

namespace BWH\Auth\OAuth;

use Illuminate\Http\Client\Response;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;

final class OAuthClient
{
    private const string STATE_SESSION_KEY = 'oauth.login.state';

    private const string VERIFIER_SESSION_KEY = 'oauth.login.code_verifier';

    /**
     * Whether a client has been issued for this application at the provider.
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
    public static function isConfigured(): bool
    {
        return self::configuredSetting('client_id') !== ''
            && self::configuredSetting('base_url') !== '';
    }

    private static function configuredSetting(string $key): string
    {
        $value = config("bherila-auth.oauth_client.{$key}");

        return is_string($value) ? trim($value) : '';
    }

    public function redirect(Request $request): RedirectResponse
    {
        $state = Str::random(40);
        $verifier = Str::random(96);
        $challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');

        $request->session()->put([
            self::STATE_SESSION_KEY => $state,
            self::VERIFIER_SESSION_KEY => $verifier,
        ]);

        return redirect()->away($this->endpoint('authorize_path').'?'.http_build_query([
            'client_id' => $this->configuredValue('client_id'),
            'redirect_uri' => $this->configuredValue('redirect_uri'),
            'response_type' => 'code',
            'scope' => $this->configuredValue('scope'),
            'state' => $state,
            'code_challenge' => $challenge,
            'code_challenge_method' => 'S256',
        ]));
    }

    public function identityFromCallback(Request $request): OAuthIdentity
    {
        $expectedState = $request->session()->pull(self::STATE_SESSION_KEY);
        $verifier = $request->session()->pull(self::VERIFIER_SESSION_KEY);
        $state = $request->query('state');
        $code = $request->query('code');

        abort_unless(
            is_string($expectedState)
            && is_string($state)
            && hash_equals($expectedState, $state)
            && is_string($verifier)
            && $verifier !== ''
            && is_string($code)
            && $code !== '',
            403,
            'The OAuth response could not be verified.',
        );

        $tokenResponse = Http::asForm()->acceptJson()->post($this->endpoint('token_path'), [
            'grant_type' => 'authorization_code',
            'client_id' => $this->configuredValue('client_id'),
            'client_secret' => $this->configuredValue('client_secret'),
            'redirect_uri' => $this->configuredValue('redirect_uri'),
            'code' => $code,
            'code_verifier' => $verifier,
        ]);
        abort_unless($tokenResponse->successful(), 502, 'The identity provider rejected the authorization code.');

        $accessToken = $tokenResponse->json('access_token');
        abort_unless(is_string($accessToken) && $accessToken !== '', 502, 'The identity provider returned an invalid token.');

        $identityResponse = Http::acceptJson()
            ->withToken($accessToken)
            ->get($this->endpoint('identity_path'));

        return $this->validatedIdentity($identityResponse);
    }

    public function providerName(): string
    {
        return $this->configuredValue('provider');
    }

    public function providerBaseUrl(): string
    {
        return $this->configuredValue('base_url');
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
        return $this->endpoint('end_session_path').'?'.http_build_query([
            'client_id' => $this->configuredValue('client_id'),
            'post_logout_redirect_uri' => $returnTo,
        ]);
    }

    private function endpoint(string $pathKey): string
    {
        return $this->configuredValue('base_url').'/'.ltrim($this->configuredValue($pathKey), '/');
    }

    private function configuredValue(string $key): string
    {
        $value = config("bherila-auth.oauth_client.{$key}");
        abort_unless(is_string($value) && $value !== '', 503, 'OAuth is not configured.');

        if ($key === 'base_url') {
            $value = rtrim($value, '/');
            abort_unless(filter_var($value, FILTER_VALIDATE_URL) !== false, 503, 'OAuth is not configured.');
        }

        if ($key === 'redirect_uri') {
            abort_unless(filter_var($value, FILTER_VALIDATE_URL) !== false, 503, 'OAuth is not configured.');
        }

        if ($key === 'provider') {
            abort_unless($value === trim($value) && Str::length($value) <= 64, 503, 'OAuth is not configured.');
        }

        return $value;
    }
}
