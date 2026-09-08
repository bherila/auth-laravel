<?php

namespace BWH\Auth\OAuth\Session;

use BWH\Auth\OAuth\OAuthIdentity;
use Illuminate\Http\Client\Factory;
use Illuminate\Support\Str;

final readonly class ProviderIdentityStatusClient
{
    public function __construct(private Factory $http) {}

    /** Null means definitively inactive; failures never become an active result. */
    public function status(string $subject): ?OAuthIdentity
    {
        if ($subject === '' || strlen($subject) > 191) {
            throw new ProviderSessionExpired('The provider session binding is invalid.');
        }

        $base = $this->baseUrl();
        $client = $this->setting('client_id');
        $secret = $this->setting('client_secret');
        $provider = $this->setting('provider');

        try {
            $response = $this->http->acceptJson()->asJson()
                ->withBasicAuth($client, $secret)
                ->withoutRedirecting()->connectTimeout(3)->timeout(5)
                ->post($base.'/api/reconciliation/identity-status', ['subject' => $subject]);
        } catch (\Throwable) {
            // Transport exceptions may contain credentials or response bodies.
            throw new ProviderStatusUnavailable('Provider session verification is unavailable.');
        }

        if (! $response->successful() || strlen($response->body()) > 16_384) {
            throw new ProviderStatusUnavailable('Provider session verification is unavailable.');
        }

        $data = json_decode($response->body(), true, 16, JSON_BIGINT_AS_STRING);
        if (! is_array($data) || ($data['contract_version'] ?? null) !== 1
            || ! is_bool($data['active'] ?? null)) {
            throw new ProviderStatusUnavailable('The provider status response is invalid.');
        }
        if (! $data['active']) {
            return null;
        }
        if (($data['subject'] ?? null) !== $subject
            || ! is_int($data['credential_version'] ?? null) || $data['credential_version'] < 0
            || ! is_string($data['name'] ?? null) || trim($data['name']) === ''
            || Str::length($data['name']) > 255
            || ! is_string($data['email'] ?? null) || strlen($data['email']) > 254
            || filter_var($data['email'], FILTER_VALIDATE_EMAIL) === false) {
            throw new ProviderStatusUnavailable('The provider status response is invalid.');
        }

        return new OAuthIdentity($provider, $subject, trim($data['name']),
            Str::lower($data['email']), credentialVersion: $data['credential_version']);
    }

    /** Pin cached session verification to this configured provider and client. */
    public function context(): string
    {
        return hash('sha256', json_encode([
            $this->baseUrl(), $this->setting('provider'), $this->setting('client_id'),
        ], JSON_THROW_ON_ERROR));
    }

    private function baseUrl(): string
    {
        $url = rtrim($this->setting('base_url'), '/');
        $parts = parse_url($url);
        $local = is_array($parts) && ($parts['scheme'] ?? '') === 'http'
            && in_array(config('app.env'), ['local', 'testing'], true)
            && in_array($parts['host'] ?? '', ['localhost', '127.0.0.1', '[::1]'], true);
        if (filter_var($url, FILTER_VALIDATE_URL) === false || ! is_array($parts)
            || (! $local && ($parts['scheme'] ?? '') !== 'https')
            || isset($parts['user']) || isset($parts['pass'])
            || isset($parts['query']) || isset($parts['fragment'])) {
            throw new ProviderStatusUnavailable('Provider status requires a trusted HTTPS base URL.');
        }

        return $url;
    }

    private function setting(string $key): string
    {
        $value = config('bherila-auth.oauth_client.'.$key);
        if (! is_string($value) || trim($value) === '') {
            throw new ProviderStatusUnavailable('Provider session verification is not configured.');
        }

        return $value;
    }
}
