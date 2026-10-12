<?php

namespace BWH\Auth\Tests\Fixtures;

use BWH\Auth\OAuth\Invitations\ApplicationInvitations;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;

/**
 * An application configured for invitations against https://identity.example.test, with a fake
 * provider that records every request it receives.
 */
trait ConfiguresApplicationInvitations
{
    protected const ISSUER = 'https://identity.example.test';

    protected const CLIENT_ID = '9d2f6b1e-4c1a-4f3e-9b7a-2f0c8d1e5a77';

    protected const SECRET = 'example-client-secret-value';

    protected const TOKEN = 'example-access-token-value';

    protected string $privateKey = '';

    protected string $publicKey = '';

    /** @var list<Request> */
    protected array $sent = [];

    protected function configureInvitations(): void
    {
        config(['app.env' => 'testing']);
        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        openssl_pkey_export($key, $this->privateKey);
        $this->publicKey = openssl_pkey_get_details($key)['key'];
        config([
            'bherila-auth.oauth_client.provider' => 'example-provider',
            'bherila-auth.oauth_client.base_url' => self::ISSUER,
            'bherila-auth.oauth_client.client_id' => self::CLIENT_ID,
            'bherila-auth.oauth_client.client_secret' => self::SECRET,
            'bherila-auth.application_invitations.key_id' => 'example-app-v1',
            'bherila-auth.application_invitations.private_key' => $this->privateKey,
            'bherila-auth.application_invitations.token_cache_store' => 'array',
        ]);
        Http::preventStrayRequests();
    }

    /**
     * Answer the token endpoint with a token, and every invitation request with $answer.
     *
     * @param  \Closure(Request): mixed|array<mixed>|null  $answer
     */
    protected function provider(\Closure|array|null $answer = null, int $status = 201, array $headers = []): void
    {
        Http::fake(function (Request $request) use ($answer, $status, $headers) {
            $this->sent[] = $request;
            if (str_ends_with($request->url(), '/oauth/token')) {
                return Http::response(['token_type' => 'Bearer', 'expires_in' => 300, 'access_token' => self::TOKEN]);
            }
            if ($answer instanceof \Closure) {
                return $answer($request);
            }

            return Http::response($answer ?? self::issuedBody(), $status, $headers);
        });
    }

    /** @return array<string, mixed> */
    protected static function issuedBody(array $override = []): array
    {
        return ['invitation' => array_replace([
            'id' => 42,
            'status' => 'pending',
            'expires_at' => '2026-10-19T12:00:00Z',
            'link' => self::ISSUER.'/invitations/example-link-token',
            'email_sent' => true,
        ], $override)];
    }

    /** @return list<Request> the invitation requests, without token requests */
    protected function invitationRequests(): array
    {
        return array_values(array_filter($this->sent, fn (Request $request): bool => ! str_ends_with($request->url(), '/oauth/token')));
    }

    /** @return list<Request> */
    protected function tokenRequests(): array
    {
        return array_values(array_filter($this->sent, fn (Request $request): bool => str_ends_with($request->url(), '/oauth/token')));
    }

    protected function invitations(): ApplicationInvitations
    {
        return app(ApplicationInvitations::class);
    }
}
