<?php

namespace BWH\Auth\Tests\Feature;

use BWH\Auth\OAuth\Session\ProviderIdentityStatusClient;
use BWH\Auth\OAuth\Session\ProviderStatusUnavailable;
use BWH\Auth\Tests\TestCase;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;
use PHPUnit\Framework\Attributes\DataProvider;

/**
 * Pins the status client's request and its failure messages, which applications may
 * surface or match on, across the extraction of the shared reconciliation transport.
 */
class ProviderIdentityStatusClientTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        config(['app.env' => 'testing']);
        config(['bherila-auth.oauth_client' => [
            'provider' => 'example-provider',
            'base_url' => 'https://identity.example.test/',
            'client_id' => 'example-client',
            'client_secret' => 'example-secret',
        ]]);
        Http::preventStrayRequests();
    }

    public function test_the_request_is_one_basic_authenticated_json_post_beneath_the_base_url(): void
    {
        $sent = [];
        Http::fake(function (Request $request, array $options) use (&$sent) {
            $sent[] = [$request, $options];

            return Http::response(['contract_version' => 1, 'active' => true, 'subject' => '42', 'credential_version' => 3]);
        });

        $status = app(ProviderIdentityStatusClient::class)->status('42');

        $this->assertSame(3, $status->credentialVersion);
        $this->assertCount(1, $sent);
        [$request, $options] = $sent[0];
        $this->assertSame('POST', $request->method());
        $this->assertSame('https://identity.example.test/api/reconciliation/identity-status', $request->url());
        $this->assertSame(['Basic '.base64_encode('example-client:example-secret')], $request->header('Authorization'));
        $this->assertTrue($request->isJson());
        $this->assertSame(['subject' => '42'], $request->data());
        $this->assertFalse($options['allow_redirects']);
        $this->assertSame([5, 3, true, 1], [$options['timeout'], $options['connect_timeout'], $options['stream'], $options['read_timeout']]);
    }

    #[DataProvider('failures')]
    public function test_failure_messages_are_unchanged(\Closure $arrange, string $message): void
    {
        $arrange();

        try {
            app(ProviderIdentityStatusClient::class)->status('42');
            $this->fail('The status check must fail.');
        } catch (ProviderStatusUnavailable $exception) {
            $this->assertSame($message, $exception->getMessage());
            $this->assertNull($exception->getPrevious());
        }
    }

    public static function failures(): array
    {
        return [
            'missing secret' => [fn () => config(['bherila-auth.oauth_client.client_secret' => '']), 'Provider session verification is not configured.'],
            'missing provider' => [fn () => config(['bherila-auth.oauth_client.provider' => null]), 'Provider session verification is not configured.'],
            'plain http' => [fn () => config(['bherila-auth.oauth_client.base_url' => 'http://identity.example.test']), 'Provider status requires a trusted HTTPS base URL.'],
            'server error' => [fn () => Http::fake(['*' => Http::response('', 500)]), 'Provider session verification is unavailable.'],
            'throttled' => [fn () => Http::fake(['*' => Http::response('', 429, ['Retry-After' => '30'])]), 'Provider session verification is unavailable.'],
            'not json' => [fn () => Http::fake(['*' => Http::response('<html>')]), 'The provider status response is invalid.'],
            'wrong version' => [fn () => Http::fake(['*' => Http::response(['contract_version' => 2, 'active' => false])]), 'The provider status response is invalid.'],
        ];
    }

    public function test_context_still_identifies_the_configured_provider_and_client(): void
    {
        $this->assertSame(
            hash('sha256', json_encode(['https://identity.example.test', 'example-provider', 'example-client'])),
            app(ProviderIdentityStatusClient::class)->context(),
        );
    }
}
