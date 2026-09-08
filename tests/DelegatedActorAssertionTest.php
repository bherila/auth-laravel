<?php

namespace BWH\Auth\Tests;

use BWH\Auth\OAuth\DelegatedAccess\ActorAssertionVerifier;
use BWH\Auth\OAuth\DelegatedAccess\CacheNonceStore;
use BWH\Auth\OAuth\DelegatedAccess\DelegatedAccessException;
use BWH\Auth\OAuth\DelegatedAccess\NonceStore;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Schema;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;

class DelegatedActorAssertionTest extends TestCase
{
    use RefreshDatabase;

    private string $privateKey = '';

    private string $publicKey;

    protected function setUp(): void
    {
        parent::setUp();
        Schema::create('cache', function (Blueprint $table) {
            $table->string('key')->primary();
            $table->mediumText('value');
            $table->integer('expiration');
        });
        config(['cache.stores.database' => ['driver' => 'database', 'connection' => 'testing', 'table' => 'cache']]);
        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        openssl_pkey_export($key, $this->privateKey);
        $this->publicKey = openssl_pkey_get_details($key)['key'];
    }

    public function test_valid_assertion_is_bound_to_request_and_atomically_consumed(): void
    {
        $body = '{"operation":"read"}';
        $token = $this->signed(['body_sha256' => hash('sha256', $body)]);
        $this->assertSame('actor-example', $this->verifier()->verify($token, 'POST', $body));
        $this->refused(fn () => $this->verifier()->verify($token, 'POST', $body), 'replayed_actor_assertion', 401);
    }

    public function test_claim_and_header_failures_are_rejected_before_replay_consumption(): void
    {
        $now = time();
        $invalidClaims = [
            ['iss' => 'https://other.example.test'], ['aud' => 'https://other.example.test/access'],
            ['aud' => ['https://app.example.test/access', 'https://other.example.test/access']],
            ['application' => 'another-app'], ['sub' => ''], ['sub' => str_repeat('x', 192)],
            ['iat' => $now + 600, 'exp' => $now + 660], ['iat' => (string) $now], ['iat' => $now + 0.5],
            ['iat' => $now - 80, 'exp' => $now - 10], ['exp' => $now + 61],
            ['exp' => $now], ['jti' => 'short'], ['method' => 'GET'],
            ['body_sha256' => str_repeat('0', 64)], ['nbf' => $now + 100],
        ];
        foreach ($invalidClaims as $claims) {
            $this->refused(fn () => $this->verifier()->verify($this->signed(['iat' => $now, ...$claims]), 'POST', '{}'), 'invalid_actor_assertion', 401);
        }
        foreach ([['alg' => 'HS256'], ['typ' => 'JWT'], ['kid' => 'unknown'], ['jku' => 'https://keys.example.test/jwks']] as $header) {
            $this->refused(fn () => $this->verifier()->verify($this->signed([], $header), 'POST', '{}'), 'invalid_actor_assertion', 401);
        }
        $this->assertDatabaseCount('cache', 0);
    }

    public function test_modified_signature_body_and_method_fail_without_an_oauth_fallback(): void
    {
        $token = $this->signed();
        $parts = explode('.', $token);
        $parts[2] = str_repeat('a', strlen($parts[2]));
        $this->refused(fn () => $this->verifier()->verify(implode('.', $parts), 'POST', '{}'), 'invalid_actor_assertion', 401);
        $this->refused(fn () => $this->verifier()->verify($token, 'GET', '{}'), 'invalid_actor_assertion', 401);
        $this->refused(fn () => $this->verifier()->verify($token, 'POST', '{ }'), 'invalid_actor_assertion', 401);
        $this->refused(fn () => $this->verifier()->verify('ordinary-oauth-token', 'POST', '{}'), 'invalid_actor_assertion', 401);
        $this->assertSame('actor-example', $this->verifier()->verify($token, 'POST', '{}'));
    }

    public function test_unavailable_or_process_local_replay_storage_fails_closed(): void
    {
        $broken = new class implements NonceStore
        {
            public function consume(string $key, int $seconds): bool
            {
                throw new \RuntimeException('storage offline');
            }
        };
        $this->refused(fn () => $this->verifier($broken)->verify($this->signed(), 'POST', '{}'), 'replay_storage_unavailable', 503);
        $this->refused(fn () => $this->verifier(new CacheNonceStore(Cache::store('array')))->verify($this->signed(), 'POST', '{}'), 'replay_storage_unavailable', 503);
    }

    public function test_trust_configuration_requires_local_https_urls_without_credentials_or_redirect_components(): void
    {
        foreach (['http://identity.example.test', 'https://identity.example.test/path', 'https://user@identity.example.test', 'https://identity.example.test?key=other', 'https://identity.example.test#fragment', 'https://invalid_host.test', 'https://identity.example.test:0'] as $issuer) {
            $this->refused(fn () => new ActorAssertionVerifier($issuer, 'https://app.example.test/access', 'example-app', ['integration-v1' => $this->publicKey], new CacheNonceStore(Cache::store('database'))), 'invalid_verifier_configuration', 503);
        }
        foreach (['http://app.example.test/access', 'https://app.example.test/access?alternate=1', 'https://user:password@app.example.test/access'] as $endpoint) {
            $this->refused(fn () => new ActorAssertionVerifier('https://identity.example.test', $endpoint, 'example-app', ['integration-v1' => $this->publicKey], new CacheNonceStore(Cache::store('database'))), 'invalid_verifier_configuration', 503);
        }
    }

    public function test_actor_is_exact_and_nonce_lifetime_includes_clock_tolerance(): void
    {
        $store = new class implements NonceStore
        {
            public int $seconds = 0;

            public string $key = '';

            public function consume(string $key, int $seconds): bool
            {
                $this->key = $key;
                $this->seconds = $seconds;

                return true;
            }
        };
        $jti = str_repeat('a', 64);
        $subject = str_repeat('S', 191);
        $this->assertSame($subject, $this->verifier($store)->verify($this->signed(['sub' => $subject, 'jti' => $jti, 'aud' => ['https://app.example.test/access']]), 'POST', '{}'));
        $this->assertSame(hash('sha256', "https://identity.example.test\0example-app\0".$jti), $store->key);
        $this->assertGreaterThanOrEqual(63, $store->seconds);
        $this->assertLessThanOrEqual(65, $store->seconds);
    }

    public function test_pinned_root_issuer_is_canonicalized_before_claim_and_nonce_validation(): void
    {
        $verifier = new ActorAssertionVerifier('https://identity.example.test/', 'https://app.example.test/access', 'example-app', ['integration-v1' => $this->publicKey], new CacheNonceStore(Cache::store('database')));
        $this->assertSame('actor-example', $verifier->verify($this->signed(), 'POST', '{}'));
        $this->refused(fn () => $verifier->verify($this->signed(['iss' => 'https://identity.example.test/']), 'POST', '{}'), 'invalid_actor_assertion', 401);
    }

    private function verifier(?NonceStore $nonces = null): ActorAssertionVerifier
    {
        return new ActorAssertionVerifier('https://identity.example.test', 'https://app.example.test/access', 'example-app', ['integration-v1' => $this->publicKey], $nonces ?? new CacheNonceStore(Cache::store('database')));
    }

    private function signed(array $overrides = [], array $headers = []): string
    {
        $encoder = new JoseEncoder;
        $head = $encoder->base64UrlEncode(json_encode(['alg' => 'RS256', 'typ' => ActorAssertionVerifier::TYPE, 'kid' => 'integration-v1', ...$headers], JSON_THROW_ON_ERROR));
        $claims = $encoder->base64UrlEncode(json_encode([
            'iss' => 'https://identity.example.test', 'sub' => 'actor-example', 'aud' => 'https://app.example.test/access',
            'iat' => time(), 'exp' => time() + 60, 'jti' => bin2hex(random_bytes(32)),
            'application' => 'example-app', 'method' => 'POST', 'body_sha256' => hash('sha256', '{}'), ...$overrides,
        ], JSON_THROW_ON_ERROR));
        $payload = $head.'.'.$claims;

        return $payload.'.'.$encoder->base64UrlEncode((new Sha256)->sign($payload, InMemory::plainText($this->privateKey)));
    }

    private function refused(callable $action, string $outcome, int $status): void
    {
        try {
            $action();
            $this->fail('Expected delegated refusal.');
        } catch (DelegatedAccessException $exception) {
            $this->assertSame($outcome, $exception->outcome);
            $this->assertSame($status, $exception->status);
        }
    }
}
