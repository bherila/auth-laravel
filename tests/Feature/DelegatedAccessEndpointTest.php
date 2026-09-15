<?php

namespace BWH\Auth\Tests\Feature;

use BWH\Auth\OAuth\DelegatedAccess\ApplicationAccessAdapter;
use BWH\Auth\OAuth\DelegatedAccess\DatabaseNonceStore;
use BWH\Auth\OAuth\DelegatedAccess\DelegatedAccessException;
use BWH\Auth\OAuth\DelegatedAccess\DelegatedAccessSettings;
use BWH\Auth\OAuth\DelegatedAccess\DelegatedContract;
use BWH\Auth\OAuth\DelegatedAccess\DelegatedCursor;
use BWH\Auth\OAuth\DelegatedAccess\NonceStore;
use BWH\Auth\OAuth\PendingAccount;
use BWH\Auth\Tests\TestCase;
use Closure;
use DateTimeImmutable;
use Illuminate\Support\Facades\Exceptions;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Testing\TestResponse;
use Lcobucci\JWT\Encoding\ChainedFormatter;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token\Builder;

/**
 * POST /application-access, driven the way the identity provider drives it: a real RS256 actor
 * assertion bound to the exact body, and every success checked against contract version 2.
 */
class DelegatedAccessEndpointTest extends TestCase
{
    private const ISSUER = 'https://identity.example.test';

    private const ENDPOINT = 'https://app.example.test/application-access';

    private const APPLICATION = 'example-app';

    private const PROVIDER = 'example-provider';

    private string $privateKey = '';

    private string $keyPath = '';

    /** @var list<array{string, array<string, mixed>}> */
    private array $calls = [];

    /** @var Closure(string, array<string, mixed>): array<string, mixed> */
    private Closure $answer;

    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);

        // Bound before the provider boots, as an application's own provider would bind it.
        $app->bind(ApplicationAccessAdapter::class, fn (): ApplicationAccessAdapter => new class($this) implements ApplicationAccessAdapter
        {
            public function __construct(private DelegatedAccessEndpointTest $test) {}

            public function handle(string $actorSubject, array $payload): array
            {
                return $this->test->answer($actorSubject, $payload);
            }
        });
    }

    protected function setUp(): void
    {
        parent::setUp();

        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        openssl_pkey_export($key, $this->privateKey);
        $this->keyPath = (string) tempnam(sys_get_temp_dir(), 'delegated-public-');
        file_put_contents($this->keyPath, openssl_pkey_get_details($key)['key']);

        config([
            'bherila-auth.oauth_client.provider' => self::PROVIDER,
            'bherila-auth.delegated_access' => [
                'enabled' => true,
                'issuer' => self::ISSUER,
                'endpoint' => self::ENDPOINT,
                'application' => self::APPLICATION,
                'public_keys' => 'integration-v1|'.$this->keyPath,
                'oauth_provider' => self::PROVIDER,
            ],
        ]);

        // The database store refuses in-memory SQLite, rightly; its own tests cover it.
        $this->app->instance(NonceStore::class, new class implements NonceStore
        {
            /** @var array<string, true> */
            private array $seen = [];

            public function consume(string $key, int $seconds): bool
            {
                if (isset($this->seen[$key])) {
                    return false;
                }

                return $this->seen[$key] = true;
            }
        });

        $this->answer = static fn (string $actor, array $payload): array => self::capabilities();
    }

    protected function tearDown(): void
    {
        @unlink($this->keyPath);

        parent::tearDown();
    }

    /** @internal Called by the bound adapter. */
    public function answer(string $actorSubject, array $payload): array
    {
        $this->calls[] = [$actorSubject, $payload];

        return ($this->answer)($actorSubject, $payload);
    }

    public function test_the_adapter_receives_the_verified_actor_and_the_validated_operation_and_the_answer_gains_the_envelope(): void
    {
        $response = $this->send(['operation' => 'capabilities'])->assertOk()->assertHeaderContains('Cache-Control', 'no-store');

        $this->assertSame([['actor-subject', ['operation' => 'capabilities']]], $this->calls);
        $this->assertSame(['contract_version' => 2, 'application' => self::APPLICATION, 'operation' => 'capabilities'], array_slice($response->json(), 0, 3, true));
        (new DelegatedContract)->response($response->json(), self::APPLICATION, 'capabilities', null, DelegatedContract::VERSION_2);
    }

    public function test_it_answers_404_until_enabled_and_never_calls_the_adapter(): void
    {
        config(['bherila-auth.delegated_access.enabled' => false]);

        $this->send(['operation' => 'capabilities'])->assertNotFound()->assertJsonPath('error', 'not_found');
        $this->assertSame([], $this->calls);
    }

    public function test_a_missing_or_foreign_assertion_and_a_replay_are_refused_before_the_adapter(): void
    {
        $body = $this->body(['operation' => 'capabilities']);

        $this->call('POST', '/application-access', [], [], [], ['CONTENT_TYPE' => 'application/json'], $body)
            ->assertStatus(401)->assertJsonPath('error', 'invalid_actor_assertion');

        $this->send(['operation' => 'capabilities'], token: $this->assertion('actor-subject', $this->body(['operation' => 'subjects'])))
            ->assertStatus(401);

        $this->assertSame([], $this->calls);

        $token = $this->assertion('actor-subject', $body);
        $this->send(['operation' => 'capabilities'], token: $token)->assertOk();
        $this->send(['operation' => 'capabilities'], token: $token)->assertStatus(401)->assertJsonPath('error', 'replayed_actor_assertion');
        $this->assertCount(1, $this->calls);
    }

    public function test_oversize_bodies_are_refused(): void
    {
        $body = $this->body(['operation' => 'capabilities']);

        $this->call('POST', '/application-access', [], [], [], [
            'CONTENT_TYPE' => 'application/json',
            'CONTENT_LENGTH' => (string) (DelegatedContract::MAX_REQUEST_BYTES + 1),
            'HTTP_AUTHORIZATION' => 'Bearer '.$this->assertion('actor-subject', $body),
        ], $body)->assertStatus(422);

        $large = $this->body(['operation' => 'capabilities', 'padding' => str_repeat('x', DelegatedContract::MAX_REQUEST_BYTES)]);
        $this->send([], body: $large, token: 'not-verified-before-the-size-check')->assertStatus(422);

        $this->assertSame([], $this->calls);
    }

    public function test_a_signed_body_in_another_version_or_for_another_application_or_not_json_is_refused(): void
    {
        foreach ([
            (string) json_encode(['contract_version' => 1, 'application' => self::APPLICATION, 'operation' => 'capabilities']),
            (string) json_encode(['contract_version' => 2, 'application' => 'another-app', 'operation' => 'capabilities']),
            '{not json',
            (string) json_encode(['contract_version' => 2, 'application' => self::APPLICATION, 'operation' => 'delete']),
        ] as $body) {
            $this->send([], token: $this->assertion('actor-subject', $body), body: $body)->assertStatus(422);
        }

        $this->assertSame([], $this->calls);
    }

    public function test_an_adapter_refusal_is_sent_as_it_is(): void
    {
        $this->answer = static fn (): array => throw new DelegatedAccessException('not_authorized', 403);

        $this->send(['operation' => 'capabilities'])->assertForbidden()->assertJsonPath('error', 'not_authorized')->assertHeaderContains('Cache-Control', 'no-store');
    }

    public function test_an_answer_outside_the_contract_is_reported_and_never_sent(): void
    {
        Exceptions::fake();
        $this->answer = static fn (): array => ['controls' => ['application_admin' => false, 'workspace_roles' => [], 'provisioning' => true]];

        $this->send(['operation' => 'capabilities'])->assertStatus(500)->assertExactJson(['error' => 'internal_error']);
        Exceptions::assertReported(DelegatedAccessException::class);
    }

    public function test_a_read_answer_must_echo_the_requested_subject(): void
    {
        Exceptions::fake();
        $this->answer = static fn (): array => self::unprovisioned('someone-else');

        $this->send(['operation' => 'read', 'subject' => 'target-subject'])->assertStatus(500);

        $this->answer = static fn (string $actor, array $payload): array => self::unprovisioned((string) $payload['subject']);
        $this->send(['operation' => 'read', 'subject' => 'target-subject'])->assertOk()->assertJsonPath('allowed_edits.provision', true);
    }

    public function test_requests_are_refused_until_the_oauth_provider_is_set_explicitly_and_agrees(): void
    {
        foreach (['', null, 'another-provider'] as $provider) {
            config(['bherila-auth.delegated_access.oauth_provider' => $provider]);

            $this->send(['operation' => 'capabilities'])->assertStatus(503)->assertJsonPath('error', 'invalid_verifier_configuration');
        }

        $this->assertSame([], $this->calls);
    }

    public function test_an_unbound_adapter_is_a_server_error(): void
    {
        Exceptions::fake();
        unset($this->app[ApplicationAccessAdapter::class]);

        $this->send(['operation' => 'capabilities'])->assertStatus(500)->assertJsonPath('error', 'internal_error');
    }

    public function test_the_route_is_throttled_by_its_own_limiter(): void
    {
        $this->assertNotNull(RateLimiter::limiter('bherila-auth-delegated-access'));
        $this->assertContains('throttle:bherila-auth-delegated-access', app('router')->getRoutes()->getByName('bherila-auth.delegated-access')->middleware());
    }

    public function test_the_default_nonce_store_is_the_database_store(): void
    {
        $this->app->forgetInstance(NonceStore::class);

        $this->assertInstanceOf(DatabaseNonceStore::class, $this->app->make(NonceStore::class));
    }

    public function test_settings_refuse_a_key_list_with_any_bad_entry(): void
    {
        $this->assertCount(1, DelegatedAccessSettings::parsePublicKeys('integration-v1|'.$this->keyPath));
        $this->assertSame([], DelegatedAccessSettings::parsePublicKeys('integration-v1|'.$this->keyPath.',integration-v2|/nonexistent.pem'));
        $this->assertSame([], DelegatedAccessSettings::parsePublicKeys('integration-v1|'.$this->keyPath.',integration-v1|'.$this->keyPath));
        $this->assertSame([], DelegatedAccessSettings::parsePublicKeys('no-separator'));
        $this->assertSame([], DelegatedAccessSettings::parsePublicKeys(''));
    }

    public function test_a_cursor_is_bound_to_its_actor_and_operation_and_fits_the_contract_for_the_longest_subject(): void
    {
        $cursors = $this->app->make(DelegatedCursor::class);
        $actor = str_repeat('s', 191);
        $cursor = $cursors->encode($actor, 'subjects', PHP_INT_MAX);

        $this->assertLessThanOrEqual(512, strlen($cursor));
        $this->assertSame(PHP_INT_MAX, $cursors->after($actor, 'subjects', ['cursor' => $cursor]));
        $this->assertSame(0, $cursors->after($actor, 'subjects', []));

        (new DelegatedContract)->response(
            ['contract_version' => 2, 'application' => self::APPLICATION, 'operation' => 'subjects', 'subjects' => [], 'next_cursor' => $cursor],
            self::APPLICATION, 'subjects', null, DelegatedContract::VERSION_2,
        );

        foreach ([[$actor.'x', 'subjects', $cursor], [$actor, 'workspaces', $cursor], [$actor, 'subjects', $cursor.'x'],
            [$actor, 'subjects', $cursors->encode($actor, 'subjects', -1)]] as [$who, $operation, $value]) {
            try {
                $cursors->after($who, $operation, ['cursor' => $value]);
                $this->fail('A foreign or tampered cursor was accepted.');
            } catch (DelegatedAccessException $refused) {
                $this->assertSame(['invalid_cursor', 422], [$refused->outcome, $refused->status]);
            }
        }
    }

    public function test_the_prune_command_leaves_a_store_other_than_the_database_store_alone(): void
    {
        $this->artisan('bherila-auth:prune-delegated-nonces')->expectsOutputToContain('nothing to prune')->assertSuccessful();
    }

    public function test_pending_account_placeholders_are_deterministic_and_unmailable(): void
    {
        $this->assertSame(PendingAccount::email('provider', 'subject'), PendingAccount::email('provider', 'subject'));
        $this->assertNotSame(PendingAccount::email('provider', 'subject'), PendingAccount::email('provider-subject', ''));
        $this->assertStringEndsWith('@invalid', PendingAccount::email('provider', 'subject'));
        $this->assertSame('Pending member ('.str_repeat('x', 40).'…)', PendingAccount::name('Pending member', str_repeat('x', 41)));
    }

    /** @return array<string, mixed> */
    private static function capabilities(): array
    {
        return ['controls' => ['application_admin' => false, 'workspace_roles' => [['id' => 'member', 'label' => 'Member']], 'provisioning' => true]];
    }

    /** @return array<string, mixed> */
    private static function unprovisioned(string $subject): array
    {
        return [
            'subject' => $subject, 'provisioned' => false, 'revision' => null, 'access' => null,
            'allowed_edits' => ['application_admin' => false, 'workspaces' => false, 'provision' => true],
        ];
    }

    /** @param array<string, mixed> $input */
    private function body(array $input): string
    {
        return (string) json_encode(['contract_version' => 2, 'application' => self::APPLICATION, ...$input], JSON_UNESCAPED_SLASHES);
    }

    /** @param array<string, mixed> $input */
    private function send(array $input, string $subject = 'actor-subject', ?string $token = null, ?string $body = null): TestResponse
    {
        $body ??= $this->body($input);

        return $this->call('POST', '/application-access', [], [], [], [
            'CONTENT_TYPE' => 'application/json',
            'HTTP_ACCEPT' => 'application/json',
            'HTTP_AUTHORIZATION' => 'Bearer '.($token ?? $this->assertion($subject, $body)),
        ], $body);
    }

    private function assertion(string $subject, string $body): string
    {
        $now = new DateTimeImmutable('@'.time());

        return Builder::new(new JoseEncoder, ChainedFormatter::withUnixTimestampDates())
            ->withHeader('typ', 'application-access+jwt')
            ->withHeader('kid', 'integration-v1')
            ->issuedBy(self::ISSUER)->relatedTo($subject)->permittedFor(self::ENDPOINT)
            ->issuedAt($now)->expiresAt($now->modify('+60 seconds'))
            ->identifiedBy(bin2hex(random_bytes(32)))
            ->withClaim('application', self::APPLICATION)
            ->withClaim('method', 'POST')
            ->withClaim('body_sha256', hash('sha256', $body))
            ->getToken(new Sha256, InMemory::plainText($this->privateKey))
            ->toString();
    }
}
