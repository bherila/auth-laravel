<?php

namespace BWH\Auth\Tests\Feature;

use BWH\Auth\OAuth\DelegatedAccess\ApplicationAccessAdapter;
use BWH\Auth\OAuth\DelegatedAccess\DatabaseNonceStore;
use BWH\Auth\OAuth\DelegatedAccess\DelegatedAccessException;
use BWH\Auth\OAuth\DelegatedAccess\DelegatedAccessSettings;
use BWH\Auth\OAuth\DelegatedAccess\DelegatedContract;
use BWH\Auth\OAuth\DelegatedAccess\DelegatedCursor;
use BWH\Auth\OAuth\DelegatedAccess\DelegatedRequestContext;
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
 * assertion bound to the exact body, and every success checked against contract version 3.
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
            'bherila-auth.oauth_client.base_url' => self::ISSUER,
            'bherila-auth.delegated_access' => [
                'enabled' => true,
                'writes_enabled' => true,
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
        $this->assertSame(['contract_version' => 3, 'application' => self::APPLICATION, 'operation' => 'capabilities'], array_slice($response->json(), 0, 3, true));
        (new DelegatedContract)->response($response->json(), self::APPLICATION, 'capabilities', null, DelegatedContract::VERSION_3);
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
            (string) json_encode(['contract_version' => 2, 'application' => self::APPLICATION, 'operation' => 'capabilities']),
            (string) json_encode(['contract_version' => '3', 'application' => self::APPLICATION, 'operation' => 'capabilities']),
            (string) json_encode(['contract_version' => 3, 'application' => 'another-app', 'operation' => 'capabilities']),
            '{not json',
            (string) json_encode(['contract_version' => 3, 'application' => self::APPLICATION, 'operation' => 'delete']),
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
        $this->answer = static fn (): array => ['controls' => ['application_admin' => false, 'workspace_roles' => [], 'provisioning' => 'yes']];

        $this->send(['operation' => 'capabilities'])->assertStatus(500)->assertExactJson(['error' => 'internal_error']);
        Exceptions::assertReported(DelegatedAccessException::class);
    }

    public function test_an_account_only_application_advertises_no_workspace_roles(): void
    {
        $this->answer = static fn (): array => ['controls' => ['application_admin' => true, 'workspace_roles' => [], 'provisioning' => true]];

        $this->send(['operation' => 'capabilities'])->assertOk()->assertJsonPath('controls.workspace_roles', []);
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

    /** The assertion issuer must be the sign-in provider, or a subject resolves in the wrong namespace. */
    public function test_the_assertion_issuer_must_be_the_sign_in_provider(): void
    {
        config(['bherila-auth.oauth_client.base_url' => 'https://other-identity.example.test']);
        $this->send(['operation' => 'capabilities'])->assertStatus(503)->assertJsonPath('error', 'invalid_verifier_configuration');
        $this->assertSame([], $this->calls);

        config(['bherila-auth.oauth_client.base_url' => self::ISSUER.'/']);
        $this->send(['operation' => 'capabilities'])->assertOk();
    }

    public function test_the_adapter_can_read_the_verified_request_context_during_its_call_only(): void
    {
        $seen = null;
        $this->answer = function (string $actor, array $payload) use (&$seen): array {
            $seen = app(DelegatedRequestContext::class);

            return self::capabilities();
        };

        $this->send(['operation' => 'capabilities'])->assertOk();

        $this->assertInstanceOf(DelegatedRequestContext::class, $seen);
        $this->assertSame([self::ISSUER, 'actor-subject', self::APPLICATION, 'capabilities'], [$seen->issuer, $seen->subject, $seen->application, $seen->operation]);
        $this->assertMatchesRegularExpression('/^[a-f0-9]{64}$/', $seen->jti);
        $this->assertFalse(app()->bound(DelegatedRequestContext::class), 'The context is unbound once the adapter returns.');
    }

    public function test_writes_are_refused_before_the_adapter_until_this_application_enables_them(): void
    {
        config(['bherila-auth.delegated_access.writes_enabled' => false]);
        $update = ['operation' => 'update', 'subject' => 'target-subject', 'expected_revision' => 'r1',
            'access' => ['application_admin' => false, 'workspaces' => []], 'operation_id' => DelegatedContract::operationId()];
        $remove = ['operation' => 'remove', 'subject' => 'target-subject', 'expected_revision' => 'r1', 'operation_id' => DelegatedContract::operationId()];

        $this->send($update)->assertStatus(403)->assertJsonPath('error', 'not_authorized');
        $this->send($remove)->assertStatus(403)->assertJsonPath('error', 'not_authorized');
        $this->send(['operation' => 'capabilities'])->assertOk();

        $this->assertSame([['actor-subject', ['operation' => 'capabilities']]], $this->calls);
    }

    public function test_an_unbound_adapter_is_a_server_error(): void
    {
        Exceptions::fake();
        unset($this->app[ApplicationAccessAdapter::class]);

        $this->send(['operation' => 'capabilities'])->assertStatus(500)->assertJsonPath('error', 'internal_error');
    }

    public function test_the_rate_limit_applies_only_once_enabled_so_a_disabled_endpoint_never_answers_429(): void
    {
        RateLimiter::clear('bherila-auth-delegated-access:127.0.0.1');
        config(['bherila-auth.delegated_access.per_minute' => 1, 'bherila-auth.delegated_access.enabled' => false]);

        $this->send(['operation' => 'capabilities'])->assertNotFound();
        $this->send(['operation' => 'capabilities'])->assertNotFound();

        config(['bherila-auth.delegated_access.enabled' => true]);

        $this->send(['operation' => 'capabilities'])->assertOk();
        $this->send(['operation' => 'capabilities'])->assertStatus(429)->assertJsonPath('error', 'rate_limited')->assertHeaderContains('Cache-Control', 'no-store');
        $this->assertCount(1, $this->calls);
    }

    public function test_the_bearer_scheme_is_case_insensitive_and_must_carry_exactly_one_credential(): void
    {
        $body = $this->body(['operation' => 'capabilities']);

        foreach (['bearer', 'BEARER'] as $scheme) {
            $this->call('POST', '/application-access', [], [], [], [
                'CONTENT_TYPE' => 'application/json',
                'HTTP_AUTHORIZATION' => $scheme.' '.$this->assertion('actor-subject', $body),
            ], $body)->assertOk();
        }

        foreach (['Bearer', 'Bearer ', 'Basic abc', 'Bearer a b'] as $header) {
            $this->call('POST', '/application-access', [], [], [], ['CONTENT_TYPE' => 'application/json', 'HTTP_AUTHORIZATION' => $header], $body)
                ->assertStatus(401)->assertJsonPath('error', 'invalid_actor_assertion');
        }
    }

    public function test_a_page_entry_with_a_field_the_contract_does_not_define_is_never_sent(): void
    {
        Exceptions::fake();

        $this->answer = static fn (): array => ['subjects' => [['subject' => 'target-subject', 'label' => 'Target', 'email' => 'person@example.test']], 'next_cursor' => null];
        $this->send(['operation' => 'subjects'])->assertStatus(500)->assertExactJson(['error' => 'internal_error']);

        $this->answer = static fn (): array => ['workspaces' => [['id' => 'workspace-1', 'label' => 'One', 'internal_id' => 7]], 'next_cursor' => null];
        $this->send(['operation' => 'workspaces'])->assertStatus(500)->assertExactJson(['error' => 'internal_error']);

        $this->answer = static fn (): array => ['workspaces' => [['id' => 'workspace-1', 'label' => 'One']], 'next_cursor' => null];
        $this->send(['operation' => 'workspaces'])->assertOk()->assertJsonPath('workspaces.0.id', 'workspace-1');

        Exceptions::assertReported(DelegatedAccessException::class);
    }

    public function test_an_answer_with_a_field_the_contract_does_not_define_or_missing_one_is_never_sent(): void
    {
        Exceptions::fake();

        $this->answer = static fn (): array => self::capabilities() + ['internal_note' => 'not for the provider'];
        $this->send(['operation' => 'capabilities'])->assertStatus(500)->assertExactJson(['error' => 'internal_error']);

        $this->answer = static fn (string $actor, array $payload): array => array_diff_key(self::unprovisioned((string) $payload['subject']), ['allowed_edits' => true]);
        $this->send(['operation' => 'read', 'subject' => 'target-subject'])->assertStatus(500);

        Exceptions::assertReported(DelegatedAccessException::class);
    }

    public function test_a_search_reaches_the_adapter_as_the_query_it_was_sent(): void
    {
        $this->answer = static fn (): array => ['subjects' => [['subject' => 'target-subject', 'label' => 'Example Person']], 'next_cursor' => null];

        $this->send(['operation' => 'subjects', 'query' => 'Exam', 'limit' => 10])->assertOk()->assertJsonPath('subjects.0.subject', 'target-subject');
        $this->send(['operation' => 'workspaces', 'query' => 'x'])->assertStatus(422)->assertJsonPath('error', 'invalid_request');

        $this->assertSame([['actor-subject', ['operation' => 'subjects', 'query' => 'Exam', 'limit' => 10]]], $this->calls);
    }

    public function test_a_removal_reaches_the_adapter_with_its_operation_and_must_answer_an_empty_projection(): void
    {
        Exceptions::fake();
        $operationId = DelegatedContract::operationId();
        $remove = ['operation' => 'remove', 'subject' => 'target-subject', 'expected_revision' => 'r1', 'operation_id' => $operationId];
        $seen = null;
        $this->answer = function (string $actor, array $payload) use (&$seen): array {
            $seen = app(DelegatedRequestContext::class);

            return self::provisioned((string) $payload['subject'], ['application_admin' => false, 'workspaces' => []]) + ['provisioned_at' => '2026-10-01T09:30:00Z'];
        };

        $this->send($remove)->assertOk()->assertJsonPath('operation', 'remove')->assertJsonPath('access.workspaces', [])->assertJsonPath('provisioned_at', '2026-10-01T09:30:00Z');
        $this->assertSame(['actor-subject', $remove], $this->calls[0]);
        $this->assertInstanceOf(DelegatedRequestContext::class, $seen);
        $this->assertSame(['remove', $operationId], [$seen->operation, $seen->operationId]);

        // An answer that leaves something the actor manages is not a removal.
        $this->answer = static fn (string $actor, array $payload): array => self::provisioned((string) $payload['subject'], ['application_admin' => true, 'workspaces' => []]);
        $this->send([...$remove, 'operation_id' => DelegatedContract::operationId()])->assertStatus(500)->assertExactJson(['error' => 'internal_error']);
        Exceptions::assertReported(DelegatedAccessException::class);
    }

    public function test_a_read_has_no_operation_id_in_its_context(): void
    {
        $seen = null;
        $this->answer = function (string $actor, array $payload) use (&$seen): array {
            $seen = app(DelegatedRequestContext::class);

            return self::unprovisioned((string) $payload['subject']);
        };

        $this->send(['operation' => 'read', 'subject' => 'target-subject'])->assertOk();
        $this->assertNull($seen?->operationId);
    }

    public function test_an_operation_id_that_is_the_assertion_jti_is_refused_before_the_adapter(): void
    {
        $jti = bin2hex(random_bytes(32));
        $body = $this->body(['operation' => 'remove', 'subject' => 'target-subject', 'expected_revision' => 'r1', 'operation_id' => $jti]);

        $this->send([], token: $this->assertion('actor-subject', $body, $jti), body: $body)->assertStatus(422)->assertJsonPath('error', 'invalid_request');
        $this->assertSame([], $this->calls);
    }

    public function test_a_state_with_malformed_metadata_is_never_sent(): void
    {
        Exceptions::fake();
        $this->answer = static fn (string $actor, array $payload): array => self::provisioned((string) $payload['subject'], ['application_admin' => false, 'workspaces' => []]) + ['last_seen_at' => '2026-10-10 12:00:00'];

        $this->send(['operation' => 'read', 'subject' => 'target-subject'])->assertStatus(500)->assertExactJson(['error' => 'internal_error']);
        Exceptions::assertReported(DelegatedAccessException::class);
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
            ['contract_version' => 3, 'application' => self::APPLICATION, 'operation' => 'subjects', 'subjects' => [], 'next_cursor' => $cursor],
            self::APPLICATION, 'subjects', null, DelegatedContract::VERSION_3,
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

    /**
     * @param  array<string, mixed>  $access
     * @return array<string, mixed>
     */
    private static function provisioned(string $subject, array $access): array
    {
        return [
            'subject' => $subject, 'provisioned' => true, 'revision' => 'r2', 'access' => $access,
            'allowed_edits' => ['application_admin' => false, 'workspaces' => true, 'provision' => false],
        ];
    }

    /** @param array<string, mixed> $input */
    private function body(array $input): string
    {
        return (string) json_encode(['contract_version' => 3, 'application' => self::APPLICATION, ...$input], JSON_UNESCAPED_SLASHES);
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

    private function assertion(string $subject, string $body, ?string $jti = null): string
    {
        $now = new DateTimeImmutable('@'.time());

        return Builder::new(new JoseEncoder, ChainedFormatter::withUnixTimestampDates())
            ->withHeader('typ', 'application-access+jwt')
            ->withHeader('kid', 'integration-v1')
            ->issuedBy(self::ISSUER)->relatedTo($subject)->permittedFor(self::ENDPOINT)
            ->issuedAt($now)->expiresAt($now->modify('+60 seconds'))
            ->identifiedBy($jti ?? bin2hex(random_bytes(32)))
            ->withClaim('application', self::APPLICATION)
            ->withClaim('method', 'POST')
            ->withClaim('body_sha256', hash('sha256', $body))
            ->getToken(new Sha256, InMemory::plainText($this->privateKey))
            ->toString();
    }
}
