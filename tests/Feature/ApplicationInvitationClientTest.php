<?php

namespace BWH\Auth\Tests\Feature;

use BWH\Auth\OAuth\Invitations\ApplicationInvitationActorNotEligible;
use BWH\Auth\OAuth\Invitations\ApplicationInvitationClient;
use BWH\Auth\OAuth\Invitations\ApplicationInvitationConflict;
use BWH\Auth\OAuth\Invitations\ApplicationInvitationError;
use BWH\Auth\OAuth\Invitations\ApplicationInvitationException;
use BWH\Auth\OAuth\Invitations\ApplicationInvitationInvalid;
use BWH\Auth\OAuth\Invitations\ApplicationInvitationMisconfigured;
use BWH\Auth\OAuth\Invitations\ApplicationInvitationNotFound;
use BWH\Auth\OAuth\Invitations\ApplicationInvitationRateLimited;
use BWH\Auth\OAuth\Invitations\ApplicationInvitations;
use BWH\Auth\OAuth\Invitations\ApplicationInvitationUnavailable;
use BWH\Auth\OAuth\Invitations\IssuedInvitation;
use BWH\Auth\Tests\Fixtures\ConfiguresApplicationInvitations;
use BWH\Auth\Tests\TestCase;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use PHPUnit\Framework\Attributes\DataProvider;

class ApplicationInvitationClientTest extends TestCase
{
    use ConfiguresApplicationInvitations;

    protected function setUp(): void
    {
        parent::setUp();
        $this->configureInvitations();
    }

    public function test_the_container_resolves_the_provider_client_once(): void
    {
        $this->assertInstanceOf(ApplicationInvitationClient::class, $this->invitations());
        $this->assertSame($this->invitations(), $this->invitations());
    }

    public function test_create_gets_a_client_credentials_token_and_returns_the_invitation(): void
    {
        $this->provider();

        $issued = $this->invitations()->create('42', 'person@example.test');

        [$token] = $this->tokenRequests();
        $this->assertSame(self::ISSUER.'/oauth/token', $token->url());
        $this->assertSame('POST', $token->method());
        $this->assertSame(['grant_type' => 'client_credentials', 'client_id' => self::CLIENT_ID,
            'client_secret' => self::SECRET, 'scope' => 'invitations:admit'], $token->data());
        $this->assertSame(42, $issued->id);
        $this->assertSame('pending', $issued->status);
        $this->assertSame('2026-10-19T12:00:00+00:00', $issued->expiresAt->format(DATE_ATOM));
        $this->assertSame(self::ISSUER.'/invitations/example-link-token', $issued->link);
        $this->assertTrue($issued->emailSent);
    }

    public function test_requests_never_follow_redirects_and_are_bounded_in_time(): void
    {
        $options = [];
        Http::fake(function (Request $request, array $sent) use (&$options) {
            $options[] = $sent;

            return str_ends_with($request->url(), '/oauth/token')
                ? Http::response(['token_type' => 'Bearer', 'expires_in' => 300, 'access_token' => self::TOKEN])
                : Http::response(self::issuedBody(), 201);
        });
        config(['bherila-auth.application_invitations.timeout_seconds' => 120]);

        $this->invitations()->create('42', 'person@example.test');

        $this->assertCount(2, $options);
        foreach ($options as $sent) {
            $this->assertFalse($sent['allow_redirects']);
            $this->assertSame(3, $sent['connect_timeout']);
            $this->assertSame(30, $sent['timeout']);
            $this->assertTrue($sent['stream']);
        }
    }

    public function test_the_token_is_reused_until_shortly_before_it_expires(): void
    {
        $this->travelTo(new \DateTimeImmutable('2026-10-12T12:00:00Z'));
        $this->provider(fn () => Http::response(self::issuedBody(), 200));

        $this->invitations()->resend('42', 42);
        $this->invitations()->resend('42', 42);
        $this->assertCount(1, $this->tokenRequests());

        // Another process: the cached token, stored encrypted.
        $this->app->forgetInstance(ApplicationInvitations::class);
        $this->invitations()->resend('42', 42);
        $this->assertCount(1, $this->tokenRequests());
        $this->assertCount(3, $this->invitationRequests());

        // 300 s token, not reused within 30 s of expiry.
        $this->travelTo(new \DateTimeImmutable('2026-10-12T12:04:31Z'));
        $this->invitations()->resend('42', 42);
        $this->assertCount(2, $this->tokenRequests());
    }

    public function test_the_cached_token_is_encrypted_and_bound_to_the_credential(): void
    {
        $this->provider(fn () => Http::response(self::issuedBody(), 200));
        $this->invitations()->resend('42', 42);

        $store = Cache::store('array');
        $keys = array_keys((fn () => $this->storage)->call($store->getStore()));
        $this->assertCount(1, $keys);
        $this->assertStringNotContainsString(self::TOKEN, serialize($store->get($keys[0])));

        // A rotated secret never reuses the old token.
        config(['bherila-auth.oauth_client.client_secret' => 'rotated-secret-value']);
        $this->app->forgetInstance(ApplicationInvitations::class);
        $this->invitations()->resend('42', 42);
        $this->assertCount(2, $this->tokenRequests());
    }

    public function test_the_token_can_be_kept_to_the_process(): void
    {
        config(['bherila-auth.application_invitations.token_cache_store' => false]);
        $this->provider(fn () => Http::response(self::issuedBody(), 200));

        $this->invitations()->resend('42', 42);
        $this->app->forgetInstance(ApplicationInvitations::class);
        $this->invitations()->resend('42', 42);

        $this->assertCount(2, $this->tokenRequests());
    }

    public function test_a_reused_token_the_provider_refuses_is_replaced_once(): void
    {
        $answers = [Http::response(self::issuedBody(), 200), Http::response(['error' => 'invalid_token', 'message' => 'x'], 401), Http::response(self::issuedBody(), 200)];
        $this->provider(function () use (&$answers) {
            return array_shift($answers);
        });

        $this->invitations()->resend('42', 42);
        $issued = $this->invitations()->resend('42', 42);

        $this->assertSame(42, $issued->id);
        $this->assertCount(2, $this->tokenRequests());
        [, $refused, $retried] = $this->invitationRequests();
        $this->assertNotSame($refused->header('Actor-Assertion'), $retried->header('Actor-Assertion'));
    }

    public function test_a_new_token_the_provider_refuses_is_not_retried(): void
    {
        $this->provider(['error' => 'invalid_token', 'message' => 'x'], 401);

        $refused = $this->refusal(fn () => $this->invitations()->create('42', 'person@example.test'));

        $this->assertInstanceOf(ApplicationInvitationMisconfigured::class, $refused);
        $this->assertSame(ApplicationInvitationError::InvalidToken, $refused->error);
        $this->assertCount(1, $this->tokenRequests());
        $this->assertCount(1, $this->invitationRequests());
    }

    /** @return array<string, array{0: int, 1: array<mixed>, 2: class-string, 3: ApplicationInvitationError}> */
    public static function refusals(): array
    {
        $cases = [];
        foreach ([
            [401, 'invalid_token', ApplicationInvitationMisconfigured::class],
            [403, 'insufficient_scope', ApplicationInvitationMisconfigured::class],
            [403, 'application_not_enabled', ApplicationInvitationMisconfigured::class],
            [401, 'invalid_actor_assertion', ApplicationInvitationMisconfigured::class],
            [401, 'replayed_actor_assertion', ApplicationInvitationMisconfigured::class],
            [503, 'invalid_configuration', ApplicationInvitationMisconfigured::class],
            [403, 'actor_not_eligible', ApplicationInvitationActorNotEligible::class],
            [422, 'invalid_request', ApplicationInvitationInvalid::class],
            [404, 'invitation_not_found', ApplicationInvitationNotFound::class],
            [409, 'invitation_not_pending', ApplicationInvitationConflict::class],
            [409, 'invitation_accepted', ApplicationInvitationConflict::class],
            [409, 'concurrent_invitation', ApplicationInvitationConflict::class],
            [429, 'rate_limited', ApplicationInvitationRateLimited::class],
            [503, 'mail_unavailable', ApplicationInvitationUnavailable::class],
            [503, 'replay_storage_unavailable', ApplicationInvitationUnavailable::class],
        ] as [$status, $code, $class]) {
            $cases[$code] = [$status, ['error' => $code, 'message' => 'Provider text.'], $class, ApplicationInvitationError::from($code)];
        }
        // A code the contract gives another status, or none, is not trusted as that code.
        $cases['a known code at another status'] = [500, ['error' => 'invitation_not_found'], ApplicationInvitationUnavailable::class, ApplicationInvitationError::Unavailable];
        $cases['an unknown code'] = [400, ['error' => 'something_else'], ApplicationInvitationUnavailable::class, ApplicationInvitationError::Unavailable];
        $cases['a server error page'] = [502, [], ApplicationInvitationUnavailable::class, ApplicationInvitationError::Unavailable];
        // The provider's coarse throttle answers 429 without a code.
        $cases['the coarse throttle'] = [429, ['message' => 'Too Many Attempts.'], ApplicationInvitationRateLimited::class, ApplicationInvitationError::RateLimited];

        return $cases;
    }

    #[DataProvider('refusals')]
    public function test_each_refusal_is_its_typed_exception(int $status, array $body, string $class, ApplicationInvitationError $error): void
    {
        $this->provider($body, $status);

        $refused = $this->refusal(fn () => $this->invitations()->resend('42', 7));

        $this->assertInstanceOf($class, $refused);
        $this->assertSame($error, $refused->error);
        $this->assertSame($status, $refused->status);
        $this->assertStringNotContainsString('Provider text', $refused->getMessage());
        $this->assertNull($refused->getPrevious());
    }

    public function test_a_rate_limit_names_its_limit_and_delay(): void
    {
        $this->provider(['error' => 'rate_limited', 'message' => 'x', 'limit' => 'recipient'], 429, ['Retry-After' => '120']);

        $refused = $this->refusal(fn () => $this->invitations()->create('42', 'person@example.test'));

        $this->assertInstanceOf(ApplicationInvitationRateLimited::class, $refused);
        $this->assertSame('recipient', $refused->limit);
        $this->assertSame(120, $refused->retryAfter);
    }

    public function test_an_unknown_limit_or_delay_is_dropped(): void
    {
        $this->provider(['error' => 'rate_limited', 'message' => 'x', 'limit' => 'everyone'], 429, ['Retry-After' => 'Wed, 21 Oct 2026 07:28:00 GMT']);

        $refused = $this->refusal(fn () => $this->invitations()->create('42', 'person@example.test'));

        $this->assertInstanceOf(ApplicationInvitationRateLimited::class, $refused);
        $this->assertNull($refused->limit);
        $this->assertNull($refused->retryAfter);
    }

    public function test_an_invalid_request_carries_the_field_messages(): void
    {
        $this->provider(['error' => 'invalid_request', 'message' => 'x', 'errors' => [
            'email' => ['The email field must be a valid email address.', ['nested']],
            'roles' => ['This field is not accepted.'],
            7 => ['not a field'],
        ]], 422);

        $refused = $this->refusal(fn () => $this->invitations()->create('42', 'not-an-address'));

        $this->assertInstanceOf(ApplicationInvitationInvalid::class, $refused);
        $this->assertSame(['email' => ['The email field must be a valid email address.'], 'roles' => ['This field is not accepted.']], $refused->errors);
    }

    public function test_an_address_that_cannot_be_sent_is_refused_before_anything_is_sent(): void
    {
        Http::fake();

        foreach (['', str_repeat('a', 244).'@example.test', "\xC3\x28@example.test"] as $email) {
            $refused = $this->refusal(fn () => $this->invitations()->create('42', $email));
            $this->assertInstanceOf(ApplicationInvitationInvalid::class, $refused);
            $this->assertNull($refused->status);
            $this->assertArrayHasKey('email', $refused->errors);
        }
        Http::assertNothingSent();
    }

    public function test_the_actor_subject_and_invitation_id_are_checked_before_anything_is_sent(): void
    {
        Http::fake();

        foreach ([
            fn () => $this->invitations()->create('042', 'person@example.test'),
            fn () => $this->invitations()->create('', 'person@example.test'),
            fn () => $this->invitations()->create('user@example.test', 'person@example.test'),
            fn () => $this->invitations()->resend('42', 0),
            fn () => $this->invitations()->revoke('42', -1),
        ] as $call) {
            try {
                $call();
                $this->fail('An invalid actor subject or invitation id was accepted.');
            } catch (\InvalidArgumentException) {
            }
        }
        Http::assertNothingSent();
    }

    /** @return array<string, array{0: int, 1: mixed}> */
    public static function invalidAnswers(): array
    {
        return [
            'create answered 200' => [200, self::issuedBody()],
            'no invitation' => [201, ['id' => 42]],
            'a string id' => [201, self::issuedBody(['id' => '42'])],
            'not pending' => [201, self::issuedBody(['status' => 'revoked'])],
            'an expiry with an offset' => [201, self::issuedBody(['expires_at' => '2026-10-19T12:00:00+00:00'])],
            'an impossible expiry' => [201, self::issuedBody(['expires_at' => '2026-02-30T12:00:00Z'])],
            'no link' => [201, self::issuedBody(['link' => null])],
            'an http link' => [201, self::issuedBody(['link' => 'http://identity.example.test/invitations/x'])],
            'a link with credentials' => [201, self::issuedBody(['link' => 'https://u:p@identity.example.test/invitations/x'])],
            'email_sent not a boolean' => [201, self::issuedBody(['email_sent' => 1])],
            'a list' => [201, [self::issuedBody()]],
            'too large' => [201, self::issuedBody(['padding' => str_repeat('x', 20_000)])],
        ];
    }

    #[DataProvider('invalidAnswers')]
    public function test_an_answer_outside_the_contract_is_refused(int $status, mixed $body): void
    {
        $this->provider($body, $status);

        $refused = $this->refusal(fn () => $this->invitations()->create('42', 'person@example.test'));

        $this->assertInstanceOf(ApplicationInvitationUnavailable::class, $refused);
        $this->assertSame(ApplicationInvitationError::InvalidResponse, $refused->error);
    }

    public function test_resend_and_revoke_must_answer_for_the_same_invitation(): void
    {
        $answers = [
            Http::response(self::issuedBody(['id' => 43]), 200),
            Http::response(['invitation' => ['id' => 43, 'status' => 'revoked']], 200),
            Http::response(['invitation' => ['id' => 42, 'status' => 'pending']], 200),
            Http::response(['invitation' => ['id' => 42, 'status' => 'revoked']], 200),
        ];
        $this->provider(function () use (&$answers) {
            return array_shift($answers);
        });

        $this->assertSame(ApplicationInvitationError::InvalidResponse, $this->refusal(fn () => $this->invitations()->resend('42', 42))->error);
        $this->assertSame(ApplicationInvitationError::InvalidResponse, $this->refusal(fn () => $this->invitations()->revoke('42', 42))->error);
        $this->assertSame(ApplicationInvitationError::InvalidResponse, $this->refusal(fn () => $this->invitations()->revoke('42', 42))->error);
        $revoked = $this->invitations()->revoke('42', 42);
        $this->assertSame([42, 'revoked'], [$revoked->id, $revoked->status]);
    }

    /** @return array<string, array{0: array<string, mixed>}> */
    public static function misconfigurations(): array
    {
        return [
            'no client id' => [['bherila-auth.oauth_client.client_id' => null]],
            'no client secret' => [['bherila-auth.oauth_client.client_secret' => '']],
            'no key id' => [['bherila-auth.application_invitations.key_id' => null]],
            'no private key' => [['bherila-auth.application_invitations.private_key' => null]],
            'both a key path and a key' => [['bherila-auth.application_invitations.private_key_path' => __FILE__]],
            'an unreadable key path' => [['bherila-auth.application_invitations.private_key' => null, 'bherila-auth.application_invitations.private_key_path' => '/nonexistent/key.pem']],
            'not a key' => [['bherila-auth.application_invitations.private_key' => 'not a key']],
            'an http issuer' => [['bherila-auth.oauth_client.base_url' => 'http://identity.example.test']],
            'an issuer with a path' => [['bherila-auth.application_invitations.issuer' => 'https://identity.example.test/id']],
            'an issuer with credentials' => [['bherila-auth.application_invitations.issuer' => 'https://u:p@identity.example.test']],
            'a token path that is not a path' => [['bherila-auth.oauth_client.token_path' => 'https://elsewhere.example.test/token']],
        ];
    }

    /** @param  array<string, mixed>  $settings */
    #[DataProvider('misconfigurations')]
    public function test_a_misconfiguration_refuses_before_anything_is_sent(array $settings): void
    {
        config($settings);
        Http::fake();

        $refused = $this->refusal(fn () => $this->invitations()->create('42', 'person@example.test'));

        $this->assertInstanceOf(ApplicationInvitationMisconfigured::class, $refused);
        $this->assertSame(ApplicationInvitationError::NotConfigured, $refused->error);
        Http::assertNothingSent();
    }

    public function test_a_small_rsa_key_is_refused(): void
    {
        $key = openssl_pkey_new(['private_key_bits' => 1024, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        openssl_pkey_export($key, $pem);
        config(['bherila-auth.application_invitations.private_key' => $pem]);
        Http::fake();

        $this->assertSame(ApplicationInvitationError::NotConfigured, $this->refusal(fn () => $this->invitations()->revoke('42', 1))->error);
        Http::assertNothingSent();
    }

    public function test_the_key_can_be_read_from_a_file_and_the_issuer_overridden(): void
    {
        $path = tempnam(sys_get_temp_dir(), 'invitation-key-');
        file_put_contents($path, $this->privateKey);
        config([
            'bherila-auth.application_invitations.private_key' => null,
            'bherila-auth.application_invitations.private_key_path' => $path,
            'bherila-auth.oauth_client.base_url' => 'https://sign-in.example.test',
            'bherila-auth.application_invitations.issuer' => self::ISSUER.'/',
        ]);
        $this->provider(['invitation' => ['id' => 5, 'status' => 'revoked']], 200);

        try {
            $this->invitations()->revoke('42', 5);
        } finally {
            unlink($path);
        }

        $this->assertSame(self::ISSUER.'/oauth/token', $this->tokenRequests()[0]->url());
        $this->assertSame(self::ISSUER.'/api/application-invitations/5/revoke', $this->invitationRequests()[0]->url());
    }

    public function test_the_token_endpoint_refusing_the_client_is_a_misconfiguration(): void
    {
        Http::fake(['*/oauth/token' => Http::response(['error' => 'invalid_client'], 401)]);

        $refused = $this->refusal(fn () => $this->invitations()->create('42', 'person@example.test'));

        $this->assertInstanceOf(ApplicationInvitationMisconfigured::class, $refused);
        $this->assertSame(ApplicationInvitationError::TokenRefused, $refused->error);
        Http::assertSentCount(1);
    }

    /** @return array<string, array{0: int, 1: array<mixed>, 2: ApplicationInvitationError}> */
    public static function tokenAnswers(): array
    {
        return [
            'a server error' => [500, [], ApplicationInvitationError::Unavailable],
            'no token' => [200, ['token_type' => 'Bearer', 'expires_in' => 300], ApplicationInvitationError::InvalidResponse],
            'not a bearer token' => [200, ['token_type' => 'MAC', 'expires_in' => 300, 'access_token' => 'x'], ApplicationInvitationError::InvalidResponse],
            'no lifetime' => [200, ['token_type' => 'Bearer', 'access_token' => 'x'], ApplicationInvitationError::InvalidResponse],
            'a token with a space' => [200, ['token_type' => 'Bearer', 'expires_in' => 300, 'access_token' => 'a b'], ApplicationInvitationError::InvalidResponse],
        ];
    }

    #[DataProvider('tokenAnswers')]
    public function test_a_token_answer_outside_the_contract_is_refused(int $status, array $body, ApplicationInvitationError $error): void
    {
        Http::fake(['*/oauth/token' => Http::response($body, $status)]);

        $refused = $this->refusal(fn () => $this->invitations()->create('42', 'person@example.test'));

        $this->assertInstanceOf(ApplicationInvitationUnavailable::class, $refused);
        $this->assertSame($error, $refused->error);
        Http::assertSentCount(1);
    }

    public function test_failures_never_carry_credentials_the_address_or_the_transport_error(): void
    {
        Http::fake(function (Request $request) {
            if (str_ends_with($request->url(), '/oauth/token')) {
                return Http::response(['token_type' => 'Bearer', 'expires_in' => 300, 'access_token' => self::TOKEN]);
            }
            throw new ConnectionException('cURL error for '.$request->body().' with '.$request->header('Authorization')[0]);
        });

        $refused = $this->refusal(fn () => $this->invitations()->create('42', 'secret-person@example.test'));

        $this->assertInstanceOf(ApplicationInvitationUnavailable::class, $refused);
        $this->assertSame(ApplicationInvitationError::Unavailable, $refused->error);
        $this->assertNull($refused->getPrevious());
        $text = $refused->getMessage().$refused->getTraceAsString().json_encode(get_object_vars($refused));
        foreach (['secret-person', self::TOKEN, self::SECRET, 'PRIVATE KEY'] as $secret) {
            $this->assertStringNotContainsString($secret, $text);
        }
    }

    public function test_the_link_is_never_serialized_or_dumped(): void
    {
        $issued = new IssuedInvitation(42, 'pending', new \DateTimeImmutable('2026-10-19T12:00:00Z'), 'https://identity.example.test/invitations/secret-token', true);

        $this->assertSame('{"id":42,"status":"pending","expires_at":"2026-10-19T12:00:00Z","email_sent":true}', json_encode($issued));
        $this->assertStringNotContainsString('secret-token', print_r($issued, true));
        $this->assertStringNotContainsString('secret-token', var_export(json_decode(json_encode($issued), true), true));
    }

    public function test_every_reason_has_an_exception_and_a_fixed_message(): void
    {
        foreach (ApplicationInvitationError::cases() as $error) {
            $exception = ApplicationInvitationException::for($error);
            $this->assertSame($error, $exception->error);
            $this->assertSame($error->status(), $exception->status);
            $this->assertNotSame('', $exception->getMessage());
        }
    }

    private function refusal(\Closure $call): ApplicationInvitationException
    {
        try {
            $call();
        } catch (ApplicationInvitationException $refused) {
            return $refused;
        }
        $this->fail('The call was not refused.');
    }
}
