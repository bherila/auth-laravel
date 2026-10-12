<?php

namespace BWH\Auth\Tests\Feature;

use BWH\Auth\OAuth\Invitations\ApplicationInvitationClient;
use BWH\Auth\OAuth\Invitations\ApplicationInvitationException;
use BWH\Auth\OAuth\Invitations\ApplicationInvitationInvalid;
use BWH\Auth\OAuth\Invitations\ApplicationInvitationRateLimited;
use BWH\Auth\OAuth\Invitations\InvitationArguments;
use BWH\Auth\OAuth\Invitations\IssuedInvitation;
use BWH\Auth\Testing\FakeApplicationInvitations;
use BWH\Auth\Tests\Fixtures\ConfiguresApplicationInvitations;
use BWH\Auth\Tests\TestCase;
use Illuminate\Support\Facades\Http;
use PHPUnit\Framework\Attributes\DataProvider;
use SensitiveParameter;
use SensitiveParameterValue;

/**
 * The property: no argument that can hold a credential (client secret, token, assertion, private
 * key or its passphrase), an invited address, an acceptance link or a provider response body
 * reaches an invitation exception's stack trace. PHP records call arguments in traces unless
 * `zend.exception_ignore_args` is on, and error reporters serialize them; only parameters marked
 * #[SensitiveParameter] are replaced.
 */
class ApplicationInvitationTraceRedactionTest extends TestCase
{
    use ConfiguresApplicationInvitations;

    /**
     * Every string, array or untyped parameter in the invitation classes that never carries one
     * of those. Anything else must be marked sensitive; a new parameter fails until classified.
     */
    private const NOT_SENSITIVE = [
        ApplicationInvitationClient::class.'::create $actorSubject',
        ApplicationInvitationClient::class.'::resend $actorSubject',
        ApplicationInvitationClient::class.'::revoke $actorSubject',
        ApplicationInvitationClient::class.'::call $path',
        ApplicationInvitationClient::class.'::call $actorSubject',
        ApplicationInvitationClient::class.'::post $url',
        ApplicationInvitationClient::class.'::sign $actorSubject',
        ApplicationInvitationClient::class.'::sign $url',
        ApplicationInvitationClient::class.'::issuer $value',
        ApplicationInvitationClient::class.'::expiresAt $value',
        ApplicationInvitationClient::class.'::retryAfter $value',
        InvitationArguments::class.'::subject $subject',
        IssuedInvitation::class.'::__construct $status',
        ApplicationInvitationRateLimited::class.'::__construct $limit',
        ApplicationInvitationException::class.'::for $limit',
        FakeApplicationInvitations::class.'::create $actorSubject',
        FakeApplicationInvitations::class.'::resend $actorSubject',
        FakeApplicationInvitations::class.'::revoke $actorSubject',
        FakeApplicationInvitations::class.'::respondNext $operation',
        FakeApplicationInvitations::class.'::refuseNext $operation',
        FakeApplicationInvitations::class.'::refuseNext $limit',
        FakeApplicationInvitations::class.'::calls $operation',
        FakeApplicationInvitations::class.'::assertCreated $actor',
        FakeApplicationInvitations::class.'::assertResent $actor',
        FakeApplicationInvitations::class.'::assertRevoked $actor',
        FakeApplicationInvitations::class.'::assertRequestCount $operation',
        FakeApplicationInvitations::class.'::assertCalled $operation',
        FakeApplicationInvitations::class.'::assertCalled $actor',
        FakeApplicationInvitations::class.'::run $operation',
        FakeApplicationInvitations::class.'::run $actor',
        FakeApplicationInvitations::class.'::script $operation',
    ];

    private string $previousIgnoreArgs;

    protected function setUp(): void
    {
        parent::setUp();
        $this->configureInvitations();
        $this->previousIgnoreArgs = (string) ini_get('zend.exception_ignore_args');
        ini_set('zend.exception_ignore_args', '0');
    }

    protected function tearDown(): void
    {
        ini_set('zend.exception_ignore_args', $this->previousIgnoreArgs);
        parent::tearDown();
    }

    public function test_every_parameter_that_can_carry_a_secret_is_redacted_from_traces(): void
    {
        $unmarked = [];
        $seen = [];
        foreach ([ApplicationInvitationClient::class, InvitationArguments::class, IssuedInvitation::class, ApplicationInvitationException::class,
            ApplicationInvitationInvalid::class, ApplicationInvitationRateLimited::class, FakeApplicationInvitations::class] as $class) {
            foreach ((new \ReflectionClass($class))->getMethods() as $method) {
                if ($method->getDeclaringClass()->getName() !== $class) {
                    continue;
                }
                foreach ($method->getParameters() as $parameter) {
                    if (! self::canCarryText($parameter->getType())) {
                        continue;
                    }
                    $site = $class.'::'.$method->getName().' $'.$parameter->getName();
                    $seen[] = $site;
                    if ($parameter->getAttributes(SensitiveParameter::class) === [] && ! in_array($site, self::NOT_SENSITIVE, true)) {
                        $unmarked[] = $site;
                    }
                }
            }
        }

        $this->assertSame([], $unmarked, 'Mark these #[SensitiveParameter], or list them as never carrying a secret.');
        $this->assertSame([], array_values(array_diff(self::NOT_SENSITIVE, $seen)), 'Stale entries in NOT_SENSITIVE.');
    }

    /** @return array<string, array{0: \Closure(self): void, 1: \Closure(self): void}> */
    public static function failures(): array
    {
        $create = fn (self $test) => $test->invitations()->create('42', 'secret-person@example.test');

        return [
            'a success answer outside the contract, carrying a link' => [
                fn (self $test) => $test->provider(self::issuedBody(['link' => self::ISSUER.'/invitations/secret-link-token', 'email_sent' => 'yes'])),
                $create],
            'a refusal body' => [
                fn (self $test) => $test->provider(['error' => 'invalid_request', 'message' => 'secret-provider-detail',
                    'errors' => ['email' => ['secret-provider-detail']]], 422),
                $create],
            'an invalid private key with a passphrase' => [
                fn (self $test) => config(['bherila-auth.application_invitations.private_key' => "-----BEGIN PRIVATE KEY-----\nsecret-key-material\n-----END PRIVATE KEY-----",
                    'bherila-auth.application_invitations.private_key_passphrase' => 'secret-passphrase']),
                $create],
            'a passphrase in the settings' => [
                fn (self $test) => config(['bherila-auth.application_invitations.private_key_passphrase' => 'secret-passphrase']),
                fn (self $test) => $test->invitations()->revoke('42', 1)],
            'a token answer outside the contract' => [
                fn (self $test) => Http::fake(['*/oauth/token' => Http::response(['token_type' => 'Bearer', 'access_token' => 'secret token with spaces', 'expires_in' => 300])]),
                $create],
            'a transport failure' => [
                fn (self $test) => Http::fake(fn () => throw new \RuntimeException('secret-transport-detail')),
                $create],
        ];
    }

    #[DataProvider('failures')]
    public function test_no_failure_trace_carries_a_secret(\Closure $arrange, \Closure $act): void
    {
        $arrange($this);

        try {
            $act($this);
            $this->fail('The call was not refused.');
        } catch (ApplicationInvitationException $refused) {
            // The package's own frames; a caller's frames hold the caller's arguments.
            $frames = array_filter($refused->getTrace(), fn (array $frame): bool => str_starts_with($frame['class'] ?? '', 'BWH\\Auth\\')
                && ! str_starts_with($frame['class'], 'BWH\\Auth\\Tests\\'));
            $this->assertNotSame([], $frames);
            $text = implode("\n", self::strings(array_column($frames, 'args')));
            foreach (['secret-person', 'secret-link-token', 'secret-provider-detail', 'secret-key-material', 'secret-passphrase',
                'secret token', 'secret-transport-detail', self::SECRET, self::TOKEN, 'PRIVATE KEY'] as $secret) {
                $this->assertStringNotContainsString($secret, $text);
            }
        }
    }

    private static function canCarryText(?\ReflectionType $type): bool
    {
        if ($type === null) {
            return true;
        }
        $types = $type instanceof \ReflectionNamedType ? [$type] : $type->getTypes();
        foreach ($types as $named) {
            // A closure carries whatever it captured, and the object it is bound to.
            if ($named instanceof \ReflectionNamedType && in_array($named->getName(), ['string', 'array', 'mixed', \Closure::class, 'callable'], true)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Every string reachable from trace arguments, through arrays, object properties and what a
     * closure captured or is bound to, except the redacted values themselves.
     *
     * @return list<string>
     */
    private static function strings(mixed $value, int $depth = 0): array
    {
        if (is_string($value)) {
            return [$value];
        }
        if ($depth > 6 || $value instanceof SensitiveParameterValue) {
            return [];
        }
        if ($value instanceof \Closure) {
            $function = new \ReflectionFunction($value);
            $value = [$function->getClosureUsedVariables(), $function->getClosureThis()];
        }
        if (is_object($value)) {
            $value = (array) $value;
        }
        if (! is_array($value)) {
            return [];
        }
        $strings = [];
        foreach ($value as $item) {
            array_push($strings, ...self::strings($item, $depth + 1));
        }

        return $strings;
    }
}
