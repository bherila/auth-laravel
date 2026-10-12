<?php

namespace BWH\Auth\Testing;

use BWH\Auth\OAuth\Invitations\ApplicationInvitationError;
use BWH\Auth\OAuth\Invitations\ApplicationInvitationException;
use BWH\Auth\OAuth\Invitations\ApplicationInvitations;
use BWH\Auth\OAuth\Invitations\InvitationArguments;
use BWH\Auth\OAuth\Invitations\IssuedInvitation;
use BWH\Auth\OAuth\Invitations\RevokedInvitation;
use DateTimeImmutable;
use DateTimeZone;
use Illuminate\Container\Container;
use Illuminate\Support\Facades\Date;
use PHPUnit\Framework\Assert;
use SensitiveParameter;

/**
 * An in-memory identity provider for application tests of invitations.
 *
 *     $invitations = FakeApplicationInvitations::swap();
 *     // ... exercise the application ...
 *     $invitations->assertCreated('person@example.test', actor: '42');
 *
 * Unscripted calls behave as the provider does: a create supersedes the pending invitation to the
 * same address (case-insensitive) and returns a new id and link; resend and revoke answer
 * `invitation_not_found` for an id this fake did not create, resend refuses a revoked or accepted
 * invitation, revoke refuses an accepted one and is idempotent otherwise; invitations expire seven
 * days after their create or resend. Arguments are checked exactly as the provider client checks
 * them. Script an outcome for the next call of an operation with {@see respondNext()} or
 * {@see refuseNext()}. Every call that reaches the "provider" is recorded, refused or not.
 */
final class FakeApplicationInvitations implements ApplicationInvitations
{
    public const LINK_BASE = 'https://identity.example.test/invitations/';

    private const OPERATIONS = ['create', 'resend', 'revoke'];

    /**
     * @var list<array{operation: 'create'|'resend'|'revoke', actor: string, email: string|null, invitation_id: int|null, result: IssuedInvitation|RevokedInvitation|null, error: ApplicationInvitationError|null}>
     */
    private array $calls = [];

    /** @var array<int, array{email: string, status: 'pending'|'revoked'|'accepted', expires_at: DateTimeImmutable, link: string}> */
    private array $invitations = [];

    /** @var array<'create'|'resend'|'revoke', list<IssuedInvitation|RevokedInvitation|ApplicationInvitationException>> */
    private array $scripted = ['create' => [], 'resend' => [], 'revoke' => []];

    private int $tokens = 0;

    /** Bind a new fake as the application's {@see ApplicationInvitations} and return it. */
    public static function swap(?Container $container = null): self
    {
        $fake = new self;
        ($container ?? Container::getInstance())->instance(ApplicationInvitations::class, $fake);

        return $fake;
    }

    public function create(string $actorSubject, #[SensitiveParameter] string $email): IssuedInvitation
    {
        InvitationArguments::subject($actorSubject);
        InvitationArguments::email($email);

        return $this->run('create', $actorSubject, $email, null, function () use ($email): IssuedInvitation {
            if (filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
                throw ApplicationInvitationException::for(ApplicationInvitationError::InvalidRequest,
                    errors: ['email' => ['The email field must be a valid email address.']]);
            }
            $normalized = mb_strtolower($email);
            foreach ($this->invitations as $id => $invitation) {
                if ($invitation['status'] === 'pending' && mb_strtolower($invitation['email']) === $normalized) {
                    $this->invitations[$id]['status'] = 'revoked';
                }
            }
            $id = count($this->invitations) + 1;
            $this->invitations[$id] = ['email' => $email, 'status' => 'pending', 'expires_at' => self::expiry(), 'link' => $this->link($id)];

            return $this->issued($id);
        });
    }

    public function resend(string $actorSubject, int $invitationId): IssuedInvitation
    {
        InvitationArguments::subject($actorSubject);
        InvitationArguments::id($invitationId);

        return $this->run('resend', $actorSubject, null, $invitationId, function () use ($invitationId): IssuedInvitation {
            $invitation = $this->find($invitationId);
            if ($invitation['status'] !== 'pending') {
                throw ApplicationInvitationException::for(ApplicationInvitationError::InvitationNotPending);
            }
            $this->invitations[$invitationId]['expires_at'] = self::expiry();
            $this->invitations[$invitationId]['link'] = $this->link($invitationId);

            return $this->issued($invitationId);
        });
    }

    public function revoke(string $actorSubject, int $invitationId): RevokedInvitation
    {
        InvitationArguments::subject($actorSubject);
        InvitationArguments::id($invitationId);

        return $this->run('revoke', $actorSubject, null, $invitationId, function () use ($invitationId): RevokedInvitation {
            if ($this->find($invitationId)['status'] === 'accepted') {
                throw ApplicationInvitationException::for(ApplicationInvitationError::InvitationAccepted);
            }
            $this->invitations[$invitationId]['status'] = 'revoked';

            return new RevokedInvitation($invitationId, 'revoked');
        });
    }

    /**
     * Answer the next call of an operation with this result instead of the in-memory provider.
     *
     * @param  'create'|'resend'|'revoke'  $operation
     */
    public function respondNext(string $operation, IssuedInvitation|RevokedInvitation $result): self
    {
        if (($operation === 'revoke') !== ($result instanceof RevokedInvitation)) {
            throw new \InvalidArgumentException('Create and resend answer an IssuedInvitation; revoke answers a RevokedInvitation.');
        }

        return $this->script($operation, $result);
    }

    /**
     * Refuse the next call of an operation, with the exception the provider client throws for the
     * reason (the same class, code and status), or with this exception.
     *
     * @param  'create'|'resend'|'revoke'  $operation
     * @param  'application'|'actor'|'recipient'|null  $limit  for {@see ApplicationInvitationError::RateLimited}
     * @param  array<string, list<string>>  $errors  for {@see ApplicationInvitationError::InvalidRequest}
     */
    public function refuseNext(
        string $operation,
        ApplicationInvitationError|ApplicationInvitationException $error,
        ?int $retryAfter = null,
        ?string $limit = null,
        array $errors = [],
    ): self {
        return $this->script($operation, $error instanceof ApplicationInvitationException
            ? $error
            : ApplicationInvitationException::for($error, retryAfter: $retryAfter, limit: $limit, errors: $errors));
    }

    /** The recipient accepted: resend and revoke now refuse it, as the provider does. */
    public function accept(int $invitationId): self
    {
        $this->find($invitationId);
        $this->invitations[$invitationId]['status'] = 'accepted';

        return $this;
    }

    /**
     * Every call that reached the fake provider, in order, with what it answered or the reason it
     * was refused.
     *
     * @return list<array{operation: 'create'|'resend'|'revoke', actor: string, email: string|null, invitation_id: int|null, result: IssuedInvitation|RevokedInvitation|null, error: ApplicationInvitationError|null}>
     */
    public function calls(?string $operation = null): array
    {
        return $operation === null ? $this->calls
            : array_values(array_filter($this->calls, fn (array $call): bool => $call['operation'] === $operation));
    }

    /**
     * The fake provider's view of an invitation, or null for an id it never created.
     *
     * @return array{id: int, email: string, status: 'pending'|'expired'|'revoked'|'accepted', expires_at: DateTimeImmutable, link: string}|null
     */
    public function invitation(int $invitationId): ?array
    {
        if (! isset($this->invitations[$invitationId])) {
            return null;
        }
        $invitation = $this->invitations[$invitationId];

        return ['id' => $invitationId, 'email' => $invitation['email'], 'status' => self::status($invitation),
            'expires_at' => $invitation['expires_at'], 'link' => $invitation['link']];
    }

    /** An invitation was created for this address (exactly as passed), by this actor when given. */
    public function assertCreated(string $email, ?string $actor = null): void
    {
        Assert::assertNotEmpty(array_filter($this->calls('create'), fn (array $call): bool => $call['email'] === $email
            && ($actor === null || $call['actor'] === $actor) && $call['error'] === null),
            'No invitation was created for the address'.($actor === null ? '' : ' by that actor').'.');
    }

    public function assertNotCreated(?string $email = null): void
    {
        Assert::assertEmpty(array_filter($this->calls('create'), fn (array $call): bool => ($email === null || $call['email'] === $email) && $call['error'] === null),
            'An invitation was created.');
    }

    public function assertResent(int $invitationId, ?string $actor = null): void
    {
        $this->assertCalled('resend', $invitationId, $actor);
    }

    public function assertRevoked(int $invitationId, ?string $actor = null): void
    {
        $this->assertCalled('revoke', $invitationId, $actor);
    }

    /** No call of any operation reached the fake provider. */
    public function assertNothingRequested(): void
    {
        Assert::assertSame([], $this->calls, 'Invitation calls were made.');
    }

    public function assertRequestCount(int $count, ?string $operation = null): void
    {
        Assert::assertCount($count, $this->calls($operation));
    }

    private function assertCalled(string $operation, int $invitationId, ?string $actor): void
    {
        Assert::assertNotEmpty(array_filter($this->calls($operation), fn (array $call): bool => $call['invitation_id'] === $invitationId
            && ($actor === null || $call['actor'] === $actor) && $call['error'] === null),
            "Invitation {$invitationId} was not {$operation}".($operation === 'resend' ? '' : 'd').' successfully.');
    }

    /**
     * @template T of IssuedInvitation|RevokedInvitation
     *
     * @param  \Closure(): T  $provider
     * @return T
     */
    private function run(string $operation, string $actor, ?string $email, ?int $id, \Closure $provider): IssuedInvitation|RevokedInvitation
    {
        $call = ['operation' => $operation, 'actor' => $actor, 'email' => $email, 'invitation_id' => $id, 'result' => null, 'error' => null];
        try {
            $next = array_shift($this->scripted[$operation]);
            if ($next instanceof ApplicationInvitationException) {
                throw $next;
            }
            $call['result'] = $next ?? $provider();

            return $call['result'];
        } catch (ApplicationInvitationException $refused) {
            $call['error'] = $refused->error;

            throw $refused;
        } finally {
            $this->calls[] = $call;
        }
    }

    private function script(string $operation, IssuedInvitation|RevokedInvitation|ApplicationInvitationException $outcome): self
    {
        if (! in_array($operation, self::OPERATIONS, true)) {
            throw new \InvalidArgumentException('The operation must be create, resend or revoke.');
        }
        $this->scripted[$operation][] = $outcome;

        return $this;
    }

    /** @return array{email: string, status: 'pending'|'revoked'|'accepted', expires_at: DateTimeImmutable, link: string} */
    private function find(int $id): array
    {
        return $this->invitations[$id] ?? throw ApplicationInvitationException::for(ApplicationInvitationError::InvitationNotFound);
    }

    private function issued(int $id): IssuedInvitation
    {
        $invitation = $this->invitations[$id];

        return new IssuedInvitation($id, 'pending', $invitation['expires_at'], $invitation['link'], true);
    }

    private function link(int $id): string
    {
        return self::LINK_BASE.'fake-'.$id.'-'.(++$this->tokens);
    }

    /** @param  array{status: string, expires_at: DateTimeImmutable}  $invitation */
    private static function status(array $invitation): string
    {
        return $invitation['status'] === 'pending' && $invitation['expires_at'] <= self::now() ? 'expired' : $invitation['status'];
    }

    private static function expiry(): DateTimeImmutable
    {
        return self::now()->modify('+7 days');
    }

    private static function now(): DateTimeImmutable
    {
        return new DateTimeImmutable('@'.Date::now()->getTimestamp(), new DateTimeZone('UTC'));
    }
}
