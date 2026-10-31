<?php

namespace BWH\Auth\OAuth\Login;

use Symfony\Component\HttpKernel\Exception\ConflictHttpException;

/**
 * A sign-in that cannot be given an account without guessing which one.
 *
 * The person sees one generic sentence. The operator gets the reason and the row ids involved
 * through {@see context()}, never the address or the subject, so a log shipped elsewhere does
 * not carry the identity it is about.
 */
final class AccountConflict extends ConflictHttpException
{
    public const EMAIL_HELD_BY_ANOTHER_ACCOUNT = 'email_held_by_another_account';

    public const CONCURRENT_SIGN_IN_DISAGREES = 'concurrent_sign_in_disagrees';

    /**
     * @param  self::*  $reason
     */
    private function __construct(
        public readonly string $reason,
        public readonly string $provider,
        public readonly int|string|null $subjectBoundTo,
        public readonly int|string|null $emailHeldBy,
    ) {
        parent::__construct('This account could not be linked to the identity provider.');
    }

    public static function emailHeldByAnotherAccount(string $provider, int|string|null $subjectBoundTo, int|string $emailHeldBy): self
    {
        return new self(self::EMAIL_HELD_BY_ANOTHER_ACCOUNT, $provider, $subjectBoundTo, $emailHeldBy);
    }

    public static function concurrentSignInDisagrees(string $provider, int|string|null $subjectBoundTo): self
    {
        return new self(self::CONCURRENT_SIGN_IN_DISAGREES, $provider, $subjectBoundTo, null);
    }

    /** What an operator needs to act on, by row id only. */
    public function explanation(): string
    {
        return match ($this->reason) {
            self::EMAIL_HELD_BY_ANOTHER_ACCOUNT => $this->subjectBoundTo === null
                ? 'A local account that is not linked to this identity already holds its address. If it belongs to the same person, link it with `php artisan oauth:bind-subject`; matching addresses are never adopted automatically.'
                : 'The address the provider now reports already belongs to a different local account, so the linked account was not updated.',
            default => 'A concurrent sign-in for the same identity committed a row with a different profile; neither was adopted.',
        };
    }

    /** @return array<string, int|string|null> */
    public function context(): array
    {
        return [
            'reason' => $this->reason,
            'provider' => $this->provider,
            'subject_bound_to' => $this->subjectBoundTo,
            'email_held_by' => $this->emailHeldBy,
            'explanation' => $this->explanation(),
        ];
    }
}
