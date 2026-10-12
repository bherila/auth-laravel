<?php

namespace BWH\Auth\OAuth\Invitations;

use SensitiveParameter;

/**
 * The checks every {@see ApplicationInvitations} implementation makes before anything is sent, so
 * the provider client and the test fake refuse the same arguments in the same way.
 *
 * @internal
 */
final class InvitationArguments
{
    /** The provider's subject form: a decimal string with no leading zeros. */
    private const SUBJECT = '/^[1-9][0-9]{0,19}$/D';

    public const MAX_EMAIL_LENGTH = 255;

    /** @throws \InvalidArgumentException */
    public static function subject(string $subject): void
    {
        if (preg_match(self::SUBJECT, $subject) !== 1) {
            throw new \InvalidArgumentException('The actor subject must be a provider subject: a decimal string with no leading zeros.');
        }
    }

    /** @throws \InvalidArgumentException */
    public static function id(int $id): void
    {
        if ($id < 1) {
            throw new \InvalidArgumentException('The invitation id must be a positive integer.');
        }
    }

    /**
     * An address that can be sent at all: the provider decides whether it is valid.
     *
     * @throws ApplicationInvitationInvalid with no provider status
     */
    public static function email(#[SensitiveParameter] string $email): void
    {
        if ($email === '' || ! mb_check_encoding($email, 'UTF-8') || mb_strlen($email) > self::MAX_EMAIL_LENGTH) {
            throw new ApplicationInvitationInvalid(ApplicationInvitationError::InvalidRequest,
                errors: ['email' => ['The email must be a valid address of at most '.self::MAX_EMAIL_LENGTH.' characters.']]);
        }
    }
}
