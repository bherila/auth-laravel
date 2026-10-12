<?php

namespace BWH\Auth\OAuth\Invitations;

use SensitiveParameter;

/**
 * The request is not valid (`invalid_request`): the address was refused, here before sending
 * ({@see $status} null) or by the provider (422).
 */
final class ApplicationInvitationInvalid extends ApplicationInvitationException
{
    /**
     * @param  array<string, list<string>>  $errors  messages by field; they never repeat the address
     */
    public function __construct(
        ApplicationInvitationError $error,
        ?int $status = null,
        ?int $retryAfter = null,
        #[SensitiveParameter] public readonly array $errors = [],
    ) {
        parent::__construct($error, $status, $retryAfter);
    }
}
