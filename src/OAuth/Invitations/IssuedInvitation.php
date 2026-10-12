<?php

namespace BWH\Auth\OAuth\Invitations;

use DateTimeImmutable;
use JsonSerializable;
use SensitiveParameter;

/**
 * An invitation the provider created or sent again, with its acceptance link.
 *
 * The link is a single-use bearer credential: show it only to the person who asked, never log it,
 * and never return it to automated agents. It is left out of {@see jsonSerialize()} and of debug
 * output, so serializing this object or dumping it never discloses it; read {@see $link} explicitly.
 */
final readonly class IssuedInvitation implements JsonSerializable
{
    /**
     * @param  int  $id  the provider's invitation id, for resend and revoke
     * @param  string  $status  `pending`
     * @param  DateTimeImmutable  $expiresAt  in UTC
     * @param  bool  $emailSent  whether the provider's email to the address was accepted for delivery
     */
    public function __construct(
        public int $id,
        public string $status,
        public DateTimeImmutable $expiresAt,
        #[SensitiveParameter] public string $link,
        public bool $emailSent,
    ) {}

    /** @return array{id: int, status: string, expires_at: string, email_sent: bool} */
    public function jsonSerialize(): array
    {
        return [
            'id' => $this->id,
            'status' => $this->status,
            'expires_at' => $this->expiresAt->format('Y-m-d\TH:i:s\Z'),
            'email_sent' => $this->emailSent,
        ];
    }

    /** @return array<string, mixed> */
    public function __debugInfo(): array
    {
        return ['id' => $this->id, 'status' => $this->status, 'expiresAt' => $this->expiresAt,
            'link' => '[redacted]', 'emailSent' => $this->emailSent];
    }
}
