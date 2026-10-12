<?php

namespace BWH\Auth\OAuth\Invitations;

use DateTimeImmutable;
use JsonSerializable;
use SensitiveParameter;
use WeakMap;

/**
 * An invitation the provider created or sent again, with its acceptance link.
 *
 * The link is a single-use bearer credential: show it only to the person who asked, never log it,
 * and never return it to automated agents. It is not a property of this object, so no way of
 * turning the object into text or an array (`json_encode`, `print_r`, `var_export`, `serialize`,
 * an array cast, a dumper) discloses it; read it explicitly with {@see link()}. A serialized and
 * restored copy has no link.
 */
final class IssuedInvitation implements JsonSerializable
{
    /** @var WeakMap<object, string>|null links by {@see $key}, outside every object's own state */
    private static ?WeakMap $links = null;

    /** An empty object that names this invitation's link; a clone shares it, a dump shows nothing. */
    private readonly object $key;

    /**
     * @param  int  $id  the provider's invitation id, for resend and revoke
     * @param  string  $status  `pending`
     * @param  DateTimeImmutable  $expiresAt  in UTC
     * @param  bool  $emailSent  whether the provider's email to the address was accepted for delivery
     */
    public function __construct(
        public readonly int $id,
        public readonly string $status,
        public readonly DateTimeImmutable $expiresAt,
        #[SensitiveParameter] string $link,
        public readonly bool $emailSent,
    ) {
        $this->key = new \stdClass;
        self::links()[$this->key] = $link;
    }

    /**
     * The acceptance link.
     *
     * @throws \LogicException for a copy restored from serialization, which carries no link
     */
    public function link(): string
    {
        return self::links()[$this->key] ?? throw new \LogicException('This invitation copy carries no link.');
    }

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

    /** @return WeakMap<object, string> */
    private static function links(): WeakMap
    {
        return self::$links ??= new WeakMap;
    }
}
