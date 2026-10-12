<?php

namespace BWH\Auth\OAuth\Invitations;

/** An invitation the provider has revoked; revoking it again answers the same. */
final readonly class RevokedInvitation
{
    /** @param  string  $status  `revoked` */
    public function __construct(
        public int $id,
        public string $status,
    ) {}
}
