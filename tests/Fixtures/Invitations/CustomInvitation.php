<?php

namespace BWH\Auth\Tests\Fixtures\Invitations;

use BWH\Auth\Invitations\HasInvitationLifecycle;
use BWH\Auth\Invitations\HasInvitationSecret;
use BWH\Auth\Invitations\InvitationDigest;
use Illuminate\Database\Eloquent\Model;

/** A binary digest in a renamed column, renamed timestamps and no way to decline. */
class CustomInvitation extends Model
{
    use HasInvitationLifecycle, HasInvitationSecret;

    protected $table = 'custom_invitations';

    protected $guarded = [];

    protected function invitationSecretColumn(): string
    {
        return 'secret_digest';
    }

    protected function invitationSecretDigest(): InvitationDigest
    {
        return InvitationDigest::Binary;
    }

    protected function invitationLifecycleColumns(): array
    {
        return ['accepted' => 'redeemed_at', 'declined' => null, 'revoked' => 'withdrawn_at', 'expires' => 'lapses_at'];
    }

    protected function casts(): array
    {
        return ['redeemed_at' => 'immutable_datetime', 'withdrawn_at' => 'immutable_datetime', 'lapses_at' => 'immutable_datetime'];
    }
}
