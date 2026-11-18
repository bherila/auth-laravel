<?php

namespace BWH\Auth\Tests\Fixtures\Invitations;

use BWH\Auth\Invitations\HasInvitationLifecycle;
use BWH\Auth\Invitations\HasInvitationSecret;
use Illuminate\Database\Eloquent\Model;

/** An invitation with every default: hex `token_hash` and the four standard timestamps. */
class DefaultInvitation extends Model
{
    use HasInvitationLifecycle, HasInvitationSecret;

    protected $table = 'default_invitations';

    protected $guarded = [];

    protected function casts(): array
    {
        return [
            'accepted_at' => 'datetime',
            'declined_at' => 'datetime',
            'revoked_at' => 'datetime',
            'expires_at' => 'datetime',
        ];
    }
}
