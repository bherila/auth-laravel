<?php

namespace BWH\Auth\Tests\Fixtures\Invitations;

use BWH\Auth\Invitations\HasInvitationLifecycle;
use Illuminate\Database\Eloquent\Model;

/** Forgets to cast its timestamps, which the lifecycle refuses rather than misreading. */
class UncastInvitation extends Model
{
    use HasInvitationLifecycle;

    protected $table = 'default_invitations';

    protected $guarded = [];
}
