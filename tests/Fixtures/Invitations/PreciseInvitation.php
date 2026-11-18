<?php

namespace BWH\Auth\Tests\Fixtures\Invitations;

/** Stores its timestamps with microseconds. */
class PreciseInvitation extends DefaultInvitation
{
    protected $dateFormat = 'Y-m-d H:i:s.u';
}
