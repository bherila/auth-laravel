<?php

namespace BWH\Auth\Invitations;

/**
 * How an invitation secret's SHA-256 digest is stored. Pick the one the column already holds:
 * changing it would orphan every invitation already sent.
 */
enum InvitationDigest
{
    /** 64 lowercase hex characters, for a `CHAR(64)`/`VARCHAR` column. */
    case Hex;

    /** The 32 raw bytes, for a `BINARY(32)`/`VARBINARY` column. */
    case Binary;
}
