<?php

use BWH\Auth\Database\OAuthIdentityColumns;
use Illuminate\Database\Migrations\Migration;

/**
 * Bind accounts to the identity provider by subject: `oauth_provider` and `oauth_subject`,
 * nullable, with a composite unique index, compared exactly (VARBINARY on MySQL and MariaDB).
 *
 * Safe whether or not the columns already exist: an application that added them itself only
 * has them made case-sensitive. Safe against the previous release, so a code rollback needs
 * no schema rollback.
 */
return new class extends Migration
{
    public function up(): void
    {
        OAuthIdentityColumns::ensure('users');
    }

    /** Leaves the columns in place: they may predate this migration. */
    public function down(): void
    {
        OAuthIdentityColumns::revertCaseSensitivity('users');
    }
};
