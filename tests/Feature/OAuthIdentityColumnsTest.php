<?php

namespace BWH\Auth\Tests\Feature;

use BWH\Auth\Database\OAuthIdentityColumns;
use BWH\Auth\Tests\TestCase;
use Illuminate\Database\QueryException;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

/**
 * The schema helper applications call from their own migrations. The MySQL/MariaDB VARBINARY
 * conversion cannot run on the SQLite the package's suite uses; consumers' MariaDB CI covers it.
 */
class OAuthIdentityColumnsTest extends TestCase
{
    public function test_ensure_adds_the_binding_columns_and_their_unique_index_when_missing(): void
    {
        OAuthIdentityColumns::ensure('users');

        $this->assertTrue(Schema::hasColumns('users', ['oauth_provider', 'oauth_subject']));

        DB::table('users')->insert(['name' => 'A', 'email' => 'a@example.test', 'password' => 'x', 'oauth_provider' => 'p', 'oauth_subject' => 's']);
        $this->expectException(QueryException::class);
        DB::table('users')->insert(['name' => 'B', 'email' => 'b@example.test', 'password' => 'x', 'oauth_provider' => 'p', 'oauth_subject' => 's']);
    }

    public function test_ensure_is_a_no_op_for_a_table_that_already_has_them(): void
    {
        OAuthIdentityColumns::ensure('users');
        OAuthIdentityColumns::ensure('users');

        $this->assertTrue(Schema::hasColumns('users', ['oauth_provider', 'oauth_subject']));
    }

    public function test_ensure_adds_the_unique_index_to_columns_that_lack_it(): void
    {
        Schema::table('users', function (Blueprint $table): void {
            $table->string('oauth_provider', 64)->nullable();
            $table->string('oauth_subject', 191)->nullable();
        });

        OAuthIdentityColumns::ensure('users');

        DB::table('users')->insert(['name' => 'A', 'email' => 'a@example.test', 'password' => 'x', 'oauth_provider' => 'p', 'oauth_subject' => 's']);
        $this->expectException(QueryException::class);
        DB::table('users')->insert(['name' => 'B', 'email' => 'b@example.test', 'password' => 'x', 'oauth_provider' => 'p', 'oauth_subject' => 's']);
    }

    public function test_ensure_refuses_when_existing_bindings_are_already_duplicated(): void
    {
        Schema::table('users', function (Blueprint $table): void {
            $table->string('oauth_provider', 64)->nullable();
            $table->string('oauth_subject', 191)->nullable();
        });
        DB::table('users')->insert(['name' => 'A', 'email' => 'a@example.test', 'password' => 'x', 'oauth_provider' => 'p', 'oauth_subject' => 's']);
        DB::table('users')->insert(['name' => 'B', 'email' => 'b@example.test', 'password' => 'x', 'oauth_provider' => 'p', 'oauth_subject' => 's']);

        $this->expectException(QueryException::class);
        OAuthIdentityColumns::ensure('users');
    }

    public function test_ensure_refuses_a_table_with_only_one_of_the_columns(): void
    {
        Schema::table('users', fn (Blueprint $table) => $table->string('oauth_subject')->nullable());

        $this->expectException(\RuntimeException::class);
        OAuthIdentityColumns::ensure('users');
    }

    public function test_the_configured_column_names_are_used(): void
    {
        config([
            'bherila-auth.provider_identity.binding.provider_column' => 'idp',
            'bherila-auth.provider_identity.binding.subject_column' => 'idp_sub',
        ]);

        OAuthIdentityColumns::ensure('users');

        $this->assertTrue(Schema::hasColumns('users', ['idp', 'idp_sub']));
        $this->assertFalse(Schema::hasColumn('users', 'oauth_subject'));
    }

    public function test_the_published_migration_runs_and_rolls_back_cleanly(): void
    {
        $migration = require __DIR__.'/../../database/oauth-identity-migrations/add_oauth_identity_to_users_table.php.stub';

        $migration->up();
        $this->assertTrue(Schema::hasColumns('users', ['oauth_provider', 'oauth_subject']));

        $migration->down();
        $this->assertTrue(Schema::hasColumns('users', ['oauth_provider', 'oauth_subject']), 'down() leaves columns that may predate it');
    }
}
