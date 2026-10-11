<?php

namespace BWH\Auth\Tests\Feature;

use BWH\Auth\Tests\TestCase;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

final class OAuthRefreshTokenClientMigrationTest extends TestCase
{
    public function test_an_application_without_passport_tables_is_unchanged(): void
    {
        $this->migration()->up();

        $this->assertFalse(Schema::hasTable('oauth_refresh_tokens'));
    }

    public function test_the_column_is_added_and_linked_rows_are_backfilled_without_guessing_orphans(): void
    {
        $this->tables();
        DB::table('oauth_access_tokens')->insert([
            ['id' => 'test-access-a', 'client_id' => 'test-client-a'],
            ['id' => 'test-access-b', 'client_id' => 'test-client-b'],
        ]);
        DB::table('oauth_refresh_tokens')->insert([
            ['id' => 'test-refresh-a', 'access_token_id' => 'test-access-a', 'revoked' => false],
            ['id' => 'test-refresh-b', 'access_token_id' => 'test-access-b', 'revoked' => true],
            ['id' => 'test-orphan', 'access_token_id' => 'test-purged-access', 'revoked' => false],
        ]);
        $migration = $this->migration();
        $migration->up();

        $this->assertSame([
            'test-orphan' => null, 'test-refresh-a' => 'test-client-a', 'test-refresh-b' => 'test-client-b',
        ], DB::table('oauth_refresh_tokens')->orderBy('id')->pluck('client_id', 'id')->all());
        $before = DB::table('oauth_refresh_tokens')->orderBy('id')->get()->all();
        $migration->up();
        $migration->down();
        $this->assertEquals($before, DB::table('oauth_refresh_tokens')->orderBy('id')->get()->all());
        $this->assertTrue(Schema::hasIndex('oauth_refresh_tokens', ['client_id']));
    }

    public function test_an_application_owned_column_and_non_null_association_are_preserved(): void
    {
        $this->tables(hasClientColumn: true);
        DB::table('oauth_access_tokens')->insert(['id' => 'test-access', 'client_id' => 'test-client']);
        DB::table('oauth_refresh_tokens')->insert([
            ['id' => 'test-owned', 'access_token_id' => 'test-access', 'client_id' => 'test-owned-client'],
            ['id' => 'test-null', 'access_token_id' => 'test-access', 'client_id' => null],
        ]);
        $migration = $this->migration();
        $migration->up();
        $migration->down();

        $this->assertSame(['test-null' => 'test-client', 'test-owned' => 'test-owned-client'], DB::table('oauth_refresh_tokens')->orderBy('id')->pluck('client_id', 'id')->all());
        $this->assertFalse(Schema::hasIndex('oauth_refresh_tokens', ['client_id']), 'An application-owned column is not altered');
    }

    public function test_the_passport_connection_and_its_table_prefix_are_used(): void
    {
        config([
            'database.connections.test_passport' => ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => 'test_'],
            'passport.connection' => 'test_passport',
        ]);
        $this->tables(connection: 'test_passport');
        $connection = DB::connection('test_passport');
        $connection->table('oauth_access_tokens')->insert(['id' => 'test-access', 'client_id' => 'test-client']);
        $connection->table('oauth_refresh_tokens')->insert(['id' => 'test-refresh', 'access_token_id' => 'test-access']);

        $this->migration()->up();

        $this->assertSame('test-client', $connection->table('oauth_refresh_tokens')->value('client_id'));
        $this->assertFalse(Schema::hasTable('oauth_refresh_tokens'), 'The default application connection is unchanged');
    }

    public function test_a_refresh_table_without_an_access_table_still_gets_the_column(): void
    {
        $this->tables();
        Schema::drop('oauth_access_tokens');

        $this->migration()->up();

        $this->assertTrue(Schema::hasColumn('oauth_refresh_tokens', 'client_id'));
    }

    private function tables(bool $hasClientColumn = false, ?string $connection = null): void
    {
        $schema = DB::connection($connection)->getSchemaBuilder();
        $schema->create('oauth_access_tokens', static function (Blueprint $table): void {
            $table->string('id')->primary();
            $table->string('client_id')->nullable();
        });
        $schema->create('oauth_refresh_tokens', static function (Blueprint $table) use ($hasClientColumn): void {
            $table->string('id')->primary();
            $table->string('access_token_id');
            $table->boolean('revoked')->default(false);
            if ($hasClientColumn) {
                $table->string('client_id')->nullable();
            }
        });
    }

    private function migration(): Migration
    {
        return require __DIR__.'/../../database/migrations/2026_10_11_120000_add_client_id_to_oauth_refresh_tokens.php';
    }
}
