<?php

namespace BWH\Auth\Tests\Feature;

use BWH\Auth\AuthServiceProvider;
use BWH\Auth\OAuth\Lifecycle\IdentityTombstoneCursorStore;
use BWH\Auth\Tests\TestCase;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\ServiceProvider;

class IdentityTombstoneCursorStoreTest extends TestCase
{
    private const MIGRATION = __DIR__.'/../../database/identity-tombstone-migrations/2026_10_10_100000_create_identity_tombstone_cursors.php';

    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);

        $app['config']->set('database.connections.lifecycle', ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '']);
        $app['config']->set('bherila-auth.identity_tombstones.connection', 'lifecycle');
    }

    private function store(): IdentityTombstoneCursorStore
    {
        return $this->app->make(IdentityTombstoneCursorStore::class);
    }

    public function test_the_migration_creates_the_table_on_the_configured_connection_once_and_keeps_it_on_rollback(): void
    {
        $migration = require self::MIGRATION;
        $this->assertFalse($this->store()->installed());

        $migration->up();
        $this->assertTrue(Schema::connection('lifecycle')->hasTable(IdentityTombstoneCursorStore::DEFAULT_TABLE));
        $this->assertFalse(Schema::connection('testing')->hasTable(IdentityTombstoneCursorStore::DEFAULT_TABLE), 'The default connection is left alone');
        $this->assertTrue($this->store()->installed());

        $owner = $this->store()->acquire('context-a');
        $this->store()->advance('context-a', $owner, 'kept');

        $migration->up();
        $migration->down();
        $this->assertSame('kept', $this->store()->cursor('context-a'), 'Running it again, or rolling back, keeps the data');
    }

    public function test_the_retry_migration_creates_its_table_on_the_configured_connection_once_and_keeps_it(): void
    {
        $migration = require dirname(self::MIGRATION).'/2026_10_10_110000_create_identity_tombstone_retries.php';
        $retries = $this->app->make(\BWH\Auth\OAuth\Lifecycle\IdentityTombstoneRetryStore::class);
        $this->assertFalse($retries->installed());

        $migration->up();
        $this->assertTrue(Schema::connection('lifecycle')->hasTable(\BWH\Auth\OAuth\Lifecycle\IdentityTombstoneRetryStore::DEFAULT_TABLE));
        $this->assertFalse(Schema::connection('testing')->hasTable(\BWH\Auth\OAuth\Lifecycle\IdentityTombstoneRetryStore::DEFAULT_TABLE));
        $at = new \DateTimeImmutable('2026-08-26T12:00:00Z');
        $retries->record('context-a', new \BWH\Auth\OAuth\Lifecycle\IdentityTombstone('648B1F85-9192-4EB2-943D-734C5F5FD817', 'example-provider', '42', $at, $at->modify('+30 days'), null));
        $retries->record('context-a', new \BWH\Auth\OAuth\Lifecycle\IdentityTombstone('648b1f85-9192-4eb2-943d-734c5f5fd817', 'example-provider', '42', $at, $at->modify('+30 days'), null));

        $migration->up();
        $migration->down();
        $this->assertSame(2, $retries->attempts('context-a', '648b1f85-9192-4eb2-943d-734c5f5fd817'), 'One row per tombstone, whatever its case; kept through a re-run and rollback');
        $this->assertSame('42', $retries->due('context-a', 10)[0]->subject);
        $this->assertSame([], $retries->due('context-b', 10));
    }

    public function test_the_migration_honours_a_configured_table_name(): void
    {
        config(['bherila-auth.identity_tombstones.table' => 'tombstone_cursors']);

        (require self::MIGRATION)->up();

        $this->assertTrue(Schema::connection('lifecycle')->hasTable('tombstone_cursors'));
        $this->assertTrue($this->store()->installed());
    }

    public function test_the_migration_is_published_in_its_own_group(): void
    {
        $paths = ServiceProvider::pathsToPublish(AuthServiceProvider::class, 'bherila-auth-identity-tombstone-migrations');

        $this->assertCount(1, $paths);
        $this->assertSame(realpath(dirname(self::MIGRATION)), realpath(array_key_first($paths)));
        $this->assertArrayNotHasKey(array_key_first($paths), ServiceProvider::pathsToPublish(AuthServiceProvider::class, 'bherila-auth-migrations'));
    }

    public function test_one_run_holds_the_lease_until_it_releases_or_it_lapses(): void
    {
        (require self::MIGRATION)->up();
        $store = $this->store();

        $first = $store->acquire('context-a');
        $this->assertIsString($first);
        $this->assertNull($store->acquire('context-a'), 'A second run is refused while the first holds the lease');
        $this->assertIsString($other = $store->acquire('context-b'), 'Another client context has its own lease');
        $this->assertTrue($store->renew('context-a', $first));

        $this->travel(IdentityTombstoneCursorStore::DEFAULT_LEASE_SECONDS - 1)->seconds();
        $this->assertNull($store->acquire('context-a'), 'The lease holds until it lapses');
        $this->travel(2)->seconds();

        $second = $store->acquire('context-a');
        $this->assertIsString($second, 'A lapsed lease passes to the next run');
        $this->assertFalse($store->renew('context-a', $first));
        $this->assertFalse($store->advance('context-a', $first, 'stale'), 'The run that lost the lease cannot move the cursor');
        $this->assertNull($store->cursor('context-a'));

        $store->release('context-a', $first);
        $this->assertNull($store->acquire('context-a'), 'Releasing a lost lease does not release the successor');
        $store->release('context-a', $second);
        $this->assertIsString($store->acquire('context-a'));
        $store->release('context-b', $other);
    }

    public function test_lease_and_cursor_reads_use_the_writer_on_a_read_write_split(): void
    {
        // Two files stand in for a primary and a replica that has not caught up: the replica has
        // the table but none of the rows this run writes.
        $primary = tempnam(sys_get_temp_dir(), 'tombstone-primary');
        $replica = tempnam(sys_get_temp_dir(), 'tombstone-replica');
        try {
            config(['database.connections.split' => [
                'driver' => 'sqlite', 'prefix' => '', 'foreign_key_constraints' => false,
                'read' => ['database' => $replica], 'write' => ['database' => $primary],
            ]]);
            config(['bherila-auth.identity_tombstones.connection' => 'split']);
            (require self::MIGRATION)->up();
            config(['database.connections.replica' => ['driver' => 'sqlite', 'prefix' => '', 'database' => $replica]]);
            config(['bherila-auth.identity_tombstones.connection' => 'replica']);
            (require self::MIGRATION)->up();
            config(['bherila-auth.identity_tombstones.connection' => 'split']);
            $store = $this->store();

            $owner = $store->acquire('context-a');
            $this->assertIsString($owner);
            $this->assertTrue($store->renew('context-a', $owner), 'A lagging replica must not look like a lost lease');
            $this->assertTrue($store->advance('context-a', $owner, 'cursor-a'));
            $this->assertSame('cursor-a', $store->cursor('context-a'), 'The cursor is the one this run wrote');
            $this->assertSame(0, \Illuminate\Support\Facades\DB::connection('replica')->table(IdentityTombstoneCursorStore::DEFAULT_TABLE)->count(), 'The replica really is behind');
        } finally {
            \Illuminate\Support\Facades\DB::purge('split');
            \Illuminate\Support\Facades\DB::purge('replica');
            @unlink($primary);
            @unlink($replica);
        }
    }

    public function test_the_lease_length_is_configurable_with_a_floor(): void
    {
        (require self::MIGRATION)->up();
        $store = $this->store();

        config(['bherila-auth.identity_tombstones.lease_seconds' => 1800]);
        $store->acquire('context-a');
        $this->travel(1000)->seconds();
        $this->assertNull($store->acquire('context-a'), 'A longer lease holds past the default');
        $this->travel(801)->seconds();
        $this->assertIsString($store->acquire('context-b'));
        $this->assertIsString($store->acquire('context-a'));

        config(['bherila-auth.identity_tombstones.lease_seconds' => 5]);
        $this->assertSame(IdentityTombstoneCursorStore::MIN_LEASE_SECONDS, IdentityTombstoneCursorStore::leaseSeconds());
        $store->acquire('context-c');
        $this->travel(30)->seconds();
        $this->assertNull($store->acquire('context-c'), 'Never shorter than the floor');
    }

    public function test_ensure_renews_only_when_less_than_the_budget_remains(): void
    {
        (require self::MIGRATION)->up();
        config(['bherila-auth.identity_tombstones.lease_seconds' => 100]);
        $store = $this->store();
        $owner = $store->acquire('context-a');
        $expiry = fn () => (int) \Illuminate\Support\Facades\DB::connection('lifecycle')->table(IdentityTombstoneCursorStore::DEFAULT_TABLE)->value('lease_expires_at');
        $first = $expiry();

        $this->travel(40)->seconds();
        $this->assertTrue($store->ensure('context-a', $owner, 50));
        $this->assertSame($first, $expiry(), '60 seconds remain, enough for a 50-second budget');

        $this->travel(20)->seconds();
        $this->assertTrue($store->ensure('context-a', $owner, 50));
        $this->assertSame($first + 60, $expiry(), '40 seconds remained, so the lease was renewed');

        $this->assertFalse($store->ensure('context-a', 'someone-else', 50));
    }

    public function test_cursors_are_kept_per_context_and_can_be_cleared(): void
    {
        (require self::MIGRATION)->up();
        $store = $this->store();
        $a = $store->acquire('context-a');
        $b = $store->acquire('context-b');

        $this->assertTrue($store->advance('context-a', $a, 'cursor-a'));
        $this->assertTrue($store->advance('context-a', $a, 'cursor-a'), 'Storing the same cursor again still reports the lease held');
        $this->assertSame('cursor-a', $store->cursor('context-a'));
        $this->assertNull($store->cursor('context-b'));

        $this->assertTrue($store->advance('context-a', $a, null));
        $this->assertNull($store->cursor('context-a'));
        $store->release('context-b', $b);
    }
}
