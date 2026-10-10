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

        $this->travel(IdentityTombstoneCursorStore::LEASE_SECONDS - 1)->seconds();
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
