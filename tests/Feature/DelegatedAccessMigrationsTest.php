<?php

namespace BWH\Auth\Tests\Feature;

use BWH\Auth\OAuth\DelegatedAccess\DatabaseNonceStore;
use BWH\Auth\OAuth\DelegatedAccess\DatabaseReceiptStore;
use BWH\Auth\Tests\TestCase;
use Illuminate\Support\Facades\Schema;

/**
 * The delegated access migrations create their tables where the stores look for them.
 */
class DelegatedAccessMigrationsTest extends TestCase
{
    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);

        $app['config']->set('database.connections.receipts', ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '']);
        $app['config']->set('bherila-auth.delegated_access.receipt_connection', 'receipts');
        $app['config']->set('database.connections.nonces', ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '']);
        $app['config']->set('bherila-auth.delegated_access.nonce_connection', 'nonces');
    }

    public function test_the_nonces_table_is_created_only_on_the_nonce_connection(): void
    {
        $migration = require __DIR__.'/../../database/delegated-access-migrations/2026_09_07_000000_create_delegated_access_nonces.php';

        $migration->up();

        $this->assertTrue(Schema::connection('nonces')->hasTable(DatabaseNonceStore::TABLE));
        $this->assertSame(['key', 'expires_at'], Schema::connection('nonces')->getColumnListing(DatabaseNonceStore::TABLE));
        $this->assertFalse(Schema::connection('testing')->hasTable(DatabaseNonceStore::TABLE));

        $migration->up();
        $migration->down();
        $this->assertTrue(Schema::connection('nonces')->hasTable(DatabaseNonceStore::TABLE), 'Rerunning or rolling back retains consumed nonces');
    }

    public function test_a_default_connection_table_does_not_skip_the_nonce_connection(): void
    {
        Schema::connection('testing')->create(DatabaseNonceStore::TABLE, static function ($table): void {
            $table->string('application_owned');
        });
        $migration = require __DIR__.'/../../database/delegated-access-migrations/2026_09_07_000000_create_delegated_access_nonces.php';

        $migration->up();

        $this->assertTrue(Schema::connection('nonces')->hasTable(DatabaseNonceStore::TABLE));
        $this->assertSame(['application_owned'], Schema::connection('testing')->getColumnListing(DatabaseNonceStore::TABLE));
    }

    public function test_the_receipts_table_is_created_on_the_receipt_connection(): void
    {
        // The default connection already has one, which must not stop the receipt connection getting its own.
        $migration = require __DIR__.'/../../database/delegated-access-migrations/2026_10_10_000000_create_delegated_access_receipts.php';
        Schema::connection('testing')->create(DatabaseReceiptStore::TABLE, static function ($table): void {
            $table->string('application');
        });

        $migration->up();

        $this->assertTrue(Schema::connection('receipts')->hasTable(DatabaseReceiptStore::TABLE));
        $this->assertTrue($this->app->make(DatabaseReceiptStore::class)->installed());
        $this->assertSame(['application'], Schema::connection('testing')->getColumnListing(DatabaseReceiptStore::TABLE), 'The default connection is left alone');

        $migration->up();
        $this->assertTrue(Schema::connection('receipts')->hasTable(DatabaseReceiptStore::TABLE), 'Running it again changes nothing');
    }
}
