<?php

namespace BWH\Auth\Tests\Feature;

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
