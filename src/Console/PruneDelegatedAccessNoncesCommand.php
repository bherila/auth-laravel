<?php

namespace BWH\Auth\Console;

use BWH\Auth\OAuth\DelegatedAccess\DatabaseNonceStore;
use BWH\Auth\OAuth\DelegatedAccess\DatabaseReceiptStore;
use BWH\Auth\OAuth\DelegatedAccess\NonceStore;
use Illuminate\Console\Command;

class PruneDelegatedAccessNoncesCommand extends Command
{
    protected $signature = 'bherila-auth:prune-delegated-nonces';

    protected $description = 'Delete expired delegated access nonces and operation receipts older than 30 days. Never deletes a nonce that could still be replayed.';

    public function handle(NonceStore $nonces, DatabaseReceiptStore $receipts): int
    {
        if ($nonces instanceof DatabaseNonceStore) {
            $count = $nonces->pruneExpired();
            $this->info("Pruned {$count} expired delegated access nonce(s).");
        } else {
            $this->info('The bound nonce store is not the database store; nothing to prune.');
        }

        // Receipts exist only where the receipts migration is installed; nonce pruning never depends on it.
        if (! $receipts->installed()) {
            $this->info('The delegated access receipts table is not installed; no receipts to prune.');

            return self::SUCCESS;
        }

        $count = $receipts->pruneExpired();
        $this->info("Pruned {$count} delegated access receipt(s) older than ".DatabaseReceiptStore::RETENTION_DAYS.' days.');

        return self::SUCCESS;
    }
}
