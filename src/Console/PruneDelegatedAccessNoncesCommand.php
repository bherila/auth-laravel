<?php

namespace BWH\Auth\Console;

use BWH\Auth\OAuth\DelegatedAccess\DatabaseNonceStore;
use BWH\Auth\OAuth\DelegatedAccess\NonceStore;
use Illuminate\Console\Command;

class PruneDelegatedAccessNoncesCommand extends Command
{
    protected $signature = 'bherila-auth:prune-delegated-nonces';

    protected $description = 'Delete expired delegated access nonces. Never deletes one that could still be replayed.';

    public function handle(NonceStore $nonces): int
    {
        if (! $nonces instanceof DatabaseNonceStore) {
            $this->info('The bound nonce store is not the database store; nothing to prune.');

            return self::SUCCESS;
        }

        $count = $nonces->pruneExpired();
        $this->info("Pruned {$count} expired delegated access nonce(s).");

        return self::SUCCESS;
    }
}
