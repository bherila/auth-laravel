<?php

namespace BWH\Auth\Tests\Fixtures;

use Closure;
use Illuminate\Database\QueryException;
use Illuminate\Database\SQLiteConnection;
use PDOException;

/**
 * SQLite with PostgreSQL's transaction rule: once a statement fails inside a transaction, every
 * later statement fails until it is rolled back, even when the first failure was caught.
 */
class TransactionAbortingSqliteConnection extends SQLiteConnection
{
    private bool $aborted = false;

    /**
     * @param  string  $query
     * @param  array<int|string, mixed>  $bindings
     */
    protected function runQueryCallback($query, $bindings, Closure $callback)
    {
        if ($this->aborted) {
            throw new QueryException($this->getName() ?? 'aborting', $query, $this->prepareBindings($bindings),
                new PDOException('current transaction is aborted, commands ignored until end of transaction block'));
        }

        try {
            return parent::runQueryCallback($query, $bindings, $callback);
        } catch (QueryException $failure) {
            $this->aborted = $this->transactionLevel() > 0;

            throw $failure;
        }
    }

    public function rollBack($toLevel = null)
    {
        $this->aborted = false;

        parent::rollBack($toLevel);
    }
}
