<?php

namespace BWH\Auth\Tests\Fixtures;

use Illuminate\Database\Query\Builder;
use Illuminate\Database\Query\Grammars\SQLiteGrammar;
use RuntimeException;

/**
 * SQLite that answers to `sqlsrv` and, like SQL Server's grammar, cannot insert while ignoring
 * errors; with PostgreSQL-style aborted transactions from its parent, so a duplicate-key error
 * outside a savepoint would poison a surrounding transaction.
 */
final class SqlServerLikeSqliteConnection extends TransactionAbortingSqliteConnection
{
    public function getDriverName()
    {
        return 'sqlsrv';
    }

    protected function getDefaultQueryGrammar()
    {
        return new class($this) extends SQLiteGrammar
        {
            /** @param  array<int|string, mixed>  $values */
            public function compileInsertOrIgnore(Builder $query, array $values)
            {
                throw new RuntimeException('This database engine does not support inserting while ignoring errors.');
            }
        };
    }
}
