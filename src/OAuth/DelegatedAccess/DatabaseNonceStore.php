<?php

namespace BWH\Auth\OAuth\DelegatedAccess;

use Illuminate\Database\ConnectionInterface;
use Illuminate\Database\UniqueConstraintViolationException;

/** Dedicated relational storage, outside application cache and business transactions. */
final readonly class DatabaseNonceStore implements NonceStore
{
    public const TABLE = 'bherila_auth_delegated_nonces';

    public function __construct(private ConnectionInterface $connection) {}

    public function consume(string $key, int $seconds): bool
    {
        $this->requireDurableConnection();
        $now = time();
        if (preg_match('/^[a-f0-9]{64}$/D', $key) !== 1 || $seconds < 1 || $seconds > PHP_INT_MAX - $now) {
            throw new DelegatedAccessException('replay_storage_unavailable');
        }
        $this->connection->table(self::TABLE)->where('key', $key)->where('expires_at', '<=', $now)->delete();
        try {
            return $this->connection->table(self::TABLE)->insert(['key' => $key, 'expires_at' => $now + $seconds]);
        } catch (UniqueConstraintViolationException) {
            return false;
        }
    }

    /** Optional scheduled maintenance; never deletes an unexpired consumed nonce. */
    public function pruneExpired(): int
    {
        $this->requireDurableConnection();

        return $this->connection->table(self::TABLE)->where('expires_at', '<=', time())->delete();
    }

    private function requireDurableConnection(): void
    {
        $driver = $this->connection->getConfig('driver');
        $database = $this->connection->getConfig('database');
        if ($this->connection->transactionLevel() !== 0
            || ! in_array($driver, ['mysql', 'mariadb', 'pgsql', 'sqlsrv', 'sqlite'], true)
            || ($driver === 'sqlite' && (! is_string($database) || ! is_file($database)))) {
            throw new DelegatedAccessException('replay_storage_unavailable');
        }
    }
}
