<?php

namespace BWH\Auth\OAuth\Session;

use Illuminate\Database\ConnectionInterface;
use Illuminate\Database\DatabaseManager;
use Illuminate\Database\QueryException;
use Illuminate\Support\Carbon;

/**
 * Whether provider lifecycle enforcement is on for this installation.
 *
 * Before cutover it follows `bherila-auth.provider_identity.enabled`, so an application can
 * adopt enforcement gradually and switch it off again. Once the installation records its
 * cutover (`bherila-auth:provider-identity-cutover record`), enforcement stays on even if the
 * setting is later false: an application that relies on the provider to end access must not
 * lose that through a configuration rollback, a redeploy of an older environment file or a
 * recovery that restores stale settings. Only the deliberate `withdraw` action turns it off.
 *
 * Enforcement left on without its other settings (client credentials, shared cache store)
 * fails closed: protected requests are refused as unavailable, never let through.
 *
 * The cutover row is read at most once a minute per process while the setting is off; the
 * setting being on never needs the database. The read never queries the schema catalog.
 */
final class ProviderIdentityEnforcement
{
    public const TABLE = 'provider_identity_cutover';

    private const RECHECK_SECONDS = 60;

    private ?bool $cutOver = null;

    private ?int $checkedAt = null;

    public function __construct(private readonly DatabaseManager $db) {}

    public function enabled(): bool
    {
        return $this->configured() || $this->cutOver();
    }

    /** What the configuration says, ignoring any recorded cutover. */
    public function configured(): bool
    {
        return (bool) config('bherila-auth.provider_identity.enabled', false);
    }

    /** Whether this installation has recorded its cutover and not withdrawn it. */
    public function cutOver(): bool
    {
        $now = Carbon::now()->getTimestamp();
        if ($this->cutOver !== null && $this->checkedAt !== null
            && $this->checkedAt <= $now && $now - $this->checkedAt < self::RECHECK_SECONDS) {
            return $this->cutOver;
        }

        $this->cutOver = $this->read();
        $this->checkedAt = $now;

        return $this->cutOver;
    }

    /** The recorded cutover row, withdrawn or not; null when none was ever recorded. */
    public function record(): ?object
    {
        if (! $this->tableExists()) {
            return null;
        }

        return $this->connection()->table(self::TABLE)->where('id', 1)->first();
    }

    /** Forget the cached answer, after recording or withdrawing a cutover in this process. */
    public function forget(): void
    {
        $this->cutOver = null;
        $this->checkedAt = null;
    }

    public function connection(): ConnectionInterface
    {
        return $this->db->connection(config('bherila-auth.provider_identity.cutover_connection'));
    }

    public function tableExists(): bool
    {
        return $this->connection()->getSchemaBuilder()->hasTable(self::TABLE);
    }

    private function read(): bool
    {
        $connection = $this->connection();
        $query = static fn (): bool => $connection->table(self::TABLE)->where('id', 1)->whereNull('withdrawn_at')->exists();

        try {
            // Inside a transaction, read under a savepoint, so a missing table cannot abort
            // the surrounding transaction (PostgreSQL would refuse every later statement).
            return $connection->transactionLevel() > 0 ? $connection->transaction($query) : $query();
        } catch (QueryException $exception) {
            // Before its migration there can be no cutover. Recognized from the error rather
            // than by asking the schema catalog, which the bearer path never queries. Any
            // other failure propagates rather than switching enforcement off.
            if ($this->missingTable($exception)) {
                return false;
            }

            throw $exception;
        }
    }

    private function missingTable(QueryException $exception): bool
    {
        // MySQL and MariaDB report 42S02, PostgreSQL 42P01; SQLite only says so in its message.
        if (in_array((string) $exception->getCode(), ['42S02', '42P01'], true)) {
            return true;
        }

        return str_contains(strtolower($exception->getMessage()), 'no such table');
    }
}
