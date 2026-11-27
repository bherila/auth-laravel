<?php

namespace BWH\Auth\OAuth\Session;

use Illuminate\Database\ConnectionInterface;
use Illuminate\Database\DatabaseManager;
use Illuminate\Database\QueryException;
use Illuminate\Support\Carbon;

/**
 * The provider login generation each remember-me token was issued under.
 *
 * Laravel's remember-me cookie restores a session after the browser session has ended. The
 * restored session holds no provider baseline, so provider lifecycle enforcement would end it
 * at once. A row here records, per session guard and account, the baseline of the login that
 * issued the account's current remember token; restoring from that token adopts it, and the
 * restored session is then checked like any other.
 *
 * Laravel shares one remember token among every device of an account. A baseline is only
 * ever recorded for a token the same login has just made safe to record
 * ({@see ProviderSession::prepareRememberedLogin()}): when the token in hand is not already
 * recorded under exactly the new login's baseline, it is replaced first, so a cookie issued
 * under an earlier generation (before a password reset, say) never comes back under the new
 * one. A token is stored only as its SHA-256 hash.
 *
 * Reads never query the schema catalog. A write asks once per process whether the `epoch`
 * column exists yet (added after the table), so an application that has not run that
 * migration keeps recording baselines without one. Before the table's own migration runs
 * there is no row, so remembered sessions are asked to sign in again, as without this class.
 */
final class RememberedProviderLogins
{
    public const TABLE = 'provider_remembered_logins';

    /** Whether the table has its `epoch` column yet; learnt once per process. */
    private ?bool $epochColumn = null;

    public function __construct(private readonly DatabaseManager $db) {}

    public static function tokenHash(string $token): string
    {
        return hash('sha256', $token);
    }

    /**
     * The row for one guard and account. `epoch` is null when none was recorded, including
     * before the migration that adds the column.
     *
     * @return object{provider: string, subject: string, generation: int|string, epoch: int|string|null, token_hash: string}|null
     */
    public function find(string $guard, string $userId): ?object
    {
        $row = $this->guarded(fn (ConnectionInterface $connection): ?object => $connection->table(self::TABLE)
            ->where('guard', $guard)->where('user_id', $userId)->first());
        if ($row !== null) {
            $row->epoch ??= null;
        }

        return $row;
    }

    public function put(string $guard, string $userId, string $provider, string $subject, int $generation, string $tokenHash, ?int $epoch = null): void
    {
        $this->guarded(function (ConnectionInterface $connection) use ($guard, $userId, $provider, $subject, $generation, $tokenHash, $epoch): null {
            $values = [
                'guard' => $guard,
                'user_id' => $userId,
                'provider' => $provider,
                'subject' => $subject,
                'generation' => $generation,
                'token_hash' => $tokenHash,
                'recorded_at' => Carbon::now(),
            ];
            $update = ['provider', 'subject', 'generation', 'token_hash', 'recorded_at'];
            $this->epochColumn ??= $connection->getSchemaBuilder()->hasColumn(self::TABLE, 'epoch');
            if ($this->epochColumn) {
                $values['epoch'] = $epoch;
                $update[] = 'epoch';
            }
            $connection->table(self::TABLE)->upsert([$values], ['guard', 'user_id'], $update);

            return null;
        });
    }

    /** Remove every row of one account, for example when the account is deleted. */
    public function forgetUser(string $userId): void
    {
        $this->guarded(function (ConnectionInterface $connection) use ($userId): null {
            $connection->table(self::TABLE)->where('user_id', $userId)->delete();

            return null;
        });
    }

    /**
     * @template T
     *
     * @param  \Closure(ConnectionInterface): T  $operation
     * @return T|null
     */
    private function guarded(\Closure $operation): mixed
    {
        $connection = $this->db->connection();

        try {
            // Inside a transaction, under a savepoint, so a missing table cannot abort it.
            return $connection->transactionLevel() > 0
                ? $connection->transaction(fn () => $operation($connection))
                : $operation($connection);
        } catch (QueryException $exception) {
            // Before its migration there is nothing remembered. Any other failure propagates.
            if (in_array((string) $exception->getCode(), ['42S02', '42P01'], true)
                || str_contains(strtolower($exception->getMessage()), 'no such table')) {
                return null;
            }

            throw $exception;
        }
    }
}
