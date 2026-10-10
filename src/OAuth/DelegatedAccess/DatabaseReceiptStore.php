<?php

namespace BWH\Auth\OAuth\DelegatedAccess;

use Illuminate\Database\Connection;
use Illuminate\Database\ConnectionInterface;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Carbon;
use JsonException;
use Throwable;

/**
 * Operation receipts: the endpoint's stored answer to every `update` and `remove`, by `operation_id`.
 *
 * A write is claimed before the adapter runs, by inserting its row; the primary key on
 * (application, a digest of operation_id) lets exactly one request claim it, so two requests carrying the same
 * operation can never both reach the adapter. The answer is stored when the adapter has given one.
 * A repeat of the same request is answered from the row; anything else carrying the same
 * operation id is refused. Receipts are kept for {@see RETENTION_DAYS} days.
 *
 * A claim whose answer never arrives (the request died mid-write) blocks repeats for
 * {@see PENDING_LEASE_SECONDS}. After that a repeat of the same request may claim it again, and
 * the adapter's revision check decides afresh whether the first attempt changed anything. Each
 * claim is identified by when it was taken, so a request that outlived its lease cannot store or
 * release over the claim that replaced it.
 *
 * Every storage failure refuses the write before the adapter runs. Nothing here may be skipped to
 * let a write through.
 */
final readonly class DatabaseReceiptStore
{
    public const TABLE = 'bherila_auth_delegated_receipts';

    public const RETENTION_DAYS = 30;

    /** How long an unfinished claim blocks repeats of its operation: ten minutes. */
    public const PENDING_LEASE_SECONDS = 600;

    public function __construct(private ConnectionInterface $connection) {}

    /**
     * Claim an operation for this request, or return the receipt another request already holds.
     *
     * An abandoned claim ({@see DelegatedReceipt::abandoned()}) for the same request is taken over.
     *
     * @param  int|null  $at  the claim's time, now by default; pass it to {@see complete()} and {@see release()}
     * @return DelegatedReceipt|null null when this request claimed the operation and may run it
     *
     * @throws DelegatedAccessException `receipt_storage_unavailable` (503), or `operation_in_progress`
     *                                  (503) when the operation was released while this was looking
     */
    public function claim(string $application, string $operationId, string $actor, string $requestHash, ?int $at = null): ?DelegatedReceipt
    {
        $at ??= self::now();
        $row = [
            'application' => $application,
            'operation_key' => self::key($operationId),
            'operation_id' => $operationId,
            'actor' => $actor,
            'request_hash' => $requestHash,
            'status' => null,
            'response' => null,
            'claimed_at' => $at,
            'created_at' => $at,
        ];
        try {
            $inserted = $this->insertOnce($row);
        } catch (Throwable) {
            throw new DelegatedAccessException('receipt_storage_unavailable');
        }
        if ($inserted === 1) {
            return null;
        }

        // Somebody holds it: what do they hold?
        $held = $this->find($application, $operationId) ?? throw new DelegatedAccessException('operation_in_progress');
        if (! $held->abandoned($at) || ! hash_equals($held->requestHash, $requestHash)) {
            return $held;
        }

        // Take it over only if it is still the abandoned claim seen above: of several repeats racing
        // for it, the conditional update lets exactly one through.
        try {
            $taken = $this->connection->table(self::TABLE)
                ->where('application', $application)->where('operation_key', self::key($operationId))
                ->whereNull('status')->where('request_hash', $requestHash)->where('claimed_at', $held->claimedAt)
                // Retention restarts with the claim, so a prune running now cannot delete the live claim
                // by the abandoned one's age.
                ->update(['claimed_at' => $at, 'created_at' => $at]);
        } catch (Throwable) {
            throw new DelegatedAccessException('receipt_storage_unavailable');
        }

        // Lost the race: another repeat holds it now, so it is in progress, as the pending receipt says.
        return $taken === 1 ? null : $held;
    }

    /**
     * Insert the row unless its key exists; 1 when inserted, 0 when somebody holds it.
     *
     * A conflict-safe insert, never a bare caught duplicate-key error: on PostgreSQL that error would
     * abort a surrounding transaction, and every statement after it, the read that follows included.
     * SQL Server's grammar has no insert-or-ignore, so there the insert runs in its own transaction,
     * a savepoint inside a surrounding one, and only a duplicate key counts as held.
     *
     * @param  array<string, mixed>  $row
     */
    private function insertOnce(array $row): int
    {
        $driver = $this->connection instanceof Connection ? $this->connection->getDriverName() : null;
        if ($driver !== 'sqlsrv') {
            return $this->connection->table(self::TABLE)->insertOrIgnore($row);
        }

        try {
            return $this->connection->transaction(fn (): int => $this->connection->table(self::TABLE)->insert($row) ? 1 : 0);
        } catch (UniqueConstraintViolationException) {
            return 0;
        }
    }

    /**
     * Store the answer that is being sent for a claimed operation.
     *
     * Nothing is stored when the claim taken at `$claimedAt` has since been taken over.
     *
     * @throws Throwable when it cannot be stored; the claim then stays pending
     */
    public function complete(string $application, string $operationId, int $claimedAt, int $status, string $response): void
    {
        $this->connection->table(self::TABLE)
            ->where('application', $application)->where('operation_key', self::key($operationId))->whereNull('status')->where('claimed_at', $claimedAt)
            ->update(['status' => $status, 'response' => $response]);
    }

    /**
     * Give up a claim whose outcome nothing can vouch for (the adapter failed, or answered outside the
     * contract), so a later attempt is decided afresh against the application's revision.
     */
    public function release(string $application, string $operationId, int $claimedAt): void
    {
        $this->connection->table(self::TABLE)
            ->where('application', $application)->where('operation_key', self::key($operationId))->whereNull('status')->where('claimed_at', $claimedAt)
            ->delete();
    }

    /**
     * @throws DelegatedAccessException `receipt_storage_unavailable` (503)
     */
    public function find(string $application, string $operationId): ?DelegatedReceipt
    {
        try {
            $row = $this->connection->table(self::TABLE)
                ->where('application', $application)->where('operation_key', self::key($operationId))->first();
        } catch (Throwable) {
            throw new DelegatedAccessException('receipt_storage_unavailable');
        }
        if ($row === null) {
            return null;
        }

        return new DelegatedReceipt(
            (string) $row->actor,
            (string) $row->request_hash,
            $row->status === null ? null : (int) $row->status,
            $row->response === null ? null : (string) $row->response,
            (int) $row->claimed_at,
        );
    }

    /**
     * Whether the receipts table exists on this store's connection. An application that does not
     * serve version 3 writes may not have installed it.
     */
    public function installed(): bool
    {
        return $this->connection instanceof Connection && $this->connection->getSchemaBuilder()->hasTable(self::TABLE);
    }

    /** Delete receipts older than {@see RETENTION_DAYS} days, stored or still pending. */
    public function pruneExpired(): int
    {
        return $this->connection->table(self::TABLE)->where('created_at', '<', self::now() - self::RETENTION_DAYS * 86400)->delete();
    }

    /** The store's clock, in Unix seconds; follows Carbon's test time. */
    public static function now(): int
    {
        return Carbon::now()->getTimestamp();
    }

    /**
     * The stored key for an operation id: its SHA-256, so the key compares exactly whatever the
     * column's collation (operation ids are case-sensitive).
     */
    public static function key(string $operationId): string
    {
        return hash('sha256', $operationId);
    }

    /** Who sent a write, as stored: a digest of the verified actor subject. */
    public static function actor(string $actorSubject): string
    {
        return hash('sha256', $actorSubject);
    }

    /**
     * A digest of a write as the actor asked for it, to tell a repeat from a different request.
     *
     * The canonical encoding is JSON of `{actor, request}`, where `request` is the operation payload
     * without the transport fields (`contract_version`, `application`) and without `operation_id`
     * itself, object keys sorted at every depth and list order kept. The same action retried gives
     * the same digest whatever order the provider serialised its keys in; the same operation id from
     * another actor never does.
     *
     * @param  array<string, mixed>  $payload
     */
    public static function requestHash(string $actorSubject, array $payload): string
    {
        unset($payload['contract_version'], $payload['application'], $payload['operation_id']);

        try {
            $canonical = json_encode(['actor' => $actorSubject, 'request' => self::canonical($payload)],
                JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRESERVE_ZERO_FRACTION);
        } catch (JsonException) {
            throw new DelegatedAccessException('invalid_request', 422);
        }

        return hash('sha256', $canonical);
    }

    private static function canonical(mixed $value): mixed
    {
        if (! is_array($value)) {
            return $value;
        }
        if (! array_is_list($value)) {
            ksort($value, SORT_STRING);
        }

        return array_map(self::canonical(...), $value);
    }
}
