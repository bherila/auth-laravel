<?php

namespace BWH\Auth\OAuth\DelegatedAccess;

use Illuminate\Database\ConnectionInterface;
use Illuminate\Database\UniqueConstraintViolationException;
use JsonException;
use Throwable;

/**
 * Operation receipts: the endpoint's stored answer to every `update` and `remove`, by `operation_id`.
 *
 * A write is claimed before the adapter runs, by inserting its row; the primary key on
 * (application, operation_id) lets exactly one request claim it, so two requests carrying the same
 * operation can never both reach the adapter. The answer is stored when the adapter has given one.
 * A repeat of the same request is answered from the row; anything else carrying the same
 * operation id is refused. Receipts are kept for {@see RETENTION_DAYS} days.
 *
 * Every storage failure refuses the write before the adapter runs. Nothing here may be skipped to
 * let a write through.
 */
final readonly class DatabaseReceiptStore
{
    public const TABLE = 'bherila_auth_delegated_receipts';

    public const RETENTION_DAYS = 30;

    public function __construct(private ConnectionInterface $connection) {}

    /**
     * Claim an operation for this request, or return the receipt another request already holds.
     *
     * @return DelegatedReceipt|null null when this request claimed the operation and may run it
     *
     * @throws DelegatedAccessException `receipt_storage_unavailable` (503), or `operation_in_progress`
     *                                  (503) when the operation was released while this was looking
     */
    public function claim(string $application, string $operationId, string $actor, string $requestHash): ?DelegatedReceipt
    {
        try {
            $this->connection->table(self::TABLE)->insert([
                'application' => $application,
                'operation_id' => $operationId,
                'actor' => $actor,
                'request_hash' => $requestHash,
                'status' => null,
                'response' => null,
                'created_at' => time(),
            ]);

            return null;
        } catch (UniqueConstraintViolationException) {
            // Somebody holds it. Fall through to what they hold.
        } catch (Throwable) {
            throw new DelegatedAccessException('receipt_storage_unavailable');
        }

        return $this->find($application, $operationId) ?? throw new DelegatedAccessException('operation_in_progress');
    }

    /**
     * Store the answer that is being sent for a claimed operation.
     *
     * @throws Throwable when it cannot be stored; the claim then stays pending
     */
    public function complete(string $application, string $operationId, int $status, string $response): void
    {
        $this->connection->table(self::TABLE)
            ->where('application', $application)->where('operation_id', $operationId)->whereNull('status')
            ->update(['status' => $status, 'response' => $response]);
    }

    /**
     * Give up a claim whose outcome nothing can vouch for (the adapter failed, or answered outside the
     * contract), so a later attempt is decided afresh against the application's revision.
     */
    public function release(string $application, string $operationId): void
    {
        $this->connection->table(self::TABLE)
            ->where('application', $application)->where('operation_id', $operationId)->whereNull('status')
            ->delete();
    }

    /**
     * @throws DelegatedAccessException `receipt_storage_unavailable` (503)
     */
    public function find(string $application, string $operationId): ?DelegatedReceipt
    {
        try {
            $row = $this->connection->table(self::TABLE)
                ->where('application', $application)->where('operation_id', $operationId)->first();
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
        );
    }

    /** Delete receipts older than {@see RETENTION_DAYS} days, stored or still pending. */
    public function pruneExpired(): int
    {
        return $this->connection->table(self::TABLE)->where('created_at', '<', time() - self::RETENTION_DAYS * 86400)->delete();
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
