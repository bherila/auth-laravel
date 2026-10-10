<?php

namespace BWH\Auth\OAuth\Lifecycle;

use Illuminate\Database\ConnectionInterface;
use Illuminate\Database\ConnectionResolverInterface;
use Illuminate\Support\Facades\Date;

/**
 * The tombstone feed's stored cursor and the lease that lets one run consume it at a time.
 *
 * One row per provider/client context: cursors are bound to the client that received
 * them, so a changed client starts from the oldest pending tombstone instead of sending
 * another client's cursor. Losing a cursor is harmless (the provider repeats pages
 * safely), but losing the lease would let two runs hand the same tombstone to the
 * handler at once, so the lease is taken by a conditional update on this durable table
 * rather than through a cache an application may not share between servers.
 *
 * A run holds the lease for {@see LEASE_SECONDS} and renews it as it goes; a run that
 * died is replaced once its lease expires. Every write is conditioned on still holding
 * the lease, so a run that outlived it cannot move the cursor under its successor.
 */
final readonly class IdentityTombstoneCursorStore
{
    public const DEFAULT_TABLE = 'bherila_auth_identity_tombstone_cursors';

    public const LEASE_SECONDS = 900;

    public function __construct(private ConnectionResolverInterface $db) {}

    public static function table(): string
    {
        $table = config('bherila-auth.identity_tombstones.table');

        return is_string($table) && $table !== '' ? $table : self::DEFAULT_TABLE;
    }

    public function installed(): bool
    {
        return $this->connection()->getSchemaBuilder()->hasTable(self::table());
    }

    /**
     * Take the lease for this context, or null while another run holds it.
     *
     * @return string|null the holder token every later call must present
     */
    public function acquire(string $context): ?string
    {
        $now = self::now();
        $this->connection()->table(self::table())->insertOrIgnore([
            'context' => $context, 'cursor' => null, 'lease_owner' => null,
            'lease_expires_at' => 0, 'updated_at' => $now,
        ]);

        // A fresh random holder always changes the row, so the affected count is exact on every driver.
        $owner = bin2hex(random_bytes(16));
        $taken = $this->connection()->table(self::table())
            ->where('context', $context)
            ->where(fn ($query) => $query->whereNull('lease_owner')->orWhere('lease_expires_at', '<=', $now))
            ->update(['lease_owner' => $owner, 'lease_expires_at' => $now + self::LEASE_SECONDS, 'updated_at' => $now]);

        return $taken === 1 ? $owner : null;
    }

    /** Extend the lease; false when it has passed to another run. */
    public function renew(string $context, string $owner): bool
    {
        $now = self::now();
        $this->held($context, $owner)->update(['lease_expires_at' => $now + self::LEASE_SECONDS, 'updated_at' => $now]);

        // Checked separately: MySQL reports an update that changes nothing (a renewal within
        // the same second) as zero affected rows.
        return $this->held($context, $owner)->exists();
    }

    /** The stored cursor, read from the writer; null to start from the oldest pending tombstone. */
    public function cursor(string $context): ?string
    {
        $cursor = $this->connection()->table(self::table())->useWritePdo()->where('context', $context)->value('cursor');

        return is_string($cursor) && $cursor !== '' ? $cursor : null;
    }

    /** Store the next cursor (null to start over next time); false when the lease was lost. */
    public function advance(string $context, string $owner, ?string $cursor): bool
    {
        $this->held($context, $owner)->update(['cursor' => $cursor, 'updated_at' => self::now()]);

        return $this->held($context, $owner)->exists();
    }

    public function release(string $context, string $owner): void
    {
        $this->held($context, $owner)->update(['lease_owner' => null, 'lease_expires_at' => 0, 'updated_at' => self::now()]);
    }

    /**
     * The row, if this run holds its lease. Read from the writer: on a read/write split a
     * lagging replica would not yet show the lease or cursor this run just wrote, and a
     * run would wrongly conclude it lost the lease or resume from an older cursor.
     */
    private function held(string $context, string $owner): \Illuminate\Database\Query\Builder
    {
        return $this->connection()->table(self::table())->useWritePdo()
            ->where('context', $context)->where('lease_owner', $owner);
    }

    private function connection(): ConnectionInterface
    {
        return $this->db->connection(config('bherila-auth.identity_tombstones.connection'));
    }

    private static function now(): int
    {
        return Date::now()->getTimestamp();
    }
}
