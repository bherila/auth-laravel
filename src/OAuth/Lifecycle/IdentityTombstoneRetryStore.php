<?php

namespace BWH\Auth\OAuth\Lifecycle;

use DateTimeImmutable;
use DateTimeZone;
use Illuminate\Database\ConnectionInterface;
use Illuminate\Database\ConnectionResolverInterface;
use Illuminate\Database\Query\Builder;
use Illuminate\Support\Facades\Date;

/**
 * Tombstones whose handler failed, kept so the next run retries them first.
 *
 * The cursor moves past a page once every item on it has been recorded, so a failed
 * tombstone would otherwise come back only when the feed has drained and the cursor starts
 * over; a feed that never drains would never revisit it. A row is removed when the
 * tombstone is acknowledged, when the provider reports it is no longer assigned to this
 * application, or once its `purge_after` has passed. The feed remains the source of truth:
 * an unacknowledged tombstone dropped from here is still delivered when the cursor cycles.
 *
 * Rows hold the opaque subject (needed to call the handler again without the feed) and
 * nothing else about the person. Reads use the writer, like the cursor store's.
 */
final readonly class IdentityTombstoneRetryStore
{
    public const DEFAULT_TABLE = 'bherila_auth_identity_tombstone_retries';

    public function __construct(private ConnectionResolverInterface $db) {}

    public static function table(): string
    {
        $table = config('bherila-auth.identity_tombstones.retry_table');

        return is_string($table) && $table !== '' ? $table : self::DEFAULT_TABLE;
    }

    public function installed(): bool
    {
        return $this->connection()->getSchemaBuilder()->hasTable(self::table());
    }

    /**
     * Tombstones awaiting a retry, least recently attempted first.
     *
     * @return list<IdentityTombstone>
     */
    public function due(string $context, int $limit): array
    {
        return $this->query($context)
            ->orderBy('last_attempt_at')->orderBy('tombstoned_at')->orderBy('tombstone_id')
            ->limit($limit)->get()
            ->map(static fn (object $row): IdentityTombstone => new IdentityTombstone(
                (string) $row->tombstone_id,
                (string) $row->provider,
                (string) $row->subject,
                self::instant((int) $row->tombstoned_at),
                self::instant((int) $row->purge_after),
                $row->provider_purged_at === null ? null : self::instant((int) $row->provider_purged_at),
            ))->values()->all();
    }

    /** Record a failed attempt: a new row, or one more attempt on an existing one. */
    public function record(string $context, IdentityTombstone $tombstone): void
    {
        $now = self::now();
        $inserted = $this->connection()->table(self::table())->insertOrIgnore([
            'context' => $context,
            'tombstone_id' => strtolower($tombstone->id),
            'provider' => $tombstone->provider,
            'subject' => $tombstone->subject,
            'tombstoned_at' => $tombstone->tombstonedAt->getTimestamp(),
            'purge_after' => $tombstone->purgeAfter->getTimestamp(),
            'provider_purged_at' => $tombstone->providerPurgedAt?->getTimestamp(),
            'attempts' => 1,
            'last_attempt_at' => $now,
        ]);
        if ($inserted === 0) {
            $this->query($context)->where('tombstone_id', strtolower($tombstone->id))
                ->increment('attempts', 1, ['last_attempt_at' => $now]);
        }
    }

    public function forget(string $context, string $tombstoneId): void
    {
        $this->query($context)->where('tombstone_id', strtolower($tombstoneId))->delete();
    }

    /** Drop rows past the provider's purge window; the feed still delivers them when it cycles. */
    public function dropExpired(string $context): int
    {
        return $this->query($context)->where('purge_after', '<', self::now())->delete();
    }

    /** @return int|null attempts so far, or null when the tombstone is not awaiting a retry */
    public function attempts(string $context, string $tombstoneId): ?int
    {
        $attempts = $this->query($context)->where('tombstone_id', strtolower($tombstoneId))->value('attempts');

        return $attempts === null ? null : (int) $attempts;
    }

    private function query(string $context): Builder
    {
        return $this->connection()->table(self::table())->useWritePdo()->where('context', $context);
    }

    private function connection(): ConnectionInterface
    {
        return $this->db->connection(config('bherila-auth.identity_tombstones.connection'));
    }

    private static function instant(int $timestamp): DateTimeImmutable
    {
        return (new DateTimeImmutable('@'.$timestamp))->setTimezone(new DateTimeZone('UTC'));
    }

    private static function now(): int
    {
        return Date::now()->getTimestamp();
    }
}
