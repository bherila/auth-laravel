<?php

namespace BWH\Auth\OAuth\Lifecycle;

use BWH\Auth\OAuth\Reconciliation\ReconciliationFailure;
use BWH\Auth\OAuth\Reconciliation\ReconciliationTransport;
use DateTimeImmutable;
use DateTimeZone;

/**
 * Reads the identity provider's pending deletion tombstones and acknowledges them,
 * authenticated with this application's static OAuth client credential.
 *
 * Shares the status client's transport, so it has the same protections: a trusted
 * HTTPS base URL, no redirects, bounded time and body size, and failures that never
 * carry credentials or response bodies. Every response is validated against contract
 * version 1 before anything in it is used; a page is accepted whole or not at all.
 */
final readonly class IdentityTombstoneClient
{
    /** The provider's default and maximum page size. */
    public const MAX_LIMIT = 100;

    /** The provider refuses longer cursors, so a longer one cannot be a cursor it issued. */
    public const MAX_CURSOR_LENGTH = 512;

    public const MAX_SUBJECT_LENGTH = 255;

    private const PATH = '/api/reconciliation/identity-tombstones';

    /** A full page of 100 maximal items is under 50 KiB; anything past this is not the feed. */
    private const PAGE_BYTES = 262_144;

    private const ACKNOWLEDGEMENT_BYTES = 16_384;

    private const PAGE_SECONDS = 10;

    private const ACKNOWLEDGEMENT_SECONDS = 5;

    private const UUID = '/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iD';

    private const TIMESTAMP = '/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})$/D';

    public function __construct(private ReconciliationTransport $transport) {}

    /**
     * The oldest unacknowledged tombstones assigned to this application.
     *
     * @param  string|null  $cursor  the previous page's `next_cursor`, unchanged, or null to start from the oldest
     *
     * @throws IdentityTombstoneFeedUnavailable
     */
    public function page(?string $cursor = null, int $limit = self::MAX_LIMIT): IdentityTombstonePage
    {
        if ($limit < 1 || $limit > self::MAX_LIMIT) {
            throw new \InvalidArgumentException('The tombstone page limit must be from 1 through '.self::MAX_LIMIT.'.');
        }
        if ($cursor !== null && ! self::isCursor($cursor)) {
            throw new \InvalidArgumentException('The tombstone cursor is not one the provider issues.');
        }

        $query = ['limit' => $limit] + ($cursor === null ? [] : ['cursor' => $cursor]);
        $data = $this->guard(
            fn (): array => $this->transport->send('GET', self::PATH, $query, null, self::PAGE_BYTES, self::PAGE_SECONDS),
            cursorSent: $cursor !== null,
        );

        if (($data['contract_version'] ?? null) !== 1 || ! array_is_list($items = $data['data'] ?? null)
            || count($items) > $limit || ! is_bool($hasMore = $data['has_more'] ?? null)
            || ! array_key_exists('next_cursor', $data)) {
            throw self::invalid();
        }
        // The contract pairs them exactly: a cursor when, and only when, there is more.
        $next = $data['next_cursor'];
        if ($hasMore ? ! (is_string($next) && self::isCursor($next)) : $next !== null) {
            throw self::invalid();
        }

        $provider = $this->guard(fn (): string => $this->transport->setting('provider'));
        $tombstones = [];
        $seen = [];
        foreach ($items as $item) {
            $tombstone = self::tombstone($item, $provider);
            $key = strtolower($tombstone->id);
            if (isset($seen[$key])) {
                throw self::invalid();
            }
            $seen[$key] = true;
            $tombstones[] = $tombstone;
        }

        return new IdentityTombstonePage($tombstones, $hasMore, $next);
    }

    /**
     * Tell the provider this application's deletion for the tombstone has committed.
     * Replaying it is safe; the provider keeps the first acknowledgement time.
     *
     * @throws IdentityTombstoneFeedUnavailable
     */
    public function acknowledge(IdentityTombstone $tombstone): void
    {
        // The id becomes a path segment, so it is never sent unless it is exactly a UUID.
        if (preg_match(self::UUID, $tombstone->id) !== 1) {
            throw new \InvalidArgumentException('The tombstone id is not a UUID.');
        }

        $data = $this->guard(fn (): array => $this->transport->send(
            'PUT', self::PATH.'/'.$tombstone->id.'/acknowledgement', [], null,
            self::ACKNOWLEDGEMENT_BYTES, self::ACKNOWLEDGEMENT_SECONDS,
        ));

        $acknowledgement = $data['acknowledgement'] ?? null;
        if (($data['contract_version'] ?? null) !== 1 || ! is_array($acknowledgement)
            || self::timestamp($acknowledgement['acknowledged_at'] ?? null) === null
            || (array_key_exists('tombstone_id', $acknowledgement) && $acknowledgement['tombstone_id'] !== $tombstone->id)) {
            throw self::invalid();
        }
    }

    /**
     * A digest of the configured provider and client. Cursors are bound to the client that
     * received them, so stored cursors are kept per context.
     *
     * @throws IdentityTombstoneFeedUnavailable
     */
    public function context(): string
    {
        return $this->guard(fn (): string => $this->transport->context());
    }

    private static function tombstone(mixed $item, string $provider): IdentityTombstone
    {
        if (! is_array($item)
            || ! is_string($id = $item['id'] ?? null) || preg_match(self::UUID, $id) !== 1
            || ! is_string($subject = $item['subject'] ?? null) || $subject === ''
            || strlen($subject) > self::MAX_SUBJECT_LENGTH
            || ($tombstonedAt = self::timestamp($item['tombstoned_at'] ?? null)) === null
            || ($purgeAfter = self::timestamp($item['purge_after'] ?? null)) === null
            || ! array_key_exists('provider_purged_at', $item)) {
            throw self::invalid();
        }
        $purgedAt = null;
        if ($item['provider_purged_at'] !== null
            && ($purgedAt = self::timestamp($item['provider_purged_at'])) === null) {
            throw self::invalid();
        }

        return new IdentityTombstone($id, $provider, $subject, $tombstonedAt, $purgeAfter, $purgedAt);
    }

    /** An ISO 8601 instant with an explicit offset, in UTC; null for anything else, including impossible dates. */
    private static function timestamp(mixed $value): ?DateTimeImmutable
    {
        if (! is_string($value) || preg_match(self::TIMESTAMP, $value) !== 1) {
            return null;
        }
        try {
            $parsed = new DateTimeImmutable($value);
        } catch (\Exception) {
            return null;
        }
        // PHP rolls 2026-02-30 over into March and reports it only as a warning.
        $errors = DateTimeImmutable::getLastErrors();
        if ($errors !== false && ($errors['warning_count'] > 0 || $errors['error_count'] > 0)) {
            return null;
        }

        return $parsed->setTimezone(new DateTimeZone('UTC'));
    }

    private static function isCursor(string $cursor): bool
    {
        return $cursor !== '' && strlen($cursor) <= self::MAX_CURSOR_LENGTH;
    }

    private static function invalid(): IdentityTombstoneFeedUnavailable
    {
        return new IdentityTombstoneFeedUnavailable(IdentityTombstoneFeedUnavailable::INVALID, 'The identity tombstone response is invalid.');
    }

    /**
     * Run a transport call, reporting its failure in this client's own terms.
     *
     * @template T
     *
     * @param  \Closure(): T  $call
     * @return T
     */
    private function guard(\Closure $call, bool $cursorSent = false): mixed
    {
        try {
            return $call();
        } catch (ReconciliationFailure $failure) {
            throw match (true) {
                $failure->reason === ReconciliationFailure::NOT_CONFIGURED => new IdentityTombstoneFeedUnavailable(
                    IdentityTombstoneFeedUnavailable::NOT_CONFIGURED, 'The identity tombstone feed is not configured.'),
                $failure->reason === ReconciliationFailure::UNTRUSTED_URL => new IdentityTombstoneFeedUnavailable(
                    IdentityTombstoneFeedUnavailable::UNTRUSTED_URL, 'The identity tombstone feed requires a trusted HTTPS base URL.'),
                $failure->reason === ReconciliationFailure::INVALID => self::invalid(),
                $failure->status === 429 => new IdentityTombstoneFeedUnavailable(
                    IdentityTombstoneFeedUnavailable::THROTTLED, 'The identity tombstone feed is throttled.', $failure->retryAfter),
                // A cursor issued to another client, or one the provider no longer accepts.
                $cursorSent && $failure->status === 422 => new IdentityTombstoneFeedUnavailable(
                    IdentityTombstoneFeedUnavailable::CURSOR_REJECTED, 'The identity tombstone feed refused the stored cursor.'),
                default => new IdentityTombstoneFeedUnavailable(
                    IdentityTombstoneFeedUnavailable::UNAVAILABLE, 'The identity tombstone feed is unavailable.'),
            };
        }
    }
}
