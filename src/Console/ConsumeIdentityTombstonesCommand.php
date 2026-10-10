<?php

namespace BWH\Auth\Console;

use BWH\Auth\OAuth\Lifecycle\IdentityTombstone;
use BWH\Auth\OAuth\Lifecycle\IdentityTombstoneClient;
use BWH\Auth\OAuth\Lifecycle\IdentityTombstoneCursorStore;
use BWH\Auth\OAuth\Lifecycle\IdentityTombstoneFeedUnavailable;
use BWH\Auth\OAuth\Lifecycle\IdentityTombstoneHandler;
use BWH\Auth\OAuth\Lifecycle\IdentityTombstonePage;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Sleep;

/**
 * Apply the identity provider's deletion tombstones through the application's handler.
 *
 * Each tombstone goes to the bound IdentityTombstoneHandler and is acknowledged only
 * when the handler returns, which states that the local deletion has committed. A
 * handler failure is recorded and the run moves on; the tombstone stays in the feed and
 * returns once the cursor starts over. The cursor advances only after every item on a
 * page has been handled or recorded as failed, so one failing record never hides later
 * pages, and a page cut short by an outage is read again (repeats are safe).
 *
 * Exits non-zero when the provider was unavailable, any tombstone failed, or no handler
 * is bound. Output is counts only: subjects never reach logs or the console.
 */
class ConsumeIdentityTombstonesCommand extends Command
{
    protected $signature = 'bherila-auth:consume-identity-tombstones
        {--limit= : Tombstones per page, 1 through 100 (defaults to bherila-auth.identity_tombstones.page_limit)}
        {--max-pages=10 : The most pages this run reads, 1 through 1000}';

    protected $description = 'Apply the identity provider\'s deletion tombstones and acknowledge each one after local deletion commits.';

    /** Throttled requests this run waits out before giving up until the next run. */
    private const MAX_THROTTLE_WAITS = 3;

    /** The longest single wait, whatever Retry-After asks for. */
    private const MAX_THROTTLE_SECONDS = 60;

    private int $received = 0;

    private int $acknowledged = 0;

    private int $failed = 0;

    private int $throttleWaits = 0;

    public function handle(IdentityTombstoneClient $client, IdentityTombstoneCursorStore $store): int
    {
        // The application reuses one command object across Artisan calls in a process, so
        // nothing from an earlier run may decide this one's outcome or throttle budget.
        $this->received = $this->acknowledged = $this->failed = $this->throttleWaits = 0;

        // Binding a handler is the opt-in. Scheduling the command without one is a
        // misconfiguration that would otherwise leave deletions unapplied silently.
        if (! $this->laravel->bound(IdentityTombstoneHandler::class)) {
            $this->error('No identity tombstone handler is bound; nothing was consumed.');

            return self::FAILURE;
        }

        $limit = $this->option('limit') ?? config('bherila-auth.identity_tombstones.page_limit', IdentityTombstoneClient::MAX_LIMIT);
        $limit = filter_var($limit, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1, 'max_range' => IdentityTombstoneClient::MAX_LIMIT]]);
        $maxPages = filter_var($this->option('max-pages'), FILTER_VALIDATE_INT, ['options' => ['min_range' => 1, 'max_range' => 1000]]);
        if ($limit === false || $maxPages === false) {
            $this->error('The limit must be from 1 through '.IdentityTombstoneClient::MAX_LIMIT.' and max-pages from 1 through 1000.');

            return self::INVALID;
        }

        if (! $store->installed()) {
            $this->error('The identity tombstone cursor table is not installed; publish bherila-auth-identity-tombstone-migrations and migrate.');

            return self::FAILURE;
        }

        try {
            $context = $client->context();
        } catch (IdentityTombstoneFeedUnavailable $exception) {
            $this->error($exception->getMessage());

            return self::FAILURE;
        }

        $handler = $this->laravel->make(IdentityTombstoneHandler::class);
        $owner = $store->acquire($context);
        if ($owner === null) {
            // Not a failure: the run holding the lease is doing this work.
            $this->info('Another run is consuming identity tombstones; skipped.');

            return self::SUCCESS;
        }

        try {
            [$pages, $stopped, $more] = $this->consume($client, $store, $handler, $context, $owner, $limit, $maxPages);
        } finally {
            try {
                $store->release($context, $owner);
            } catch (\Throwable) {
                // The lease lapses on its own; never mask the run's own outcome.
            }
        }

        $summary = "Identity tombstones: {$this->received} received, {$this->acknowledged} acknowledged, "
            ."{$this->failed} failed, {$pages} page(s) read";
        if ($stopped !== null) {
            $this->error($summary."; stopped: {$stopped}.");

            return self::FAILURE;
        }
        $summary .= $more ? '; more pending.' : '.';
        if ($this->failed > 0) {
            $this->error($summary);

            return self::FAILURE;
        }
        $this->info($summary);

        return self::SUCCESS;
    }

    /**
     * @return array{int, string|null, bool} pages fully recorded, why the run stopped early (if it did), whether more is pending
     */
    private function consume(
        IdentityTombstoneClient $client,
        IdentityTombstoneCursorStore $store,
        IdentityTombstoneHandler $handler,
        string $context,
        string $owner,
        int $limit,
        int $maxPages,
    ): array {
        $cursor = $store->cursor($context);
        for ($pages = 0; $pages < $maxPages;) {
            try {
                $page = $this->throttled($store, $context, $owner, fn (): IdentityTombstonePage => $client->page($cursor, $limit));
            } catch (IdentityTombstoneFeedUnavailable $exception) {
                if ($exception->reason === IdentityTombstoneFeedUnavailable::CURSOR_REJECTED) {
                    // Most likely a cursor from before the client changed; the next run starts from the oldest.
                    $store->advance($context, $owner, null);

                    return [$pages, 'the provider refused the stored cursor, which was cleared', false];
                }

                return [$pages, 'the tombstone feed is unavailable ('.$exception->reason.')', false];
            }

            $this->received += count($page->tombstones);
            foreach ($page->tombstones as $tombstone) {
                if (! $store->renew($context, $owner)) {
                    return [$pages, 'another run took over the lease', false];
                }
                if (! $this->apply($handler, $tombstone)) {
                    continue;
                }
                try {
                    $this->throttled($store, $context, $owner, fn () => $client->acknowledge($tombstone));
                    $this->acknowledged++;
                } catch (IdentityTombstoneFeedUnavailable $exception) {
                    // The local deletion committed and the next delivery repeats it harmlessly;
                    // the rest of this page waits for a provider that answers.
                    $this->failed++;
                    Log::warning('An identity tombstone could not be acknowledged.', [
                        'tombstone_id' => $tombstone->id, 'reason' => $exception->reason,
                    ]);

                    return [$pages, 'an acknowledgement failed ('.$exception->reason.')', false];
                }
            }

            // Every item on the page is recorded, acknowledged or not: advance past it.
            if (! $store->advance($context, $owner, $page->nextCursor)) {
                return [$pages, 'another run took over the lease', false];
            }
            $pages++;
            $cursor = $page->nextCursor;
            if (! $page->hasMore) {
                return [$pages, null, false];
            }
        }

        return [$pages, null, true];
    }

    /** Whether the handler committed the local deletion. A failure is recorded without the subject. */
    private function apply(IdentityTombstoneHandler $handler, IdentityTombstone $tombstone): bool
    {
        try {
            $handler->handle($tombstone);

            return true;
        } catch (\Throwable $exception) {
            $this->failed++;
            // The exception's message is the application's and may name the person; its class is enough to find it.
            Log::warning('An identity tombstone handler failed; the tombstone stays unacknowledged.', [
                'tombstone_id' => $tombstone->id, 'exception' => $exception::class,
            ]);

            return false;
        }
    }

    /**
     * Run a feed call, waiting out the provider's throttle a bounded number of times per run.
     * The reconciliation throttle is shared with session status checks, so waiting is
     * preferable to retrying immediately.
     *
     * @template T
     *
     * @param  \Closure(): T  $call
     * @return T
     */
    private function throttled(IdentityTombstoneCursorStore $store, string $context, string $owner, \Closure $call): mixed
    {
        while (true) {
            try {
                return $call();
            } catch (IdentityTombstoneFeedUnavailable $exception) {
                if ($exception->reason !== IdentityTombstoneFeedUnavailable::THROTTLED
                    || $this->throttleWaits >= self::MAX_THROTTLE_WAITS) {
                    throw $exception;
                }
                $this->throttleWaits++;
                Sleep::for(max(1, min($exception->retryAfter ?? self::MAX_THROTTLE_SECONDS, self::MAX_THROTTLE_SECONDS)))->seconds();
                if (! $store->renew($context, $owner)) {
                    throw $exception;
                }
            }
        }
    }
}
