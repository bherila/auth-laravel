<?php

namespace BWH\Auth\Console;

use BWH\Auth\OAuth\Lifecycle\IdentityTombstone;
use BWH\Auth\OAuth\Lifecycle\IdentityTombstoneClient;
use BWH\Auth\OAuth\Lifecycle\IdentityTombstoneCursorStore;
use BWH\Auth\OAuth\Lifecycle\IdentityTombstoneFeedUnavailable;
use BWH\Auth\OAuth\Lifecycle\IdentityTombstoneHandler;
use BWH\Auth\OAuth\Lifecycle\IdentityTombstonePage;
use BWH\Auth\OAuth\Lifecycle\IdentityTombstoneRetryStore;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Sleep;

/**
 * Apply the identity provider's deletion tombstones through the application's handler.
 *
 * Each tombstone goes to the bound IdentityTombstoneHandler and is acknowledged only
 * when the handler returns, which states that the local deletion has committed. A
 * handler failure is recorded in the retry table and the run moves on; recorded failures
 * are retried first on every run. The cursor advances only after every item on a page has
 * been handled or recorded as failed, so one failing record never hides later pages, and
 * a page cut short by an outage is read again (repeats are safe).
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

    private int $retried = 0;

    private int $acknowledged = 0;

    private int $failed = 0;

    private int $throttleWaits = 0;

    /** @var array<string, true> tombstone ids (lower-case) already handed to the handler this run */
    private array $attempted = [];

    private IdentityTombstoneClient $client;

    private IdentityTombstoneCursorStore $store;

    private IdentityTombstoneRetryStore $retries;

    private IdentityTombstoneHandler $handler;

    private string $context;

    private string $owner;

    private int $budget;

    public function handle(IdentityTombstoneClient $client, IdentityTombstoneCursorStore $store, IdentityTombstoneRetryStore $retries): int
    {
        // The application reuses one command object across Artisan calls in a process, so
        // nothing from an earlier run may decide this one's outcome or throttle budget.
        $this->received = $this->retried = $this->acknowledged = $this->failed = $this->throttleWaits = 0;
        $this->attempted = [];

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
        // A handler can only be kept from overlapping another run if its budget fits in a lease.
        $budget = filter_var(config('bherila-auth.identity_tombstones.handler_budget_seconds', 300), FILTER_VALIDATE_INT,
            ['options' => ['min_range' => 1, 'max_range' => IdentityTombstoneCursorStore::leaseSeconds()]]);
        if ($budget === false) {
            $this->error('identity_tombstones.handler_budget_seconds must be from 1 through lease_seconds ('.IdentityTombstoneCursorStore::leaseSeconds().').');

            return self::INVALID;
        }
        $this->budget = $budget;

        if (! $store->installed() || ! $retries->installed()) {
            $this->error('The identity tombstone tables are not installed; publish bherila-auth-identity-tombstone-migrations and migrate.');

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

        [$this->client, $this->store, $this->retries, $this->handler, $this->context, $this->owner]
            = [$client, $store, $retries, $handler, $context, $owner];
        try {
            [$pages, $stopped, $more] = $this->retry($limit) ?? $this->consume($limit, $maxPages);
        } finally {
            try {
                $store->release($context, $owner);
            } catch (\Throwable) {
                // The lease lapses on its own; never mask the run's own outcome.
            }
        }

        $summary = "Identity tombstones: {$this->received} received, {$this->retried} retried, "
            ."{$this->acknowledged} acknowledged, {$this->failed} failed, {$pages} page(s) read";
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
     * Retry earlier failures before reading the feed, so they are revisited every run rather
     * than only once the feed drains. A failure here, like one in the feed, does not hold up
     * newer tombstones.
     *
     * @return array{int, string, bool}|null null to go on to the feed
     */
    private function retry(int $limit): ?array
    {
        $this->retries->dropExpired($this->context);
        foreach ($this->retries->due($this->context, $limit) as $tombstone) {
            $this->retried++;
            if (($stopped = $this->process($tombstone)) !== null) {
                return [0, $stopped, false];
            }
        }

        return null;
    }

    /**
     * @return array{int, string|null, bool} pages fully recorded, why the run stopped early (if it did), whether more is pending
     */
    private function consume(int $limit, int $maxPages): array
    {
        $cursor = $this->store->cursor($this->context);
        for ($pages = 0; $pages < $maxPages;) {
            try {
                $page = $this->throttled(fn (): IdentityTombstonePage => $this->client->page($cursor, $limit));
            } catch (IdentityTombstoneFeedUnavailable $exception) {
                if ($exception->reason === IdentityTombstoneFeedUnavailable::CURSOR_REJECTED) {
                    // Most likely a cursor from before the client changed; the next run starts from the oldest.
                    $this->store->advance($this->context, $this->owner, null);

                    return [$pages, 'the provider refused the stored cursor, which was cleared', false];
                }

                return [$pages, 'the tombstone feed is unavailable ('.$exception->reason.')', false];
            }

            $this->received += count($page->tombstones);
            foreach ($page->tombstones as $tombstone) {
                // Already retried, and failed again, this run: it is recorded for the next one.
                if (isset($this->attempted[strtolower($tombstone->id)])) {
                    continue;
                }
                if (($stopped = $this->process($tombstone)) !== null) {
                    return [$pages, $stopped, false];
                }
            }

            // Every item on the page is recorded, acknowledged or not: advance past it.
            if (! $this->store->advance($this->context, $this->owner, $page->nextCursor)) {
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

    /**
     * Hand one tombstone to the handler and acknowledge it if the handler committed; record
     * it for a retry if not.
     *
     * @return string|null why the run must stop, or null to go on
     */
    private function process(IdentityTombstone $tombstone): ?string
    {
        // The lease cannot be renewed while the handler runs, so it must already cover the
        // handler's budget when the call starts.
        if (! $this->store->ensure($this->context, $this->owner, $this->budget)) {
            return 'another run took over the lease';
        }
        $this->attempted[strtolower($tombstone->id)] = true;
        if (! $this->apply($tombstone)) {
            $this->retries->record($this->context, $tombstone);

            return null;
        }

        try {
            $this->throttled(fn () => $this->client->acknowledge($tombstone));
            $this->acknowledged++;
        } catch (IdentityTombstoneFeedUnavailable $exception) {
            if ($exception->reason === IdentityTombstoneFeedUnavailable::GONE) {
                // The provider no longer assigns it to this application: nothing is owed.
                Log::warning('An identity tombstone is no longer assigned to this application.', ['tombstone_id' => $tombstone->id]);
                $this->retries->forget($this->context, $tombstone->id);

                return null;
            }
            // The local deletion committed and the next delivery repeats it harmlessly;
            // the rest of this run waits for a provider that answers.
            $this->failed++;
            Log::warning('An identity tombstone could not be acknowledged.', [
                'tombstone_id' => $tombstone->id, 'reason' => $exception->reason,
            ]);

            return 'an acknowledgement failed ('.$exception->reason.')';
        }
        $this->retries->forget($this->context, $tombstone->id);

        return null;
    }

    /** Whether the handler committed the local deletion. A failure is recorded without the subject. */
    private function apply(IdentityTombstone $tombstone): bool
    {
        try {
            $this->handler->handle($tombstone);

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
    private function throttled(\Closure $call): mixed
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
                if (! $this->store->renew($this->context, $this->owner)) {
                    throw $exception;
                }
            }
        }
    }
}
