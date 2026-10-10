<?php

namespace BWH\Auth\Tests\Feature;

use BWH\Auth\OAuth\Lifecycle\IdentityTombstoneClient;
use BWH\Auth\OAuth\Lifecycle\IdentityTombstoneCursorStore;
use BWH\Auth\OAuth\Lifecycle\IdentityTombstoneHandler;
use BWH\Auth\Tests\Fixtures\RecordingTombstoneHandler;
use BWH\Auth\Tests\TestCase;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Sleep;

class ConsumeIdentityTombstonesCommandTest extends TestCase
{
    private const COMMAND = 'bherila-auth:consume-identity-tombstones';

    private RecordingTombstoneHandler $handler;

    /** @var list<Request> */
    private array $reads = [];

    /** @var list<string> */
    private array $acknowledged = [];

    protected function setUp(): void
    {
        parent::setUp();
        config(['app.env' => 'testing']);
        config(['bherila-auth.oauth_client' => [
            'provider' => 'example-provider',
            'base_url' => 'https://identity.example.test',
            'client_id' => 'example-client',
            'client_secret' => 'example-secret',
        ]]);
        (require __DIR__.'/../../database/identity-tombstone-migrations/2026_10_10_100000_create_identity_tombstone_cursors.php')->up();
        $this->handler = new RecordingTombstoneHandler;
        $this->app->instance(IdentityTombstoneHandler::class, $this->handler);
        Http::preventStrayRequests();
        Sleep::fake();
    }

    private static function id(int $n): string
    {
        return sprintf('00000000-0000-4000-8000-%012d', $n);
    }

    private static function page(array $ns, ?string $next = null): array
    {
        return [
            'contract_version' => 1,
            'data' => array_map(static fn (int $n): array => [
                'id' => self::id($n), 'subject' => 'subject-secret-'.$n,
                'tombstoned_at' => '2026-08-26T12:00:00.000000Z', 'purge_after' => '2026-09-25T12:00:00.000000Z',
                'provider_purged_at' => null,
            ], $ns),
            'has_more' => $next !== null,
            'next_cursor' => $next,
        ];
    }

    /**
     * Serve reads from a queue and acknowledge anything, unless an id is listed as failing.
     *
     * @param  list<array|\GuzzleHttp\Promise\PromiseInterface>  $reads
     * @param  array<string, \GuzzleHttp\Promise\PromiseInterface>  $acknowledgements  per tombstone id
     */
    private function provider(array $reads, array $acknowledgements = []): void
    {
        Http::fake(function (Request $request) use (&$reads, $acknowledgements) {
            if ($request->method() === 'PUT') {
                $id = explode('/', parse_url($request->url(), PHP_URL_PATH))[4];
                // An acknowledgement states that local deletion committed: it may never precede the handler.
                $this->assertContains($id, $this->handler->ids(), 'Acknowledged before the handler returned');
                if (isset($acknowledgements[$id])) {
                    return $acknowledgements[$id];
                }
                $this->acknowledged[] = $id;

                return Http::response(['contract_version' => 1, 'acknowledgement' => ['tombstone_id' => $id, 'acknowledged_at' => '2026-08-27T00:00:00.000000Z']]);
            }
            $this->reads[] = $request;
            $next = array_shift($reads) ?? $this->fail('Unexpected read: '.$request->url());

            return is_array($next) ? Http::response($next) : $next;
        });
    }

    /** @return array{int, string} */
    private function run_(array $options = []): array
    {
        $code = Artisan::call(self::COMMAND, $options);

        return [$code, Artisan::output()];
    }

    private function store(): IdentityTombstoneCursorStore
    {
        return $this->app->make(IdentityTombstoneCursorStore::class);
    }

    private function storedCursor(): ?string
    {
        return $this->store()->cursor($this->app->make(IdentityTombstoneClient::class)->context());
    }

    private function storeCursor(string $cursor): void
    {
        $context = $this->app->make(IdentityTombstoneClient::class)->context();
        $owner = $this->store()->acquire($context);
        $this->store()->advance($context, $owner, $cursor);
        $this->store()->release($context, $owner);
    }

    public function test_it_reads_every_page_handles_and_acknowledges_each_tombstone_and_starts_over_at_the_end(): void
    {
        $this->provider([self::page([1, 2], 'cursor-1'), self::page([3])]);

        [$code, $output] = $this->run_();

        $this->assertSame(0, $code, $output);
        $this->assertSame([self::id(1), self::id(2), self::id(3)], $this->handler->ids());
        $this->assertSame('example-provider', $this->handler->handled[0]->provider);
        $this->assertSame('subject-secret-1', $this->handler->handled[0]->subject);
        $this->assertSame([self::id(1), self::id(2), self::id(3)], $this->acknowledged);
        $this->assertStringEndsWith('/identity-tombstones?limit=100', $this->reads[0]->url());
        $this->assertStringEndsWith('/identity-tombstones?limit=100&cursor=cursor-1', $this->reads[1]->url());
        $this->assertNull($this->storedCursor(), 'The next cycle starts without a cursor');
        $this->assertStringContainsString('Identity tombstones: 3 received, 3 acknowledged, 0 failed, 2 page(s) read.', $output);
        $this->assertStringNotContainsString('subject-secret', $output);
    }

    public function test_a_run_that_reaches_max_pages_persists_the_cursor_for_the_next_run(): void
    {
        $this->provider([self::page([1], 'cursor-1'), self::page([2])]);

        [$code, $output] = $this->run_(['--max-pages' => 1, '--limit' => 1]);
        $this->assertSame(0, $code, $output);
        $this->assertStringContainsString('1 page(s) read; more pending.', $output);
        $this->assertSame('cursor-1', $this->storedCursor());
        $this->assertStringEndsWith('?limit=1', $this->reads[0]->url());

        [$code] = $this->run_(['--limit' => 1]);
        $this->assertSame(0, $code);
        $this->assertStringEndsWith('?limit=1&cursor=cursor-1', $this->reads[1]->url(), 'A restart resumes from the stored cursor');
        $this->assertSame([self::id(1), self::id(2)], $this->acknowledged);
    }

    public function test_the_page_limit_defaults_to_configuration(): void
    {
        config(['bherila-auth.identity_tombstones.page_limit' => 7]);
        $this->provider([self::page([])]);

        $this->assertSame(0, $this->run_()[0]);
        $this->assertStringEndsWith('?limit=7', $this->reads[0]->url());
    }

    public function test_a_handler_failure_leaves_that_tombstone_unacknowledged_and_the_run_continues_then_fails(): void
    {
        Log::spy();
        $this->handler->failing[self::id(2)] = true;
        $this->provider([self::page([1, 2, 3], 'cursor-1'), self::page([4])]);

        [$code, $output] = $this->run_();

        $this->assertSame(1, $code);
        $this->assertSame([self::id(1), self::id(3), self::id(4)], $this->acknowledged);
        $this->assertNull($this->storedCursor(), 'The page was recorded, so the cursor advanced past it');
        $this->assertStringContainsString('4 received, 3 acknowledged, 1 failed, 2 page(s) read.', $output);
        $this->assertStringNotContainsString('subject-secret', $output);
        Log::shouldHaveReceived('warning')->once()->withArgs(fn (string $message, array $context): bool => $context === ['tombstone_id' => self::id(2), 'exception' => \RuntimeException::class]
            && ! str_contains($message.json_encode($context), 'subject-secret'));
    }

    public function test_each_invocation_starts_with_fresh_counts_and_throttle_budget(): void
    {
        // The command object is reused by repeated Artisan calls in one process.
        $this->handler->failing[self::id(1)] = true;
        $this->provider([
            self::page([1]),
            Http::response('', 429, ['Retry-After' => '1']), Http::response('', 429, ['Retry-After' => '1']),
            Http::response('', 429, ['Retry-After' => '1']), self::page([]),
            Http::response('', 429, ['Retry-After' => '1']), self::page([2]),
        ]);

        [$first] = $this->run_();
        $this->assertSame(1, $first);

        $this->handler->failing = [];
        [$second, $output] = $this->run_();
        $this->assertSame(0, $second, $output);
        $this->assertStringContainsString('0 received, 0 acknowledged, 0 failed, 1 page(s) read.', $output);

        [$third, $output] = $this->run_();
        $this->assertSame(0, $third, 'Earlier throttle waits do not use up this run\'s budget: '.$output);
        $this->assertSame([self::id(2)], $this->acknowledged);
    }

    public function test_an_unavailable_feed_fails_without_touching_the_cursor_or_the_handler(): void
    {
        $this->storeCursor('cursor-1');
        $this->provider([Http::response(['message' => 'example-secret'], 503)]);

        [$code, $output] = $this->run_();

        $this->assertSame(1, $code);
        $this->assertSame([], $this->handler->handled);
        $this->assertSame('cursor-1', $this->storedCursor());
        $this->assertStringContainsString('0 page(s) read; stopped: the tombstone feed is unavailable (unavailable).', $output);
        $this->assertStringNotContainsString('example-secret', $output);
    }

    public function test_a_malformed_page_is_not_handled_at_all(): void
    {
        $page = self::page([1, 2]);
        $page['data'][1]['subject'] = 42;
        $this->provider([$page]);

        [$code, $output] = $this->run_();

        $this->assertSame(1, $code);
        $this->assertSame([], $this->handler->handled, 'A page is accepted whole or not at all');
        $this->assertStringContainsString('stopped: the tombstone feed is unavailable (invalid)', $output);
    }

    public function test_a_failed_acknowledgement_stops_the_run_and_leaves_the_page_to_be_read_again(): void
    {
        Log::spy();
        $this->storeCursor('cursor-0');
        $this->provider([self::page([1, 2, 3], 'cursor-1')], [self::id(2) => Http::response('', 500)]);

        [$code, $output] = $this->run_();

        $this->assertSame(1, $code);
        $this->assertSame([self::id(1), self::id(2)], $this->handler->ids(), 'The rest of the page waits for the provider');
        $this->assertSame([self::id(1)], $this->acknowledged);
        $this->assertSame('cursor-0', $this->storedCursor(), 'An incompletely recorded page is read again');
        $this->assertStringContainsString('3 received, 1 acknowledged, 1 failed, 0 page(s) read; stopped: an acknowledgement failed (unavailable).', $output);
        Log::shouldHaveReceived('warning')->once()->with('An identity tombstone could not be acknowledged.', ['tombstone_id' => self::id(2), 'reason' => 'unavailable']);
    }

    public function test_throttling_is_waited_out_a_bounded_number_of_times(): void
    {
        $this->provider([
            Http::response('', 429, ['Retry-After' => '2']),
            Http::response('', 429, ['Retry-After' => '3600']),
            self::page([1]),
        ]);

        [$code, $output] = $this->run_();

        $this->assertSame(0, $code, $output);
        $this->assertSame([self::id(1)], $this->acknowledged);
        Sleep::assertSequence([Sleep::for(2)->seconds(), Sleep::for(60)->seconds()]);
    }

    public function test_persistent_throttling_gives_up_until_the_next_run(): void
    {
        $this->provider(array_fill(0, 4, Http::response('', 429)));

        [$code, $output] = $this->run_();

        $this->assertSame(1, $code);
        $this->assertStringContainsString('stopped: the tombstone feed is unavailable (throttled)', $output);
        Sleep::assertSleptTimes(3);
    }

    public function test_a_refused_cursor_is_cleared_so_the_next_run_starts_from_the_oldest(): void
    {
        $this->storeCursor('cursor-from-another-client');
        $this->provider([Http::response(['message' => 'The cursor is invalid.'], 422)]);

        [$code, $output] = $this->run_();

        $this->assertSame(1, $code);
        $this->assertNull($this->storedCursor());
        $this->assertStringContainsString('the provider refused the stored cursor, which was cleared', $output);
    }

    public function test_a_changed_client_does_not_reuse_the_previous_clients_cursor(): void
    {
        $this->storeCursor('cursor-for-example-client');
        config(['bherila-auth.oauth_client.client_id' => 'replacement-client']);
        $this->provider([self::page([])]);

        $this->assertSame(0, $this->run_()[0]);
        $this->assertStringEndsWith('?limit=100', $this->reads[0]->url());
    }

    public function test_nothing_is_consumed_without_a_bound_handler(): void
    {
        $this->app->offsetUnset(IdentityTombstoneHandler::class);
        Http::fake();

        [$code, $output] = $this->run_();

        $this->assertSame(1, $code);
        $this->assertStringContainsString('No identity tombstone handler is bound', $output);
        Http::assertNothingSent();
    }

    public function test_a_second_run_skips_while_one_holds_the_lease(): void
    {
        $context = $this->app->make(IdentityTombstoneClient::class)->context();
        $this->assertIsString($this->store()->acquire($context));
        Http::fake();

        [$code, $output] = $this->run_();

        $this->assertSame(0, $code);
        $this->assertStringContainsString('Another run is consuming identity tombstones; skipped.', $output);
        Http::assertNothingSent();
    }

    public function test_the_lease_is_released_at_the_end_of_a_run(): void
    {
        $this->provider([self::page([]), self::page([])]);

        $this->assertSame(0, $this->run_()[0]);
        $this->assertSame(0, $this->run_()[0]);
        $this->assertCount(2, $this->reads);
    }

    public function test_a_run_that_loses_its_lease_stops_before_the_next_tombstone_and_leaves_the_cursor(): void
    {
        $this->storeCursor('cursor-0');
        $context = $this->app->make(IdentityTombstoneClient::class)->context();
        $this->handler->during = function () use ($context): void {
            // The handler outlives the lease and a second run takes over.
            $this->handler->during = null;
            $this->travel(IdentityTombstoneCursorStore::LEASE_SECONDS + 1)->seconds();
            $this->assertIsString($this->store()->acquire($context));
        };
        $this->provider([self::page([1, 2], 'cursor-1')]);

        [$code, $output] = $this->run_();

        $this->assertSame(1, $code);
        $this->assertSame([self::id(1)], $this->handler->ids(), 'Two runs never handle tombstones at once');
        $this->assertSame('cursor-0', $this->storedCursor());
        $this->assertStringContainsString('stopped: another run took over the lease', $output);
    }

    public function test_an_untrusted_provider_url_fails_before_anything_is_sent(): void
    {
        config(['bherila-auth.oauth_client.base_url' => 'http://identity.example.test']);
        Http::fake();

        [$code, $output] = $this->run_();

        $this->assertSame(1, $code);
        $this->assertStringContainsString('requires a trusted HTTPS base URL', $output);
        $this->assertStringNotContainsString('example-secret', $output);
        Http::assertNothingSent();
    }

    public function test_a_missing_table_fails_before_anything_is_sent(): void
    {
        config(['bherila-auth.identity_tombstones.table' => 'not_migrated']);
        Http::fake();

        [$code, $output] = $this->run_();

        $this->assertSame(1, $code);
        $this->assertStringContainsString('cursor table is not installed', $output);
        Http::assertNothingSent();
    }

    public function test_invalid_options_are_refused(): void
    {
        Http::fake();

        $this->assertSame(2, $this->run_(['--limit' => 101])[0]);
        $this->assertSame(2, $this->run_(['--limit' => 'all'])[0]);
        $this->assertSame(2, $this->run_(['--max-pages' => 0])[0]);
        Http::assertNothingSent();
    }
}
