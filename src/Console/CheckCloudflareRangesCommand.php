<?php

namespace BWH\Auth\Console;

use BWH\Auth\Http\TrustedProxies;
use Closure;
use Illuminate\Console\Command;

/**
 * Fail when the trusted Cloudflare ranges no longer match the published ones.
 *
 * Meant for a scheduled CI job: a stale list fails quietly - clients arriving
 * through a new edge are keyed on that edge's address and share one budget -
 * so it has to fail loudly somewhere.
 */
class CheckCloudflareRangesCommand extends Command
{
    public const array SOURCES = ['https://www.cloudflare.com/ips-v4', 'https://www.cloudflare.com/ips-v6'];

    protected $signature = 'bherila-auth:check-cloudflare-ranges';

    protected $description = 'Compare the trusted Cloudflare ranges with the published list; exit non-zero on drift.';

    /** @var (Closure(string): (string|false))|null Replaces the network fetch in tests. */
    public static ?Closure $fetcher = null;

    public function handle(): int
    {
        $published = [];
        foreach (self::SOURCES as $url) {
            $body = (self::$fetcher ?? static fn (string $url): string|false => @file_get_contents($url, false, stream_context_create(['http' => ['timeout' => 10]])))($url);
            if (! is_string($body) || trim($body) === '') {
                $this->error("Could not fetch {$url}.");

                return 2;
            }
            foreach (preg_split('/\s+/', trim($body)) ?: [] as $range) {
                if ($range !== '') {
                    $published[] = $range;
                }
            }
        }

        $pinned = TrustedProxies::cloudflareRanges();
        sort($pinned);
        sort($published);
        $add = array_values(array_diff($published, $pinned));
        $remove = array_values(array_diff($pinned, $published));
        if ($add === [] && $remove === []) {
            $this->info('The trusted Cloudflare ranges match the published list ('.count($pinned).' ranges).');

            return self::SUCCESS;
        }

        $this->error('The trusted Cloudflare ranges are out of date with the published list.');
        foreach ($add as $range) {
            $this->line("  add:    {$range}");
        }
        foreach ($remove as $range) {
            $this->line("  remove: {$range}");
        }

        return self::FAILURE;
    }
}
