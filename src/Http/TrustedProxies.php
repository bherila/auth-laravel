<?php

namespace BWH\Auth\Http;

use Illuminate\Http\Middleware\TrustProxies;
use Illuminate\Http\Request;

/**
 * Which proxies may tell the application who its client is.
 *
 * Every per-client limit - login throttling, client registration, token
 * exchange, API throttles - keys on Request::ip(). Behind a CDN that is the
 * edge's address unless the edge is trusted, so every client behind one edge
 * shares one budget. Trusting too much is worse: an origin that also answers
 * direct connections would let anyone forge their address with a header.
 *
 * So only the CDN's published ranges are trusted, and only X-Forwarded-For
 * and its scheme - never the forwarded port or host. Symfony then takes the
 * rightmost address that is not a trusted proxy, which is the one the edge
 * appended; anything a client wrote further left is ignored.
 *
 * Opt in with `bherila-auth.trusted_proxies.apply`. `trusted` accepts
 * `cloudflare` (the default), an explicit comma-separated list of addresses or
 * CIDR ranges, `*` (only where a firewall admits the proxy alone), or empty to
 * trust nothing - which is right for a deployment with no proxy in front.
 */
final class TrustedProxies
{
    /**
     * Published at https://www.cloudflare.com/ips-v4 and /ips-v6. The
     * `bherila-auth:check-cloudflare-ranges` command reports drift; a stale list
     * fails quietly into "clients on a new edge share its address".
     *
     * @var list<string>
     */
    public const array CLOUDFLARE = [
        '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
        '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
        '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
        '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
        '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32',
        '2405:8100::/32', '2a06:98c0::/29', '2c0f:f248::/32',
    ];

    /**
     * The client address and scheme only. Cloudflare overwrites
     * X-Forwarded-For (appending) and X-Forwarded-Proto, but passes a
     * client-supplied X-Forwarded-Port through, so trusting the port would let
     * a visitor choose the port in generated absolute URLs.
     */
    public const int HEADERS = Request::HEADER_X_FORWARDED_FOR
        | Request::HEADER_X_FORWARDED_PROTO;

    /**
     * Resolve a TRUSTED_PROXIES setting into what TrustProxies::at() accepts.
     *
     * @param  list<string>|null  $cloudflare  the ranges `cloudflare` expands to
     * @return list<string>|string|null null when nothing is trusted
     */
    public static function resolve(mixed $setting, ?array $cloudflare = null): array|string|null
    {
        if (! is_string($setting) || trim($setting) === '') {
            return null;
        }
        $setting = trim($setting);
        if ($setting === '*' || $setting === '**') {
            return $setting;
        }

        $proxies = [];
        foreach (explode(',', $setting) as $entry) {
            $entry = trim($entry);
            if ($entry === 'cloudflare') {
                array_push($proxies, ...($cloudflare ?? self::CLOUDFLARE));
            } elseif ($entry !== '') {
                $proxies[] = $entry;
            }
        }

        return $proxies === [] ? null : array_values(array_unique($proxies));
    }

    /** The ranges `cloudflare` expands to: configured, or the shipped list. */
    /** @return list<string> */
    public static function cloudflareRanges(): array
    {
        $configured = config('bherila-auth.trusted_proxies.cloudflare');

        return is_array($configured) && $configured !== []
            ? array_values(array_map('strval', $configured))
            : self::CLOUDFLARE;
    }

    /** Apply the configured setting to Laravel's TrustProxies middleware. */
    public static function apply(): void
    {
        $proxies = self::resolve(config('bherila-auth.trusted_proxies.trusted'), self::cloudflareRanges());
        if ($proxies === null) {
            // "Trust nothing" has to undo trust configured elsewhere - a `*`
            // left over from bootstrap would otherwise stay in force. An empty
            // list cannot say it (Laravel reads [] as "not set"), so clear it.
            TrustProxies::flushState();

            return;
        }

        TrustProxies::at($proxies);
        TrustProxies::withHeaders(self::HEADERS);
    }
}
