<?php

namespace BWH\Auth\Support;

use BWH\Auth\Models\TwoFactorAttempt;
use Closure;
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\RateLimiter;
use InvalidArgumentException;

/**
 * The named rate limiters on the package's own routes.
 *
 * Each limiter keys its own buckets: an unprefixed `throttle:N,M` shares one per-user (or
 * per-IP) counter with every other unprefixed throttle in the application, so a route that
 * sends mail or checks a credential gets a named limiter here instead. Within one limiter,
 * every dimension (`ip`, `email`, `account`, `attempt`) is a separate bucket, and a request
 * is refused when any of them is exhausted.
 *
 * Limits come from `bherila-auth.rate_limits`: each dimension is `[max attempts, decay
 * minutes]`, or null to leave that dimension unlimited; `rate_limits.enabled = false` leaves
 * every limiter here unlimited. An application that defines a limiter of the same name keeps
 * its own, whether it defines it before this package boots or after.
 *
 * Addresses and challenge tokens are hashed before they become cache keys, so the cache
 * never holds a mailbox or a live sign-in token.
 */
final class RateLimits
{
    /** `POST {prefix}/auth/two-factor/verify`: per IP and per challenge token. */
    public const string TWO_FACTOR_VERIFY = 'bherila-auth.two-factor-verify';

    /** `POST {prefix}/auth/two-factor/resend`: per IP and per account (each resend emails a code). */
    public const string TWO_FACTOR_RESEND = 'bherila-auth.two-factor-resend';

    /** `POST {prefix}/auth/forgot-password`: per IP and per address (each request can email a link). */
    public const string FORGOT_PASSWORD = 'bherila-auth.forgot-password';

    /** `POST {prefix}/auth/reset-password`: per IP and per address (checks a reset token). */
    public const string RESET_PASSWORD = 'bherila-auth.reset-password';

    /** `POST {prefix}/change-password`: per IP and per account (checks the current password). */
    public const string CHANGE_PASSWORD = 'bherila-auth.change-password';

    /** `POST {prefix}/auth/confirm-password`: per IP and per account (checks the password). */
    public const string CONFIRM_PASSWORD = 'bherila-auth.confirm-password';

    /** Issuing personal API tokens and OAuth apps (`oauth_server.credentials`): per account. */
    public const string CREDENTIALS = 'bherila-auth.credentials';

    public static function register(): void
    {
        self::define(self::TWO_FACTOR_VERIFY, static fn (Request $request): Limit|array => self::limits('two_factor_verify', [
            'ip' => self::ip($request),
            'attempt' => self::hashed(self::attemptToken($request)),
        ]));

        self::define(self::TWO_FACTOR_RESEND, static fn (Request $request): Limit|array => self::limits('two_factor_resend', [
            'ip' => self::ip($request),
            'account' => self::challengedAccount($request),
        ]));

        self::define(self::FORGOT_PASSWORD, static fn (Request $request): Limit|array => self::limits('forgot_password', [
            'ip' => self::ip($request),
            'email' => self::emailKey($request),
        ]));

        self::define(self::RESET_PASSWORD, static fn (Request $request): Limit|array => self::limits('reset_password', [
            'ip' => self::ip($request),
            'email' => self::emailKey($request),
        ]));

        self::define(self::CHANGE_PASSWORD, static fn (Request $request): Limit|array => self::limits('change_password', [
            'ip' => self::ip($request),
            'account' => self::account($request),
        ]));

        self::define(self::CONFIRM_PASSWORD, static fn (Request $request): Limit|array => self::limits('confirm_password', [
            'ip' => self::ip($request),
            'account' => self::account($request),
        ]));

        self::define(self::CREDENTIALS, static fn (Request $request): Limit|array => self::limits('credentials', [
            'account' => self::account($request),
        ]));
    }

    /** The `throttle` middleware for one of these limiters. */
    public static function middleware(string $name): string
    {
        return 'throttle:'.$name;
    }

    /**
     * A per-address bucket key that does not keep the address itself in the cache.
     *
     * Case and surrounding space are folded, so `Person@Example.test ` and
     * `person@example.test` share one bucket. A request without an address shares the
     * empty-address bucket, which validation then refuses anyway.
     */
    public static function emailKey(Request $request): string
    {
        $email = $request->input('email');

        return hash('sha256', is_string($email) ? mb_strtolower(trim($email)) : '');
    }

    private static function define(string $name, Closure $callback): void
    {
        if (RateLimiter::limiter($name) === null) {
            RateLimiter::for($name, $callback);
        }
    }

    /**
     * @param  array<string, string|null>  $keys  dimension => bucket key; null skips the dimension
     * @return Limit|list<Limit>
     */
    private static function limits(string $setting, array $keys): Limit|array
    {
        if (! (bool) config('bherila-auth.rate_limits.enabled', true)) {
            return Limit::none();
        }

        $limits = [];
        foreach ($keys as $dimension => $key) {
            $configured = config("bherila-auth.rate_limits.{$setting}.{$dimension}");
            if ($key === null || $configured === null) {
                continue;
            }

            [$maxAttempts, $decayMinutes] = self::parse($setting, $dimension, $configured);
            $limits[] = Limit::perMinutes($decayMinutes, $maxAttempts)->by($dimension.':'.$key);
        }

        return $limits === [] ? Limit::none() : $limits;
    }

    /** @return array{int, int} */
    private static function parse(string $setting, string $dimension, mixed $configured): array
    {
        $values = is_array($configured) ? array_values($configured) : [];

        // A limit that cannot be read fails loudly rather than open: a typo must not quietly
        // remove the protection, and must not refuse every request either.
        if (count($values) !== 2 || ! is_int($values[0]) || ! is_int($values[1]) || $values[0] < 1 || $values[1] < 1) {
            throw new InvalidArgumentException("bherila-auth.rate_limits.{$setting}.{$dimension} must be [max attempts, decay minutes] with positive integers, or null.");
        }

        return [$values[0], $values[1]];
    }

    private static function ip(Request $request): string
    {
        return (string) $request->ip();
    }

    private static function account(Request $request): ?string
    {
        $identifier = $request->user()?->getAuthIdentifier();

        return is_scalar($identifier) ? (string) $identifier : null;
    }

    private static function attemptToken(Request $request): ?string
    {
        $token = $request->input('attempt_token');

        return is_string($token) && $token !== '' ? $token : null;
    }

    /** The account a resend would email, when the challenge token names one. */
    private static function challengedAccount(Request $request): ?string
    {
        $token = self::attemptToken($request);
        if ($token === null) {
            return null;
        }

        $userId = TwoFactorAttempt::query()->where('token', $token)->value('user_id');

        return is_scalar($userId) ? (string) $userId : null;
    }

    private static function hashed(?string $value): ?string
    {
        return $value === null ? null : hash('sha256', $value);
    }
}
