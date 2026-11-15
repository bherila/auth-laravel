<?php

namespace BWH\Auth\Http\Middleware;

use BWH\Auth\OAuth\AuthenticationRequirement;
use BWH\Auth\OAuth\Session\AuthenticationContext;
use Closure;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Symfony\Component\HttpFoundation\Response;

/**
 * Require a recent password confirmation, answering JSON 423 when it is missing or stale.
 *
 * ```php
 * Route::middleware(['auth', RequirePasswordConfirmation::class])->...;
 * Route::middleware(['auth', RequirePasswordConfirmation::class.':900'])->...; // 15 minutes
 * ```
 *
 * Laravel's `password.confirm` redirects to a confirmation page whenever the request does not
 * ask for JSON, which a fetch-based client (the `bwh-auth` passkey component, for one) does
 * not; this always answers JSON. The client confirms with `POST {prefix}/auth/confirm-password`
 * and retries.
 *
 * Satisfied by Laravel's standard session confirmation (`auth.password_confirmed_at`, set by
 * the package endpoint, Fortify, or `$request->session()->passwordConfirmed()`), or by a
 * provider authentication of this account within the same window
 * ({@see AuthenticationContext}): an account that signs in through the identity provider
 * holds only a random local password nobody knows, and re-authenticating at the provider is
 * the equivalent proof. A user-verified assertion of one of this account's own passkeys
 * ({@see self::recordPasskeyConfirmation()}: a passkey sign-in, or
 * `POST {prefix}/passkeys/confirm`) counts too, so an account that only uses passkeys, whose
 * local password is random or unknown, can still confirm. The window is
 * `bherila-auth.password_confirmation.timeout` seconds, or `auth.password_timeout` (Laravel's
 * default, three hours) when that is null.
 */
final class RequirePasswordConfirmation
{
    public const string ERROR = 'password_confirmation_required';

    /**
     * When this session last proved its account with a user-verified passkey assertion:
     * `{account: string, at: int}`. Bound to the account, and read only by this middleware,
     * not by Laravel's `password.confirm`.
     */
    public const string PASSKEY_SESSION_KEY = 'bherila_auth.passkey_confirmed';

    public function handle(Request $request, Closure $next, ?string $seconds = null): Response
    {
        return self::refusal($request, $seconds === null ? null : max(1, (int) $seconds)) ?? $next($request);
    }

    /** Whether this session confirmed the signed-in account recently enough. */
    public static function confirmed(Request $request, ?int $timeout = null): bool
    {
        $timeout ??= self::timeout();
        $user = $request->user();

        if ($user === null || ! $request->hasSession()) {
            return false;
        }

        $confirmedAt = $request->session()->get('auth.password_confirmed_at');
        if (is_numeric($confirmedAt) && Carbon::now()->getTimestamp() - (int) $confirmedAt < $timeout) {
            return true;
        }

        $passkey = $request->session()->get(self::PASSKEY_SESSION_KEY);
        if (is_array($passkey)
            && ($passkey['account'] ?? null) === (string) $user->getAuthIdentifier()
            && is_int($passkey['at'] ?? null)
            && Carbon::now()->getTimestamp() - $passkey['at'] < $timeout) {
            return true;
        }

        return AuthenticationContext::satisfies($request, $user, new AuthenticationRequirement(maxAge: $timeout));
    }

    /**
     * Record that this session just proved `$user` with a user-verified assertion of one of
     * that account's own passkeys. Call only after the assertion has been verified, and only
     * when the authenticator reported user verification: presence alone proves possession of
     * a device, not the person.
     */
    public static function recordPasskeyConfirmation(Request $request, Authenticatable $user): void
    {
        $request->session()->put(self::PASSKEY_SESSION_KEY, [
            'account' => (string) $user->getAuthIdentifier(),
            'at' => Carbon::now()->getTimestamp(),
        ]);
    }

    /** The 423 answer when the confirmation is missing or stale; null when it is fresh. */
    public static function refusal(Request $request, ?int $timeout = null): ?JsonResponse
    {
        if (self::confirmed($request, $timeout)) {
            return null;
        }

        return new JsonResponse([
            'success' => false,
            'message' => 'Confirm your password to continue.',
            'error' => self::ERROR,
        ], Response::HTTP_LOCKED, ['Cache-Control' => 'private, no-store']);
    }

    /** How long a confirmation lasts, in seconds. */
    public static function timeout(): int
    {
        $configured = config('bherila-auth.password_confirmation.timeout');

        return max(1, (int) ($configured ?? config('auth.password_timeout', 10800)));
    }
}
