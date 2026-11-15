<?php

namespace BWH\Auth\Support;

use Illuminate\Auth\SessionGuard;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\QueryException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

/**
 * Ends an account's other sessions after the package changes or resets its password
 * (`bherila-auth.sessions.end_other_sessions_on_password_change`, on by default).
 *
 * - The remember token is rotated, so a remember-me cookie issued under the old password,
 *   on any device, stops working. The device making the change gets its cookie reissued.
 * - With the `database` session driver, the account's other session rows are deleted.
 * - Any other driver cannot be enumerated. Laravel's `authenticateSessions()` middleware
 *   ends those sessions instead: each stores the password hash it signed in with, and the
 *   session that made the change stores the new one. Applications must enable it.
 */
final class PasswordChangeSessions
{
    public static function enabled(): bool
    {
        return (bool) config('bherila-auth.sessions.end_other_sessions_on_password_change', true);
    }

    /**
     * The remember-token attribute to save with the new password, when the account has a
     * token to retire. An account with no token has no cookie to retire, so none is minted.
     *
     * @return array<string, string>
     */
    public static function rotatedRememberToken(Authenticatable $user): array
    {
        $name = $user->getRememberTokenName();

        // getRememberToken() casts a missing token to ''.
        if (! self::enabled() || ! is_string($name) || $name === '' || in_array($user->getRememberToken(), [null, ''], true)) {
            return [];
        }

        return [$name => Str::random(60)];
    }

    /**
     * After the new password is saved: reissue this device's remember-me cookie and end the
     * account's other database sessions.
     */
    public static function endOthers(Request $request, Authenticatable $user, #[\SensitiveParameter] string $newPassword): void
    {
        if (! self::enabled()) {
            return;
        }

        self::reissueRememberCookie($request, $user, $newPassword);
        self::deleteOtherDatabaseSessions($request, $user);
    }

    /**
     * The changing device keeps "remember me": its cookie carries the rotated token and the
     * new password hash. Laravel's own API for exactly this, which also announces
     * OtherDeviceLogout; it rehashes the (already new) password once more as it does.
     */
    private static function reissueRememberCookie(Request $request, Authenticatable $user, string $newPassword): void
    {
        $guard = Auth::guard();

        if (! $guard instanceof SessionGuard
            || $guard->user()?->getAuthIdentifier() !== $user->getAuthIdentifier()
            || (! $request->cookies->has($guard->getRecallerName()) && ! $guard->getCookieJar()->hasQueued($guard->getRecallerName()))) {
            return;
        }

        $guard->logoutOtherDevices($newPassword);
    }

    private static function deleteOtherDatabaseSessions(Request $request, Authenticatable $user): void
    {
        if (config('session.driver') !== 'database') {
            return;
        }

        $connection = DB::connection(config('session.connection'));
        $table = (string) config('session.table', 'sessions');
        $current = $request->hasSession() ? $request->session()->getId() : null;

        try {
            if (! $connection->getSchemaBuilder()->hasColumn($table, 'user_id')) {
                return;
            }

            $connection->table($table)
                ->where('user_id', $user->getAuthIdentifier())
                ->when($current !== null, fn ($query) => $query->where('id', '!=', $current))
                ->delete();
        } catch (QueryException $exception) {
            // The password has already changed; failing the request now would hide that.
            // Sessions still end through authenticateSessions() where it is enabled.
            report($exception);
        }
    }
}
