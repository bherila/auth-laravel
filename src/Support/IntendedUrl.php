<?php

namespace BWH\Auth\Support;

use Illuminate\Http\Request;

/**
 * The `?redirect=` a sign-in page may return to, accepted only when it stays on this site.
 *
 * `redirect()->intended()` and the password form's JSON `redirect` both follow the stored
 * value without looking at its host. Storing a request parameter there unchecked makes
 * every sign-in link an open redirect: a link to `/login?redirect=https://elsewhere`
 * shows the real sign-in page and then sends the freshly authenticated person away.
 *
 * Two shapes are accepted: a path on this site (`/shops/12`), which the guest redirect
 * never sends but people and pages may, and an absolute URL on this request's own origin,
 * which is what `redirectGuestsTo()` sends. Anything else is dropped, never repaired, and
 * the caller falls back to its default landing page.
 */
final class IntendedUrl
{
    public static function remember(Request $request, string $parameter = 'redirect'): void
    {
        $value = $request->query($parameter);
        if (! is_string($value)) {
            return;
        }

        $url = self::sameSite($request, $value);
        if ($url === null) {
            return;
        }

        $request->session()->put('url.intended', $url);
    }

    /** The absolute same-origin URL for $value, or null when it would leave this site. */
    public static function sameSite(Request $request, string $value): ?string
    {
        // Backslashes are read as slashes by browsers (`/\elsewhere` is protocol-relative),
        // and control characters or spaces are stripped before parsing by some of them.
        if ($value === '' || strlen($value) > 2048 || preg_match('/[\\\\\x00-\x20\x7F]/', $value) === 1) {
            return null;
        }

        $root = $request->root();

        if (str_starts_with($value, '/')) {
            // `//host` is protocol-relative: another site.
            return str_starts_with($value, '//') ? null : $root.$value;
        }

        // The trailing slash keeps `https://site.example.evil` from passing as a prefix
        // match on `https://site.example`.
        if ($value === $root || str_starts_with($value, $root.'/') || str_starts_with($value, $root.'?')) {
            return $value;
        }

        return null;
    }
}
