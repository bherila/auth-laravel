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

    /** Consume the stored destination once, validating even values stored by other middleware. */
    public static function consume(Request $request, bool $absolute = true, bool $rejectEncodedUnsafe = false): ?string
    {
        $value = $request->session()->pull('url.intended');

        return is_string($value) ? self::sameSite($request, $value, $absolute, $rejectEncodedUnsafe) : null;
    }

    /**
     * The normalized same-origin URL, or its root-relative path when $absolute is false.
     * $rejectEncodedUnsafe additionally applies the raw-character checks after one URL decode.
     */
    public static function sameSite(Request $request, string $value, bool $absolute = true, bool $rejectEncodedUnsafe = false): ?string
    {
        // Backslashes are read as slashes by browsers (`/\elsewhere` is protocol-relative),
        // and control characters or spaces are stripped before parsing by some of them.
        if ($value === '' || strlen($value) > 2048 || preg_match('/[\\\\\x00-\x20\x7F]/', $value) === 1) {
            return null;
        }

        // An authority without a scheme remains protocol-relative, even on this host.
        if (str_starts_with($value, '//')) {
            return null;
        }

        $parts = parse_url($value);
        if ($parts === false || isset($parts['user']) || isset($parts['pass'])) {
            return null;
        }
        if (isset($parts['scheme']) || isset($parts['host'])) {
            $scheme = strtolower($parts['scheme'] ?? '');
            $port = $parts['port'] ?? ($scheme === 'https' ? 443 : 80);
            if ($scheme !== $request->getScheme()
                || strtolower($parts['host'] ?? '') !== strtolower($request->getHost())
                || $port !== $request->getPort()) {
                return null;
            }
        }

        $local = ($parts['path'] ?? '/').(isset($parts['query']) ? '?'.$parts['query'] : '')
            .(isset($parts['fragment']) ? '#'.$parts['fragment'] : '');
        if (! str_starts_with($local, '/') || str_starts_with($local, '//')) {
            return null;
        }
        if ($rejectEncodedUnsafe) {
            $decoded = rawurldecode($local);
            if (str_starts_with($decoded, '//') || preg_match('/[\\\\\x00-\x20\x7F]/', $decoded) === 1) {
                return null;
            }
        }

        return $absolute ? $request->getSchemeAndHttpHost().$local : $local;
    }
}
