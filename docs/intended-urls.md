# Intended sign-in destinations

`BWH\Auth\Support\IntendedUrl` validates destinations against the request's origin.
It accepts root-relative paths and absolute HTTP(S) URLs with the same scheme,
case-insensitive host and effective port. Explicit default ports are equivalent.
It rejects user information, protocol-relative URLs, raw spaces, controls and
backslashes. Paths, queries, fragments and percent escapes retain their spelling;
the returned origin is normalized to the request's origin.

`sameSite($request, $value)` returns an absolute URL or `null`.
`remember($request)` validates the `redirect` query parameter before storing it in
`url.intended`; invalid input leaves an existing destination alone.
`consume($request)` removes `url.intended` once and validates it, including values
stored by other middleware. Invalid or non-string values return `null`.

Use `absolute: false` with `sameSite` or `consume` to return a root-relative path.
Encoded characters remain accepted by default, including `%20` separating OAuth
scopes in a query. Consumers with a stricter existing destination policy can pass
`rejectEncodedUnsafe: true`: this also rejects controls, spaces, backslashes and
leading double slashes after one URL decode, without decoding the returned URL.

The default authentication policy uses `consume` for its fallback destination.
A model's explicit `getLoginRedirectUrl()` hook still takes priority and owns its
own destination validation. Application policies can preserve admission gates and
other landing priorities before calling `consume`.
