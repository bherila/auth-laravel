# Several authorization servers

`BWH\Auth\OAuth\OAuthClient` signs people in through one provider, the top-level
`oauth_client` settings. An application can also be an OAuth client of other
authorization servers, for example to call a sibling application's API for the person who
connected it. Each of those is an entry of `oauth_client.servers`.

Being a client of more than one server opens the issuer mix-up attack: a response, or a code,
from one server is presented as if it came from another, and the code (with the PKCE
verifier) is sent to the wrong token endpoint. The client defends against it in three
independent ways: each server has its own callback, each pending flow is bound to the server
it was sent to, and RFC 9207 `iss` is checked before any code is exchanged.

## Configure a server

```php
// config/bherila-auth.php
'oauth_client' => [
    // ... the sign-in provider, unchanged ...
    'servers' => [
        'svc' => [
            'issuer' => env('SVC_OAUTH_ISSUER'),          // exact, e.g. https://svc.example.com
            'client_id' => env('SVC_OAUTH_CLIENT_ID'),
            'client_secret' => env('SVC_OAUTH_CLIENT_SECRET'),
            'redirect_uri' => rtrim((string) env('APP_URL'), '/').'/connections/svc/callback',
            'scope' => 'finance:read identity:read',
            'resource' => env('SVC_OAUTH_RESOURCE'),       // RFC 8707, optional
            'authorization_response_iss' => 'advertised',  // the default for named servers
        ],
    ],
],
```

| Key | Default | Meaning |
|---|---|---|
| `issuer` | required | The server's exact issuer identifier (RFC 8414): `http(s)`, no query, fragment or credentials. Compared byte for byte with `iss`. |
| `client_id`, `client_secret`, `scope` | required | This application's confidential client at that server. |
| `redirect_uri` | required | This server's own callback. Two servers, or a server and the sign-in provider, sharing one is a 503. |
| `resource` | none | Sent as `resource` on the authorization request, the code exchange and every refresh. Any absolute URI without a fragment (RFC 8707), for example `https://svc.example.com/api/v1` or `urn:example:payments`. |
| `authorization_response_iss` | `advertised` | `required`: refuse a response without `iss`. `advertised`: require it when the metadata at the issuer advertises `authorization_response_iss_parameter_supported`. `when_present`: only check it when sent. A present `iss` is always checked. |
| `base_url` | `issuer` | Where the paths below are appended. |
| `authorize_path`, `token_path` | `/oauth/authorize`, `/oauth/token` | |
| `identity_path` | none | Only for `identityFromCallback()` on this server. |
| `provider` | the key | The provider name an `OAuthIdentity` from this server carries. |

`default` is the sign-in provider's name and cannot be used as a server key. Names are
letters, digits, `_` and `-`, up to 64 characters; an all-digit name such as `1` works too.

Every endpoint comes from configuration. With `advertised`, the RFC 8414 document at the
configured issuer (`/.well-known/oauth-authorization-server`, with the issuer's path appended
after it) is read when a flow starts, must name exactly that issuer, and only its
`authorization_response_iss_parameter_supported` flag is used; the answer is cached for
`oauth_client.metadata_cache_seconds` (3600). A document that cannot be read or names another
issuer is a 503 before the person is sent anywhere.

Shared settings: `oauth_client.pending_flow_ttl` (1800 seconds) is how long a flow may wait for
its response. Named pending flows are cached under a SHA-256 hash of their random state, using
`oauth_client.pending_flow_cache_store` (`BHERILA_AUTH_OAUTH_PENDING_FLOW_CACHE_STORE`), or
Laravel's configured default cache store when null. Use a persistent store shared by all
processes serving connect callbacks, with atomic lock support. A callback consumes its entry
under a lock on the same store before checking bindings or exchanging a code. Cache expiry,
eviction or flushing refuses the flow; it never falls back to session attributes.

This prevents a stale session save from erasing a pending connect flow or reviving one already
consumed. The existing user binding remains required, including refusal after signing out or
switching users. Named flows are no longer tied to session attributes; the default sign-in
flow retains its legacy session keys. Named flows already pending in session at deployment
must be restarted.

## Connect and complete

```php
public function connect(Request $request, OAuthClient $oauth): RedirectResponse
{
    return $oauth->forServer('svc')->redirect($request);
}

// Routed at exactly the path of servers.svc.redirect_uri.
public function callback(Request $request, OAuthClient $oauth): RedirectResponse
{
    try {
        $tokens = $oauth->forServer('svc')->tokensFromCallback($request);
    } catch (OAuthCallbackRejected $rejected) {
        // $rejected->reason is an OAuthCallbackFailure; $rejected->providerError is the
        // server's OAuth error code for AuthorizationDenied (for example access_denied).
        return redirect()->route('connections')->withErrors(['svc' => 'The connection was not completed.']);
    }

    // Before storing anything: confirm the token's owner is the person who connected.
    $reported = Http::withToken($tokens->accessToken)->get(/* the server's own "who am I" */)->json('provider_subject');
    abort_unless(SameSubject::matchesUser($request->user(), config('bherila-auth.oauth_client.provider'), $reported), 403);

    // Store $tokens->accessToken, ->refreshToken, ->expiresAt, ->scopes, ->resource encrypted.
}
```

`OAuthTokens` carries the server name, issuer, resource, access and refresh tokens, expiry and
granted scopes. When a code exchange's response omits `scope`, the scopes are the ones that
flow requested (RFC 6749 §5.1), recorded when it started, not the setting at callback time; for
a sign-in flow begun before that was recorded they are null. Access and refresh tokens must be
`1*VSCHAR` (printable ASCII and space, RFC 6749 Appendix A); anything else is refused as a
malformed response. Its token values are redacted from `var_dump`/`print_r`, and the token request's
parameters are `#[\SensitiveParameter]`, so the client secret, code, verifier and refresh token
never appear in an exception trace.

### What is checked, in order

The response is refused with `OAuthCallbackRejected` (a 403) before its code leaves the
application unless every check passes:

1. `state_mismatch`: the named-flow cache has a pending flow for the response's `state`. The
   flow is consumed now, whatever follows, so concurrent callbacks and restored session
   snapshots cannot replay it. An expired or evicted entry is missing and is refused here.
2. `expired`: the flow is younger than `pending_flow_ttl`.
3. `server_mismatch`: the flow was started for this server, and its issuer, callback and
   resource are still this server's settings.
4. `callback_mismatch`: the request arrived at the path of this server's `redirect_uri`.
5. `user_mismatch`: the signed-in person (or guest) is the one who started the flow.
6. `issuer_mismatch` / `issuer_missing`: RFC 9207. A present `iss` must equal the flow's
   issuer exactly, read from the raw query string; a missing one is refused when expected.
   This applies to error responses too.
7. `authorization_denied`: the server answered with `error`. `providerError` is its value when
   it fits RFC 6749's grammar (printable ASCII other than `"` and `\`, at most 64
   characters), else null. It is still another server's text: escape it when displaying it.
8. `code_missing`.

The code is then exchanged at the configured token endpoint with the flow's verifier, callback
and resource. A refusal, or a response without a bearer `access_token`, is an
`OAuthTokenRequestFailed` (a 502).

Several named flows (to different servers, or in several tabs) can be pending independently
until their cache TTL expires; session saves do not overwrite them.

## Refresh

```php
$tokens = $oauth->forServer('svc')->refreshTokens($stored->refreshToken, $stored->scopes);
```

Sends the refresh grant with the client credentials and configured resource. A server that does
not rotate refresh tokens omits `refresh_token`; the one you sent stays valid (RFC 6749 §6), and
`$tokens->refreshToken` is that token, so storing the result always keeps a usable refresh
token. Compare it with the stored one if you only want to write on rotation. A refresh token
that is empty or not `1*VSCHAR`, or granted scopes that are not a list of scope tokens, throw
`InvalidArgumentException` before anything is sent. A response that
omits `scope` leaves the grant unchanged (RFC 6749 §6): `$tokens->scopes` is then the granted
scopes you passed, or null if you passed none. It is never filled from the configured `scope`,
which may be broader than what was granted. A server that
rotates refresh tokens revokes the whole family when an old one is reused, so persist the new
token in the same transaction that read the old one (lock the row). On
`OAuthTokenRequestFailed`, `$definitive` false (a 5xx, a dropped connection, or a success
response without a usable bearer token) means the server may already have rotated: mark the
connection for reconnection rather than retrying with the old token. `$oauthError` carries the
error code (such as `invalid_grant`) when it fits RFC 6749's grammar.

## Same subject

`SameSubject::matches($trustedProvider, $boundProvider, $boundSubject, $reportedProvider,
$reportedSubject)` is true only when both providers are the trusted one and both subjects are
the same non-empty value, byte for byte (an integer is compared as its decimal string).
`SameSubject::matchesUser($user, $reportedProvider, $reportedSubject)` reads the user's binding
through the bound `ProviderBindingResolver` under `oauth_client.provider`; an unbound or broken
binding never matches, so an owner with no bound subject cannot connect.

The reported provider is the provider the other application says the subject belongs to. When
its API reports only a subject, pass the trusted provider name only if that application signs
people in through the same identity provider.

## The sign-in provider

The sign-in flow is unchanged in use. Its pending state and verifier stay under
`oauth.login.state` and `oauth.login.code_verifier`, so sessions seeded that way (in an
application's tests, or started before an upgrade) still complete. It now also:

- checks a present `iss` against `oauth_client.issuer` (`OAUTH_PROVIDER_ISSUER`), which
  defaults to `base_url`; set `authorization_response_iss` (`OAUTH_AUTHORIZATION_RESPONSE_ISS`)
  to `required` or `advertised` once the provider sends it;
- binds a newly started flow to the signed-in person (normally a guest) and refuses it after
  `pending_flow_ttl`;
- throws `OAuthCallbackRejected` and `OAuthTokenRequestFailed`, which are the same 403 and 502
  with the same messages as before; an unreachable token endpoint is now a 502 rather than an
  uncaught connection error.

Its callback route is not checked against `redirect_uri`, as before.
