# Provider browser-session verification

These helpers are opt-in. Installing the package does not add middleware, end
local sessions or change application login policy. They implement the consumer
side of the provider's identity-status contract; the provider status endpoint
must be deployed before enabling enforcement.

## Quick start

1. In the login callback, after binding the account by provider and subject and
   calling `Auth::login()` and `session()->regenerate()`:

   ```php
   try {
       app(ProviderSession::class)->establish($request, $identity, Auth::guard());
   } catch (ProviderStatusUnavailable) {
       abort(503, 'Sign-in verification is unavailable. Please retry.');
   }
   ```

2. Add `RequireActiveProviderSession` after authentication on every
   session-authenticated route (for example, append it to the `web` group, or
   use it alongside `auth`). Pass guard names as parameters if the route does
   not use the default guard. A session holds one provider login: guards that
   share a session must be signed in as the same provider subject. Sign-out routes
   named in `provider_identity.except_routes` (default `logout`) are let through,
   so a person can always end their session during an outage. The default
   `ColumnProviderBindingResolver` reads Eloquent models; bind your own resolver
   for guards whose users are not Eloquent models.
3. If the account's binding does not live in `oauth_provider` / `oauth_subject`
   columns, bind your own `ProviderBindingResolver`, or rename the columns in
   `bherila-auth.provider_identity.binding`.
4. Use a cache store shared by every web worker
   (`bherila-auth.provider_identity.cache_store`), then set
   `BHERILA_AUTH_PROVIDER_IDENTITY_ENABLED=true`.
5. Once enforcement is verified, record the cutover so it cannot be switched off by
   configuration alone: see [locking enforcement after cutover](#locking-enforcement-after-cutover).

`establish()` remembers the login generation even while enforcement is off, so
sessions started after deploying step 1 survive turning enforcement on. Sessions
started before it have no baseline and are asked to sign in again once.

The middleware implements the consumer actions described below: an ended identity
logs out the guard, invalidates the session, regenerates the CSRF token and
redirects (`expired_redirect_route`) or answers JSON 401; an unavailable provider
answers 503 with `Retry-After` and keeps the session. Applications that need
different responses can call `ProviderSession::assertActive()` themselves.

## Remember-me and other sign-in methods

A session restored from a remember-me cookie, and a session started through a sign-in method
other than this provider (a social login), carry no baseline from a provider sign-in. Without
one, enforcement ends them on their first protected request.

**Remember-me.** Call `prepareRememberedLogin()` before the login that sets the cookie, then
`establish()` as usual. `RelyingPartyLoginController` does this when `$remember` is true.

```php
$session = app(ProviderSession::class);
$session->prepareRememberedLogin($request, $guard, $account,
    $identity->provider, $identity->subject, $identity->credentialVersion);
$guard->login($account, remember: true);
$request->session()->regenerate();
$session->establish($request, $identity, $guard);
```

The baseline is recorded in `provider_remembered_logins`, one row per guard and account, with the
token stored only as a SHA-256 hash. When the guard later restores a session from that cookie,
the package's `Login` listener gives the restored session the recorded baseline. Its first
protected request then checks the provider, so a reset, disable or ungrant since the login still
ends it.

- Laravel keeps one remember token per account, shared by every device.
  `prepareRememberedLogin()` replaces that token unless it is already recorded under exactly this
  login's baseline. A cookie issued under an earlier generation, before a password reset say, then
  stops working rather than coming back under the new baseline. As a result, the first remembered
  sign-in of each account after adopting this replaces its token, and that account's other
  devices sign in again once.
- A remembered login made without `prepareRememberedLogin()` records nothing. While enforcement
  is on, its restored sessions are asked to sign in again. A restored session reports the identity
  with empty name and email: the login-time projection is not kept.
- Publish and run the migration (`2026_11_23_000000_create_provider_remembered_logins_table`).
  Until it runs nothing is recorded and remember-me behaves as it did before this change. Call
  `RememberedProviderLogins::forgetUser($id)` when deleting an account.

**Other sign-in methods.** For an account bound to the provider that signs in some other way, ask
the provider first:

```php
$session = app(ProviderSession::class);
try {
    $observation = $session->observe($binding);   // null while enforcement is off and the check fails
} catch (ProviderSessionExpired) {
    // The provider has ended this identity: refuse the sign-in.
}
// ProviderStatusUnavailable propagates as a retryable 503.
if ($observation !== null && $remember) {
    $session->prepareRememberedLogin($request, $guard, $user,
        $observation->provider, $observation->subject, $observation->generation);
}
$guard->login($user, $remember);
$request->session()->regenerate();
if ($observation !== null) {
    $session->establishObserved($request, $guard, $observation, $name, $email);
}
```

`observe()` always makes a fresh status request, including while enforcement is off, so that
baselines exist before it is turned on. The baseline is the identity's current generation. That
is safe only because the sign-in is happening now. Never use it to fill in a login that happened
earlier.

## Recovery epoch

Restoring the identity provider's database from a backup rolls its credential generations
back. A session or token captured before a password reset or a disable could then match the
restored answer and work again. To stop that, a provider reports a `recovery_epoch` in the
sign-in identity and identity-status responses: a whole number kept outside its database and
raised on every restore.

- The epoch is captured with the generation:
  - in the session baseline at sign-in, and in `establishObserved()`;
  - on remembered logins;
  - on authorization codes and access and refresh tokens (`provider_epoch`).

  A token minted from a code or refresh token inherits its epoch.
- Every check that compares the generation also compares a captured epoch. A raised epoch ends
  the session or credential. So does a provider that stops reporting one: the sign-out is the
  usual one, a bearer gets 401 and a refresh gets `invalid_grant`. Everyone signs in again
  after a restore, against the restored data.
- Anything captured with no epoch is not compared: credentials from before the provider sent
  one, or from a provider that sends none. It keeps working until it ends on its own.
- Run the migration `2026_11_24_000000_add_provider_epoch_columns`. Until it runs, credentials
  and remembered logins are recorded without an epoch. Browser sessions need no migration.

Provider subjects are opaque strings: an existing account's subject may be its decimal id,
and a newer account's a random ULID. Never parse or compare a subject as a number.

## Locking enforcement after cutover

Before cutover, `BHERILA_AUTH_PROVIDER_IDENTITY_ENABLED` is an ordinary switch. Once the
application relies on the provider to end access, record the cutover so a configuration
rollback or a stale environment file cannot turn enforcement off:

```bash
php artisan bherila-auth:provider-identity-cutover record
```

From then on enforcement stays on even if the setting is false, until a confirmed `withdraw`.
Run the `check` action in deploys. Adoption, the command's actions, failure modes, withdrawal
and testing are in [provider identity cutover](provider-identity-cutover.md).

## OAuth credentials (agent and personal tokens)

With enforcement enabled, the package's OAuth repositories apply the same policy to
the credentials the application issues:

- **Issuance.** An authorization code, and a personal token issued from the credentials
  screen, record the provider subject and the generation of the authorizing browser
  session (`provider_subject`, `provider_generation`). A token minted by exchanging a
  code or a refresh token inherits that stamp; it is never filled from a fresh status
  lookup. A bound account without a verified session cannot be issued a credential.
- **Use.** Every bearer request checks the token's stamp against the account's current
  binding and the shared observation. An ended identity is refused (401); an unavailable
  provider answers a retryable 503 (`ProviderStatusUnavailable` renders itself).
- **Renewal.** A refresh checks the person freshly. An ended identity gets
  `invalid_grant`; an unavailable provider answers 503 before the grant revokes anything,
  so the refresh token is not consumed and the client can retry.
- **Credentials issued before enforcement** have no stamp and are refused, not upgraded:
  connectors authorize again once. Credentials issued while enforcement is still off are
  stamped when the authorizing session has a baseline, so enabling it later keeps them.
- **Privileged operations.** `ProviderIdentityTokens::verifyUser($user, $tokenId)` checks
  freshly; call it before an operation that should not wait out the freshness window.
- Unbound accounts and client-credential tokens are left to the application.
- Under the agent profile, Passport's transient-token cookie route
  (`POST /oauth/token/refresh`) is refused: its cookie authenticates API requests with
  every scope outside both the session's and the bearer token's checks.

Publish and run the package migrations to add the stamp columns
(`2026_10_11_000000_add_provider_identity_to_oauth_credentials`). Set
`provider_identity.bearer_guard` if the guard authenticating bearer tokens is not `api`.

## Shared observations

`ProviderIdentityPolicy` holds one status observation per provider context and
subject, shared by every credential of that person. A person with several
sessions costs one status request per freshness window, which keeps traffic
within the provider's per-client throttle without widening the window. A
credential records the time of the observation it relied on, not the time it
asked, so a shared answer never extends freshness. Inactive answers are shared
too; outages are never cached. Privileged writes (`fresh: true`) bypass the
shared observation and refresh it.

## Details

`OAuthIdentity::credentialVersion` preserves the optional integer returned by
the provider's login identity response. Old providers continue to authenticate
with a null generation, but cannot establish a generation-verified session.
Do not fill the missing login generation by fetching today's status: doing so
could adopt a newer credential into an older login.

After callback verification, explicit subject binding and local authentication,
call `ProviderSession::remember($request, $identity)`. Call this once per new
login, not on each request. The binding must use the configured provider and
opaque subject, never email matching. Roll back local authentication if this
step fails while enforcement is enabled.

On every protected request for a bound account, call
`ProviderSession::assertActive($request, $provider, $subject, fresh: $privileged)`.
Pass the binding from the authenticated local record, never browser input. This
returns the current identity projection or throws one of two distinct errors:

| Result | Consumer behavior |
| --- | --- |
| Identity returned | Continue existing application authorization. This is the login-time identity; the status check never refreshes name/email |
| `ProviderSessionExpired` | Log out the relevant local guard, invalidate the session and regenerate CSRF; require a new login |
| `ProviderStatusUnavailable` | Return retryable 503 and refuse protected work; retain the session for retry |

The exception does not log out on its own because the application owns its
guards and onboarding state. Consumer middleware must implement these actions;
catching either exception and continuing would defeat enforcement. Local
unbound emergency accounts follow a separate explicit application policy. An
outage must never turn a provider-bound account into a local account.

A successful check is fresh for strictly less than 300 seconds. Privileged
writes pass `fresh: true`; clock rollback also forces a fresh check. Inactive
status, missing login baseline, changed provider/client context, changed local
binding or a credential-generation mismatch expires the session. A newer
generation never replaces its login baseline. Failed checks never advance the
last-success timestamp.

An active status response carries the subject and credential generation only.
Because the request is authenticated by this application's client credential
rather than by the person, the provider does not release profile data through
it, and the client never reads `name` or `email` from a status response even if
one is present. Refresh name/email projections from the bearer-authenticated
login identity response at sign-in, using explicit provider/subject binding.

The client uses the configured OAuth provider base URL, static client ID and
client secret to POST one subject to `/api/reconciliation/identity-status`.
The endpoint is fixed beneath that base, HTTPS is required (local loopback HTTP
only in local/testing), and redirects are not followed. Status responses must
be version 1, correctly typed, bound to the requested subject and bounded in
size. The provider must deny dynamic clients and profiles without an explicit
grant to the authenticated static client. Credentials remain server-side.

Application approval, membership, disabled state and last-admin safeguards still
run locally. Alias normalization and length limits remain consumer decisions.
Tombstone processing/acknowledgements remain a separate durable deletion task;
session verification does not assert that domain data has been deleted.

Before cutover, test an existing session across password reset, provider
disable/delete, grant removal, local account disable, provider timeout, malformed
response and recovery. Verify both ordinary requests and privileged writes.
Provider status endpoint capacity/throttling must accommodate per-session checks;
do not silently widen the freshness window to hide capacity failures.
