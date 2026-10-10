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
   not use the default guard.
3. If the account's binding does not live in `oauth_provider` / `oauth_subject`
   columns, bind your own `ProviderBindingResolver`, or rename the columns in
   `bherila-auth.provider_identity.binding`.
4. Use a cache store shared by every web worker
   (`bherila-auth.provider_identity.cache_store`), then set
   `BHERILA_AUTH_PROVIDER_IDENTITY_ENABLED=true`.

`establish()` remembers the login generation even while enforcement is off, so
sessions started after deploying step 1 survive turning enforcement on. Sessions
started before it have no baseline and are asked to sign in again once.

The middleware implements the consumer actions described below: an ended identity
logs out the guard, invalidates the session, regenerates the CSRF token and
redirects (`expired_redirect_route`) or answers JSON 401; an unavailable provider
answers 503 with `Retry-After` and keeps the session. Applications that need
different responses can call `ProviderSession::assertActive()` themselves.

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
