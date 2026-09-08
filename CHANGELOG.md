# Changelog

Notable changes per release. Versions follow the tags published to
[Packagist](https://packagist.org/packages/bherila/auth-laravel); anything older than
the first entry here is in the git history.

## v0.13.0 - 2026-09-08

### Verify provider browser sessions against credential generation

- Opt-in `ProviderSession` and `ProviderIdentityStatusClient` under `BWH\Auth\OAuth\Session`
  implement the consumer side of the Auth Manager identity-status contract (version 1).
  `OAuthIdentity` gains an optional `credentialVersion` preserved from the login identity
  response; `ProviderSession::remember()` binds it once per login and
  `ProviderSession::assertActive()` re-verifies liveness and generation against the
  provider's `POST /api/reconciliation/identity-status` with a strict five-minute freshness
  bound, always fresh for privileged writes. Inactive status, a changed generation, a changed
  binding or a changed provider/client context throws `ProviderSessionExpired`; transport,
  protocol and size/deadline failures throw `ProviderStatusUnavailable` and never authorize.
- The status endpoint is authenticated by the application's client credential, not by the
  person, so it carries no profile data. `status()` returns a `ProviderIdentityStatus`
  (subject and generation only) and `assertActive()` returns the login-time identity; a
  status response's `name`/`email` are never read. Refresh projections from the
  bearer-authenticated login response at sign-in.
  See `docs/provider-session-verification.md`.

### Extract delegated application access verification for consumers

- `BWH\Auth\OAuth\DelegatedAccess` adds the shared `DelegatedActorAssertionVerifier`,
  `DelegatedContract` validator, `DatabaseNonceStore` with its opt-in migration, and
  `DelegatedAccessException`, so consuming applications can host provider-driven access
  management without copying provider code. Verification pins RS256 keys, canonical issuer,
  exact endpoint audience, application, method, body digest and a short lifetime; nonces are
  consumed by atomic unique insert and expiry is re-checked after consumption. There is no
  cache-backed nonce store. The returned actor subject still requires consumer-owned
  authorization.

### Return inactive results for invalid introspected token contexts

- Remote introspection now returns an inactive result, rather than reporting the
  authorization server unavailable, for a well-formed active response whose issuer,
  resource or audience does not match, whose token is expired, or whose not-before lies in
  the future. Malformed responses, configuration, network and client-authentication failures
  still throw.

## v0.12.2 - 2026-09-05

### Accept fractional NumericDate timestamps during introspection

- Remote introspection now accepts fractional `exp`, `iat`, and `nbf` claims and
  floors them to whole seconds. RFC 7519 defines NumericDate as a JSON numeric
  value and states that non-integer values can be represented, so rejecting them
  made the resource server dependent on every authorization server it talks to
  emitting integers -- including v0.12.1's own producer fix. A resource server
  pointed at a stock Passport authorization server rejected every live token and
  reported the authorization server as unavailable.
- The direction of that rounding is a security property. `exp` and `iat` floor, so
  a token never outlives the instant it was given. `nbf` ceils: flooring an `nbf`
  of `time() + 0.75` yields exactly `time()`, and the not-before check rejects only
  `nbf > now`, so the token would have been honoured up to a second before it
  became valid.
- The introspection endpoint applies the same directions when publishing claims,
  so it never advertises a token as valid earlier than the instant it was issued
  for, and both sides derive the same whole second.
- Malformed, non-finite, and out-of-range values are still rejected, and the
  exclusive 64-bit bounds are unchanged. Values at or above 2 ** 53 are already
  integral in a double, so neither rounding direction can push an in-range value
  past those bounds.

## v0.12.1 - 2026-09-04

### OAuth introspection timestamp interoperability

- Normalized the introspection response's `exp`, `iat`, and `nbf` claims to integer
  NumericDate wire values. Passport emits fractional timestamps, which RFC 7662
  consumers that decode these claims as integers rejected outright.
- Remote introspection accepts integers and finite integral JSON floats, and rejects
  fractional, string, non-finite, and out-of-range values. Decoding uses
  `JSON_BIGINT_AS_STRING` so oversized integer literals cannot be silently accepted.
- Both magnitude bounds are exclusive on 64-bit builds: an out-of-range literal such
  as `-9223372036854775809.0` has no double representation and rounds onto exactly
  `PHP_INT_MIN`, which an inclusive lower bound would have accepted as a valid
  timestamp. A 32-bit integer range is represented exactly by a double, so those
  bounds remain inclusive.

## v0.12.0 - 2026-09-04

### Separate authorization and resource servers

- Added opt-in RFC 7662 introspection backed by Passport's signature, expiry,
  revocation, issuer, audience, and stored resource checks.
- Introspection requires HTTP Basic credentials for a confidential resource server,
  stores only a password hash server-side, and pins each configured credential to
  one exact resource.
- Added a remote introspection client that defensively validates active issuer,
  audience, resource, scope, and temporal claims without positively caching results.
- Made the three resource-aware Passport repository implementations extensible so
  authorization-server applications can compose additional account and grant policy
  without replacing RFC 8707 enforcement.

## v0.11.0 - 2026-09-04

### OAuth/MCP authorization-server foundation

- Added opt-in Passport repositories and a JWT access-token entity that carry one
  configured protected-resource URI from authorization request and consent state through
  authorization codes, access/refresh token exchange, and refresh rotation.
- Resource-bound access tokens carry the protected resource in `aud` and `resource`, and
  resource-server validation checks the stored binding, signed audience, configured issuer,
  route-declared expected resource, revocation state, and expiry before Passport
  authenticates the bearer. Bound tokens fail closed on unmarked Passport routes.
- Disabling new authorization/token issuance no longer removes audience enforcement from
  previously issued resource-bound access tokens; ordinary unbound Passport token behavior
  remains compatible on unmarked routes while the opt-in server is disabled. Unbound or
  incompletely bound tokens still fail closed wherever a route expects a resource.
- Added the reusable RFC 9728 protected-resource metadata/challenge helper, including
  `resource_metadata` and scope-bearing 401/403 `WWW-Authenticate` responses.
- Added opt-in RFC 9207 authorization-response issuer decoration; the metadata flag is
  emitted only when the corresponding middleware is enabled.
- DCR metadata is advertised only when an endpoint is configured. Public clients accept
  native or hosted/web authorization-code + refresh-token profiles with `none` token
  authentication, never receive a reusable secret, and retain explicit registered scope
  limits; loopback redirects remain native-only.
- Added a safe, idempotent Passport metadata/resource-column migration and documented
  consumer migration steps.
- Refresh tokens now persist their resource binding directly, so a valid longer-lived
  refresh token remains usable after Passport purges its expired access-token row.
- Metadata controller routes now fail closed with a non-cacheable 404 while the opt-in
  OAuth server is disabled, so accidentally routed discovery endpoints cannot advertise
  an inactive server.
- Added `EnsureOAuthServerEnabled` for application-owned Passport authorization/token
  routes, so disabling the opt-in server can stop new issuance and refresh processing
  instead of hiding only package metadata and registration routes.
- Resource URI identity now preserves a configured trailing slash, and the protected
  resource helper derives the RFC 9728 path-based well-known metadata URL when no override
  is configured.
- Dynamic registrations now persist the configured scope catalog when the request omits
  `scope`; legacy dynamic clients without a stored scope fail closed rather than becoming
  implicitly unrestricted.
- Dynamic registration validates the bounded raw JSON document so Laravel's global empty-
  string normalization cannot turn an explicitly empty `scope` into an omitted scope and
  accidentally register the server catalog instead.
- Enabling the resource-aware Passport binding requires legacy Passport bearer tokens to
  be reissued because they do not carry the package's issuer claim.
- Protected routes accepting bound credentials must put `ExpectOAuthResource` before
  Passport authentication (or set the same request expectation before direct validation).
- Authorization resource state requires Laravel's default cache to persist across
  requests and be shared by every authorization-server node; the request-local `array`
  store is unsupported for this flow and causes issuance to fail closed.
- Authorization and consent responses now carry `no-store`/`no-cache`; pre-validation
  errors redirect only to an active client's exact registered callback, including the
  sole registered callback when the optional `redirect_uri` is omitted.
- Registered scope ceilings accept supported array, JSON, and collection casts, and
  auth-code scope persistence avoids double-encoding cast model attributes. Access-token
  validation also normalizes collection-cast scopes before deciding whether a token must
  carry a protected-resource binding, including while new issuance is disabled.

### Deferred

- Client ID Metadata Documents are not advertised or fetched yet. URL-form client IDs
  require a Passport client-identity adapter and hardened SSRF-safe document retrieval;
  DCR remains available for compatibility. See [issue #30](https://github.com/bherila/auth-laravel/issues/30)
  for the focused follow-up design.

## v0.10.0 - 2026-09-04

Breaking: this release drops PHP 8.3 and Laravel 12. For a pre-1.0 package `^0.9`
resolves as `>=0.9.0 <0.10.0`, so shipping a platform drop as 0.9.x would upgrade
consumers into a package their runtime cannot load. Consumers move to `^0.10`
together with PHP 8.4+ and Laravel 13.

### Requirements

- **Requires PHP 8.4+ and Laravel 13.** Earlier releases advertised PHP 8.2 and
  Laravel 12 or 13, but `OAuthClient` used typed class constants (PHP 8.3+) and CI
  installed a single PHP 8.5 / Laravel 12 combination, so neither claim was true or
  tested. CI now runs the floor, the newest runtime, and `--prefer-lowest`.
- `web-auth/webauthn-lib` floor raised to `^5.3.5`, excluding the origin-validation
  advisory affecting 5.2.0–5.2.3 and the advisory fixed in 5.3.5. CI runs
  `composer audit`.

### Security

- `canLogin()` is rechecked immediately before `Auth::login()` on 2FA completion and
  before the post-reset auto-login, so an account disabled after a challenge was
  issued — or one that completes a password reset — no longer receives a session. The
  2FA attempt is consumed either way.
- `/api/change-password` and the authenticated passkey routes carry `RequireActiveUser`
  alongside `auth`.
- The fixed 2FA test code is off by default and now requires all three of: the setting,
  an allowed environment (`two_factor.test_code_environments`), and an `is_test`
  account. Previously either the setting or an `is_test` account sufficed, and the
  setting defaulted to on in every environment except `APP_ENV=production`.
- `POST /api/auth/forgot-password` goes through `PasswordBroker::sendResetLink()`,
  restoring the broker's recently-created-token throttle and timebox, which calling
  `createToken()` directly had bypassed.
- `POST /api/auth/two-factor/resend` refuses an expired attempt, which could previously
  mint a fresh code and expiry for itself indefinitely.
- `ClientIp::resolve()` returns null for an address that will not pack, instead of
  handing back a value that packs to null on write and reads as `ip_address IS NULL` in
  a throttle lookup — counting the failures of every request whose IP was unknown.

### Fixed

- Package config defaults are merged into a published `config/bherila-auth.php` key by
  key. A published config that predates a release no longer erases the nested defaults
  added since, which had left later keys reading as null.
- The `rp_id` migration targets `auth_passkeys` (it fell back to `webauthn_credentials`,
  a name nothing else uses) and skips cleanly when the table is missing or the column
  already exists.
- The package dispatches Laravel's `PasswordResetLinkSent` and `PasswordReset` events.
