# Threat Model: bherila/auth-laravel

_Last reviewed: 2026-09-04 for the v0.11.0 OAuth/MCP server foundation; OAuth client rows revised 2026-10-19 for several authorization servers; rate-limit, 2FA, password-confirmation, session and provider-email rows revised 2026-11-15 for v0.30.0, and the 2FA link-secret, password-reset ordering and passkey-confirmation rows later that day. Re-review after route, controller, OAuth client/server, or `web-auth/webauthn-lib` changes._

## Scope

`bherila/auth-laravel` provides shared Laravel authentication services for BWH applications.

Covered package capabilities:

- OAuth 2.0 authorization-code + PKCE client mechanics for the sign-in provider and further authorization servers (per-server callbacks, bound pending flows, RFC 9207 `iss`, refresh, same-subject checks), and the relying-party session it owns.
- Opt-in Passport authorization-server helpers: metadata, dynamic public-client registration, S256 PKCE and RFC 8707 resource-indicator enforcement, consent presentation, RFC 9728 protected-resource challenges, and resource-bound JWT access tokens.
- WebAuthn/passkey registration, deletion, and login APIs.
- Password reset APIs and Laravel mailables.
- Authenticated password change and password confirmation APIs, and what a password change or reset does to the account's other sessions.
- Named rate limiters on the package's own routes.
- Email-based 2FA APIs and mailables.
- Database migrations for shared auth tables.
- Opt-in identity provider reconciliation clients: session status checks and the deletion tombstone consumer (`bherila-auth:consume-identity-tombstones`).
- Package routes, config, events, audit logger interfaces, and service classes.

Out of scope:

- App-owned Blade pages and Vite entrypoints.
- App-owned signup/login controllers, invite-code logic, business authorization, and user lifecycle rules.
- Production infrastructure controls such as TLS termination, WAF rules, secrets management, backups, and host hardening.
- Third-party mail provider security beyond correct Laravel mail configuration.

## Security objectives

- Only the legitimate user can authenticate with a password, passkey, password reset token, or 2FA code.
- Passkey assertions are bound to the expected relying party ID and origin.
- Password reset and password change flows do not expose user enumeration, plaintext secrets, or reusable tokens.
- Auth state changes are auditable by consuming applications.
- Package defaults are safe enough for reuse, while app-specific policies remain configurable by consumers.

## Primary assets

- Laravel authenticated session and remember tokens.
- User identity and user IDs.
- Password hashes.
- Password reset tokens.
- Email-based 2FA codes, attempt tokens, and the link secrets the emailed confirm/report links carry.
- WebAuthn credential IDs, public keys, counters, AAGUIDs, transports, and last-used timestamps.
- WebAuthn registration and authentication challenges stored in the Laravel session.
- CSRF tokens.
- Mail contents for password reset, password reset notice, and 2FA code emails.
- OAuth authorization state, authorization codes, refresh tokens, access-token JWTs, resource/audience bindings, registered redirect URIs, client scope restrictions, and consent decisions.
- Audit events and logs emitted by consuming apps.
- The application's invitation signing key, the client credentials token scoped to `invitations:admit`, and the invitation acceptance links the provider returns.

## Trust boundaries

- Browser to Laravel app over HTTPS.
- Laravel app to database.
- Laravel app to configured mail transport.
- Laravel app session storage to WebAuthn challenge verification.
- Browser/client to the OAuth authorization server and consent UI.
- OAuth authorization server to the Passport token database and protected resource endpoint.
- Laravel app to the identity provider's reconciliation API, authenticated with the static OAuth client credential (trusted HTTPS base URL, no redirects, bounded time and response size, strict response validation).
- Laravel app to the identity provider's application invitation endpoints, authenticated with a client credentials token and a per-request signed actor assertion (same transport bounds as above).
- Composer dependency supply chain to deployed package code.
- App-specific policy layer through `AuthUserPolicy` and `AuthAuditLogger`.

## Entry points

Default package routes are registered under the app-configured prefix, usually `/api`.

- `GET /api/passkeys`
- `POST /api/passkeys/register/options`
- `POST /api/passkeys/register`
- `DELETE /api/passkeys/{id}`
- `POST /api/passkeys/auth/options`
- `POST /api/passkeys/auth`
- `POST /api/auth/forgot-password`
- `POST /api/auth/reset-password`
- `POST /api/change-password`
- `POST /api/auth/confirm-password` (records a password confirmation for the session)
- `POST /api/auth/two-factor/verify`
- `POST /api/auth/two-factor/resend`
- `GET|POST /api/auth/two-factor/confirm/{token}?secret=` (user-clickable "this was me" link from 2FA email)
- `GET|POST /api/auth/two-factor/report/{token}?secret=` (user-clickable "this wasn't me" link from 2FA email)
- `POST /api/passkeys/confirm/options` and `POST /api/passkeys/confirm` (records a passkey confirmation for the session)

The OAuth client and authorization-server helpers are classes, not routes: the consuming
app owns and names those endpoints, so they are entry points of the app, reached through
package code.

When enabled by an application, the OAuth entry points also include the metadata and DCR
controller methods, Passport's authorization/token routes, and any protected endpoint
that returns an `OAuthProtectedResource` bearer challenge.

## Key assumptions

- Consuming apps serve auth pages only over HTTPS in production.
- Package routes run with Laravel `web` middleware unless the consuming app intentionally overrides it.
- CSRF protection remains enabled for browser-originated state-changing requests.
- Laravel sessions are protected with secure cookies, `SameSite` policy, and app-controlled session lifetime.
- The consuming app has a correct `APP_URL` and passkey relying-party configuration for each deployed host.
- The package rate-limits its own mail-sending and credential-checking routes with named limiters (`rate_limits`); the consuming app rate-limits its own auth endpoints (password login, registration, the OAuth callback) and the package's passkey assertion endpoints.
- Laravel's limiter cache store is shared by every web worker, so a limit or a wrong-code count is not per process.
- Apps whose session driver is not `database` enable Laravel's `authenticateSessions()` so a password change ends other sessions.
- Users can access their configured email address for password reset and 2FA flows.

## Threats and mitigations

| Threat | Risk | Package controls | Consumer requirements |
| --- | --- | --- | --- |
| Passkey phishing or credential replay | Attacker replays a captured assertion or tricks a user into authenticating to the wrong origin. | WebAuthn challenge verification, relying-party ID, allowed origins, credential ID lookup, signature validation, counter update. | Use HTTPS, configure `APP_URL`, configure allowed origins for all production hostnames, avoid wildcard origin assumptions. |
| Reuse of WebAuthn challenges | Stolen or repeated challenge could be reused. | Registration and login challenges are stored in session and pulled during verification. | Use secure session storage and avoid sharing sessions across untrusted domains. |
| Cloned authenticator (counter rollback) | Attacker uses a cloned credential whose counter has not advanced past the stored value. | Counter validation is delegated to `web-auth/webauthn-lib`'s assertion checker; on success the new counter is stored. The package does not itself add a separate counter-regression check or alert on suspicious counter behavior. | Track which authenticators report counter `0` (always) vs. monotonic counters; for high-risk apps, surface counter-regression failures from the underlying library as audit events for review. |
| Passkey registration CSRF | Attacker attempts to add their passkey to a victim account. | Registration routes are registered with `web` + `auth` middleware groups by the package's route file. | Keep CSRF middleware enabled and same-site cookies on; do not strip the package middleware groups when re-publishing routes. |
| Passkey deletion CSRF | Attacker attempts to remove victim passkeys. | Delete endpoint requires authenticated user and CSRF-protected middleware. | Keep CSRF enabled and consider step-up auth for deleting the last remaining credential in high-risk apps. |
| Passkey enrollment from a stolen long-lived session | Attacker who has hijacked a session adds their own passkey to lock the victim out. | By default (`passkeys.require_password_confirmation`) registration options and registration answer JSON 423 unless the session confirmed the password within `password_confirmation.timeout` (else `auth.password_timeout`, three hours) at the rate-limited `POST /api/auth/confirm-password`, or the account authenticated at the provider within that window, or the session made a user-verified assertion of one of the account's own passkeys within it (`POST /api/passkeys/confirm`, `userVerification: required`, restricted to that account's credentials and a ceremony separate from sign-in; or a passkey sign-in that reported user verification). The passkey record is bound to the account and not read by Laravel's `password.confirm`. The local-credential refusal is checked first. | Keep the requirement on; shorten the window for high-risk apps; handle the 423 in the enrollment UI. A provider-bound app relying on the provider-authentication alternative should require a recent sign-in at the provider for its own sensitive pages too. |
| Passkey list info disclosure | `GET /api/passkeys` returns AAGUIDs, transports, labels, and last-used timestamps; could fingerprint a victim's devices if exposed cross-user. | Endpoint requires authenticated user and only returns rows scoped to that user. | Do not expose this endpoint to admin/impersonation paths without re-checking authorization; redact AAGUIDs in any logs that may leave the trust boundary. |
| Password reset account enumeration | Attacker discovers whether an email has an account. | Reset requests go through `PasswordBroker::sendResetLink()`, so an unknown address, a throttled request, and a sent link share one response body, and the broker's timebox imposes a minimum execution time that flattens simple lookup timing differences. Mail is sent synchronously inside the callback, so transport latency beyond that minimum can still make a request for an existing account observably slower. | Keep generic copy in UI and mail flows; rate-limit reset requests. |
| Password reset token theft | Stolen email/token lets attacker set a password. | Uses Laravel password broker and hashed password update; reset token comparison is constant-time via the broker. | Require HTTPS, keep mail provider secure, set a short reset token expiry, notify user after reset. |
| Multiple outstanding password reset tokens | Older reset emails remain valid in inboxes after the user requests a new one. | Laravel's password broker stores one row per user and overwrites on new requests, invalidating prior tokens. | Do not customize the broker to keep historical tokens; verify behavior after Laravel upgrades. |
| Reset/2FA email flooding (mailbox abuse) | Attacker uses public reset/2FA endpoints to spam a victim's inbox or burn the app's mail-sender reputation. | Named limiters on the package routes: forgot-password 5/min per IP and 5/hour per (case-folded, hashed) address; 2FA resend 6/min per IP and 3 per 15 minutes per account. The password broker's recently-created-token throttle still applies. | Keep `rate_limits` on and the limiter cache store shared; limit the app's own login route, which starts challenges; alert on abnormal volume. |
| Stale sessions survive password change/reset | A session that was hijacked before the password change continues to work afterward. | With `sessions.end_other_sessions_on_password_change` on (default), change and reset rotate the remember token (the changing device's cookie is reissued) and, with the `database` session driver, delete the account's other session rows. Both do so straight after saving the new password, before the notice mail, audit, events and the post-reset sign-in, so a failure in any of those cannot leave the old sessions alive (from v0.30.0; the unreleased first cut of this change revoked after them). The reset regenerates the resetting device's session. Other drivers cannot be enumerated by the package. | Enable Laravel's `authenticateSessions()` (required for non-`database` drivers, recommended for all, since it also covers passwords changed outside the package); rotate the remember token in any app-owned password path. |
| 2FA code brute force | Attacker guesses emailed 2FA code. | Constant-time comparison; a challenge is spent after `two_factor.max_wrong_codes` (5) wrong codes, counted in the controller so any route using it is capped; verify is limited to 60/min per IP and 10/min per hashed challenge token; consumption is one conditional update, so concurrent submissions cannot both sign in. Resend requires a still-valid attempt and is limited per account, so at most a handful of challenges (each five guesses) exist per 15 minutes. | Keep the cap and limiters on; use short code lifetimes; log failures. |
| Fixed 2FA test code reaching a real deployment | The configured test code authenticates any account on a non-production deploy. | Off by default, and honoured only when the setting is on AND the environment is in `two_factor.test_code_environments` (`local`, `testing` by default) AND the account is flagged `is_test`. | Leave `BHERILA_AUTH_ALLOW_TEST_2FA_CODE` unset outside development; never flag a real account `is_test`. |
| Account state changes between first factor and session | An account disabled after its 2FA challenge (or during a password reset) still completes login. | `canLogin()` is rechecked immediately before `Auth::login()` on 2FA completion, and before the post-reset auto-login; the 2FA attempt is consumed either way. Change-password and passkey-management routes carry `RequireActiveUser`. | Implement `canLogin()` to reflect every account state that should block a login, and call it from the app's own password-login controller. |
| Second factor skipped with the public attempt token | Attacker who knows the password receives the attempt token (the login response's `attempt_token`, the resend response, the confirm page's JSON) and posts it to the confirm link to finish the sign-in without the mailbox. | Fixed in v0.30.0; every earlier release, v0.1.0 through v0.29.0, was affected. The emailed links carry a separate 64-character link secret, stored only as its SHA-256 (`link_secret_hash`) and never returned in JSON; confirm `GET` and `POST` and the report page require it with `hash_equals`. Code and link completion spend the attempt with one conditional update, so only one wins. Without the migrated column the email carries no links and only the code completes. | Publish and run the `link_secret_hash` migration; build any custom challenge email's links from `TwoFactorAttempt::linkSecret()`; never put the secret in an API response. |
| 2FA report endpoint abuse | Attacker triggers the "this wasn't me" link to lock out a legitimate login attempt, writes false suspicious reports into an account's history, or replays a report. | Only a request with the emailed link secret flags an attempt suspicious and audits a report. The token alone (the browser that started the attempt) can only withdraw that attempt, audited as a failed sign-in. Reporting and withdrawal are one conditional update on an unused attempt, so they are single-use and cannot race a completing sign-in. Neither authenticates nor changes account state. | Rate-limit by token and by IP if the link can leak; ensure the audit logger captures who reported and from what address. |
| Password reset on passwordless account | User with only passkeys needs recovery, or attacker abuses email recovery. | Passwordless users can still use email reset because Laravel users keep a random password hash. See "Design decisions" below. | Treat email account as a recovery factor and disclose this in UI; high-risk apps should disable email reset for passkey-only accounts and require admin recovery. |
| Normal password reset revokes passkeys unexpectedly | User loses access after routine reset. | Package does not automatically delete passkeys during reset. | Revoke passkeys only during explicit compromise/account-recovery flows; show passkey review UI after reset. |
| Session fixation after passkey login | Attacker forces victim into known session. | Passkey login regenerates the Laravel session. | Ensure app password login and signup paths also regenerate sessions. |
| Provider asserts an unverified address | The identity provider vouches for a subject whose address it has not verified, and the application creates or refreshes an account with that address (taking over grants that bind by email). | `OAuthIdentity::$emailVerified` carries the `email_verified` claim (only `true`/`"true"` is verified; any other present value is not; absent is `null`). `RelyingPartyLoginController` refuses `false` before any account is created, linked or updated, by default (`oauth_login.refuse_unverified_email`). | Keep the refusal on; a custom callback must check `emailVerified` itself; decide explicitly whether an absent claim is trusted for the provider in use. |
| Weak app-specific auth policy | Inactive, banned, or unverified users authenticate. | `AuthUserPolicy` interface controls whether passkey login is allowed and where to redirect. | Override policy for app-specific status checks and email verification requirements. |
| Missing audit visibility | Security events occur without detection. | Events are dispatched and `AuthAuditLogger` contract exists; the package logs through whatever logger consumers bind. | Bind a real audit logger in apps that need monitoring, alerting, or SIEM integration. Without one, key events are not retained. |
| OAuth resource confusion / token redirect | A bearer token issued for one protected resource is replayed at another resource or another Passport route in the same application, including after new issuance is disabled. | The opt-in repositories persist the validated resource through consent, authorization code, token and refresh exchange; bound JWTs carry it in `aud` and `resource`; bearer validation checks the stored binding, signed audience, configured issuer, route-declared expected resource, and revocation state. Scope lists are normalized from supported JSON, array, and collection casts before deciding whether a resource binding is required. The access-token validation repository remains active when issuance is disabled. Truly unbound tokens retain Passport-compatible handling only on unmarked routes; an expected-resource route or a resource-bearing JWT missing its database binding fails closed. Bound tokens fail closed on routes without an expected-resource declaration. | Configure the exact resource URI, run the OAuth metadata migration, enable `oauth_server.enabled` for issuance, and put `ExpectOAuthResource` before Passport authentication on each accepting route (or set the expectation before direct resource-server validation). Disabling issuance is not token revocation; revoke outstanding credentials separately when required. |
| Resource substitution during code or refresh exchange | A stolen/intercepted grant is exchanged for a different audience, or a refresh request adds an audience later. | Authorization-code and refresh-token repositories require the original resource, reject missing/different values, and preserve the binding on rotated access tokens. The refresh-token row owns its resource binding, so purging an expired parent access-token row does not erase the audience or invalidate a still-live refresh token. | Send the same `resource` value on authorization and every token request; publish the refresh-token resource column before enabling issuance; do not issue tokens through a bypass route or alternate repository. |
| Authorization resource state loss | Request-local or node-local cache state disappears between authorization, login, and consent, preventing the validated resource from reaching the code. | Resource state is keyed by a hash of Passport's opaque approval token, retained for the browser-session lifetime, and issuance fails closed when it cannot be recovered. | Use a persistent Laravel default cache store shared by every authorization-server node; never use the `array` store for this flow, and preserve the configured prefix for at least the authorization-state TTL. |
| OAuth issuer mix-up | A client accepts an authorization response or bearer token from an unintended issuer. | Issuer metadata is taken from the exact configured issuer; optional RFC 9207 decoration uses that exact value; resource-bound JWT validation checks `iss`. | Use one canonical issuer per deployment, enable RFC 9207 only when its middleware covers every authorization/consent response, and verify metadata after proxy/tenant changes. |
| OAuth client issuer mix-up | An application that is a client of several authorization servers accepts one server's response (or an attacker server's) as another's, and sends the code and PKCE verifier to the wrong token endpoint. | `OAuthClient` gives each server its own static callback (shared callbacks are a configuration error) and binds every pending flow to its server, exact issuer, callback, resource and verifier. A response is refused before any exchange unless it arrives at that server's callback path for a flow started for that server with its current settings; a present RFC 9207 `iss` must equal the configured issuer byte for byte (raw query, error responses too), and a missing one is refused when configured `required` or advertised by metadata. Metadata is read only from the configured issuer, must name it exactly, and only its `iss` flag is used; every endpoint comes from configuration. | Give each server a distinct `redirect_uri` routed only to that server's client; configure exact issuers; set `authorization_response_iss` to `required` once a server sends `iss`. |
| OAuth client state replay or cross-session completion | A captured authorization response is replayed, completed in another browser (login/connection CSRF), completed after the person changed, or left pending indefinitely. | Pending flows live in the session that started them, keyed by a hash of `state`, are removed on first use whatever the outcome, carry the signed-in person's identifier and start time, and are refused when the person differs or after `pending_flow_ttl`; at most ten are kept per session. | Keep session cookies `SameSite=Lax` or stricter and regenerate the session at sign-in. |
| Connected account belongs to someone else | A token obtained from another application belongs to a different person than the local owner (a different account signed in at that application), and its data is attributed to the owner. | `SameSubject` matches only the trusted provider and the same non-empty subject on both sides; unbound owners and broken bindings never match. | Compare the other application's reported subject with the owner's binding before storing a connection and on every use; refuse connections for unbound owners. |
| OAuth authorization response leakage or redirect abuse | A browser/cache retains authorization state or errors, or an invalid/revoked client uses pre-validation as a redirector. | Authorization and consent responses carry `Cache-Control: no-store` and `Pragma: no-cache`. Errors redirect only after loading an active client and matching the exact registered callback; omission is accepted only when one callback is registered. | Keep package middleware on every authorization/consent route, preserve exact redirect registration, and revoke compromised clients rather than only hiding their UI. |
| Dynamic-client scope escalation | A public client registers narrowly and later asks for broader application permissions. | Registration scopes are checked against the application catalog and stored on the client; dynamic-client requests are always required to be a subset of registered scopes (or the configured catalog when registration omitted one); consent remains in the flow; refresh cannot add scopes. DCR parses its bounded raw JSON document so Laravel's empty-string normalization cannot change an explicitly empty scope into an omitted scope. | Apply the OAuth migration and make the configured scope catalog the sole source of application permissions. The legacy `enforce_registered_scopes` switch is not a security bypass. |
| Public-client secret misuse | A public MCP client receives a reusable secret or is treated as trusted merely because it used DCR. | DCR creates `confidential:false` clients with no response secret, and answers `token_endpoint_auth_method: none` even when the request asked for `client_secret_post` or `client_secret_basic` (RFC 7591 §3.2.1 lets the server replace requested metadata; MCP SDK clients ask for a secret method by default and follow the returned one); only public auth-code + refresh grants are accepted; the shared consent path remains active. The accepted application types are `native` and `web`; loopback HTTP is allowed only for native/unspecified development clients, while hosted/web clients require HTTPS. | Do not add a client secret to native/loopback or hosted public clients, and do not mark dynamic clients first-party in an application policy/model override. |
| Hidden or unrevocable agent grants | A self-registered agent keeps a person's grant that the person cannot see or end, or one person's disconnect revokes another's grant to the same shared dynamic client. | `connectedClients()` lists every non-personal-access client with a live access or refresh token for the owner, dynamic clients included, without secrets; `disconnectClient()` revokes only rows owned by the signed-in person (codes, access tokens, linked and purged-access refresh tokens), leaves the registration, is idempotent, and with durable revocation raises the owner/client barrier. Both are session-only routes. | Expose the list to people; render the self-asserted client name with its `kind` and redirect URIs; enable durable revocation so an in-flight exchange cannot outlive a disconnect. |
| Static key with connection rights | A personal API token opted in to an MCP connection scope (`credentials.personal_token_connection_scopes`) is copied from a client config or log and used to connect as its owner, with no consent screen naming the client. | Off by default (`[]`); only listed scopes that are also `resource_required_scopes` entries, in the catalog and not excluded are offered, to personal tokens only; once opted in, every token carrying a connection scope is capped at `personal_token_connection_max_lifetime` (default `P30D`, invalid fails closed); the token is resource-bound and accepted only on `ExpectOAuthResource` routes; issuance stays browser-only with the secret shown once; listings flag connection tokens. | Opt in only for clients that cannot run OAuth; keep the cap short; removing a scope from the list does not revoke issued tokens, so revoke flagged tokens when withdrawing the option. |
| Protected-resource discovery failure | A client cannot discover the authorization server or does not understand the API challenge. | Reusable RFC 9728 metadata and `WWW-Authenticate` helpers include `authorization_servers`, supported scopes, bearer method, and `resource_metadata` when configured. | Route the metadata document at the exact configured URI and return the helper's challenge from the MCP endpoint's unauthenticated/insufficient-scope responses. |
| Disabled server still issues credentials | An operator turns off metadata/DCR but Passport's separately registered authorization or token routes continue processing existing clients and refresh grants. | `EnsureOAuthServerEnabled` returns a non-cacheable 404 before application-owned Passport routes execute. Package metadata and DCR controllers enforce the same opt-in switch themselves. | Install the gate on every Passport authorization/token route, clear cached configuration after changing the flag, and revoke existing credentials separately when required. |
| Unsafe client metadata retrieval | A URL-form client ID causes server-side fetches into private infrastructure. | Client ID Metadata Documents are not enabled or advertised in this release; no arbitrary client URL is fetched. | Use DCR compatibility for now. Do not add `client_id_metadata_document_supported` until the follow-up implementation includes URL identity resolution, bounded fetches, redirect policy, DNS/IP SSRF defenses, and safe caching. |
| Invitation link or credential leakage | An acceptance link (a single-use bearer credential), the invitation token, or the signing key reaches a log, an API response or an agent, letting someone else accept an invitation or request one as the application. | `IssuedInvitation` omits the link from JSON and debug output; exceptions carry fixed messages and no address, link, token, assertion, body or transport exception; sensitive parameters are marked; the token is cached encrypted under a key bound to the issuer, client and secret; requests never follow redirects. | Show the link only to the manager who asked; never log it or return it to automated agents; keep the signing key in the secret store and use it for nothing else. |
| Invitation request replay or redirection | A captured request is replayed, or its assertion is used for another invitation, body or endpoint. | Each assertion binds the exact URL and SHA-256 of the exact body bytes, lives 60 seconds and carries a fresh 64-hex `jti`; the provider accepts each `jti` once. The client signs nothing it does not send. | Decide the actor's authority before calling: the provider relies on it. |
| Misleading scope group or preset | A preset or group label misdescribes what it grants, or a sensitive scope ends up in a one-click preset. | Grants store explicit scopes; presets cannot contain sensitive-group scopes (validated, `LogicException`); the consent screen always lists every requested scope's own description; nothing accepts a preset or group id. | Review group and preset labels as security copy; keep dangerous scopes in sensitive groups. |
| Scope implications widening a grant | A declared implication (`billing:write` needs `billing:read`) is treated as authorization, or a picker cascade pulls a sensitive scope in. | Implications are presentation only: credentials store explicit scopes, store endpoints add and reject nothing, authorization never infers one scope from another; validation refuses a routine scope requiring a sensitive one, cycles, unknown scopes and presets not closed under them. | Review declared implications as security copy; keep dangerous scopes in sensitive groups. |
| Dependency compromise | Composer package or transitive dependency is compromised. | Package is versioned and installable from tagged GitHub source. | Pin Composer lockfiles, review dependency updates, run CI, monitor advisories. |

## Design decisions

- **Email is a recovery factor for passwordless accounts.** Laravel users keep a random password hash, so the email-based reset flow remains usable even for users who only have passkeys. This is a deliberate trade-off in favor of recovery over phishing-resistance. Apps that handle high-risk accounts (admin, finance, regulated data) should disable email reset for passkey-only users in their `AuthUserPolicy` and require an out-of-band recovery path.
- **`AuthAuditLogger` defaults to a no-op.** Apps that do not bind an implementation will silently lose detection signal for password changes, passkey registrations/deletions, suspicious 2FA reports, and failed verifications. Treat binding a real logger as a security requirement, not an enhancement.

## Known gaps

These are gaps in package behavior that the threat table flags above. They are listed here so they remain visible until fixed in the package itself.

- **Other sessions on non-`database` drivers end only with `authenticateSessions()`.** The package rotates the remember token and deletes database sessions on password change and reset, but cannot enumerate file, cookie, Redis or other sessions. An app on those drivers that has not enabled Laravel's session authentication keeps a hijacked session alive until it expires.
- **Passkey sign-in and 2FA confirm/report endpoints carry no package limiter.** Their inputs are WebAuthn assertions or 64-character random tokens and link secrets, so they are not guessable, but the options endpoint can be called freely. Apps that see abuse limit them per IP.
- **The wrong-code count and the limiters live in the cache.** A cache flush resets them, and an unshared (per-process) limiter store divides them by the number of workers.
- **Client ID Metadata Documents are deferred.** DCR remains the compatibility mechanism. The package deliberately does not advertise or fetch URL-form client IDs until it can map the external client identity into Passport and enforce bounded, SSRF-safe document retrieval. The design is tracked in [issue #30](https://github.com/bherila/auth-laravel/issues/30).
- **MCP protocol policy remains application-owned.** This package does not implement MCP transport, tool authorization, endpoint routing, or application-specific scope policy. Consumers must install the resource-aware Passport bindings and return the protected-resource challenge from their own endpoint.

## Security checklist for consuming apps

- Confirm deployed `composer.lock` uses a fixed package version known to include required security fixes.
- Confirm `web-auth/webauthn-lib` is compatible with the package code.
- Confirm `APP_URL` matches the production origin exactly.
- If acting as an OAuth authorization server, set `oauth_server.enabled`, the exact issuer,
  the exact protected resource, and `protected_resource_metadata_url`; publish and run
  `2026_09_02_000000_add_oauth_server_metadata` before issuing bound tokens.
- Use a persistent default cache store shared by all authorization-server nodes so the
  validated resource survives authorization, login, and consent request boundaries.
- Review DCR registrations; public clients must have no reusable secret and must go through
  consent. Registered-scope enforcement is always active.
- Add `EnsureOAuthServerEnabled`, `EnforceOAuthPkce`, and
  `EnforceOAuthResourceIndicator` to the Passport routes; if RFC 9207 is enabled, add
  `AppendOAuthAuthorizationResponseIssuer` to every authorization and consent route.
- Put `ExpectOAuthResource` before Passport authentication on each protected route that
  accepts the resource-bound credential; an unmarked route rejects bound tokens.
- Return `OAuthProtectedResource::unauthorizedResponse()` / `insufficientScopeResponse()`
  from the protected endpoint and verify the challenge's `resource_metadata` URI.
- If using application invitations, check the actor's authority before every call, keep the
  invitation key separate from other keys, and keep acceptance links out of logs and agent responses.
- Configure `bherila-auth.passkeys.allowed_origins` for every trusted production origin.
- Ensure all auth routes are HTTPS-only in production.
- Ensure cookies are secure and same-site.
- Keep CSRF middleware enabled for browser auth routes.
- Keep `rate_limits` on (the package limits password reset, password change, password confirmation, 2FA verify/resend and credential issuance) and use a limiter cache store shared by every worker; add rate limiting to the app's own login and registration routes and, if needed, passkey options/auth.
- Enable Laravel's `authenticateSessions()`, so a password change ends every other session whatever the session driver.
- Keep `passkeys.require_password_confirmation` on and handle its 423 in the enrollment UI.
- Override `AuthUserPolicy` for disabled users, email verification, tenant membership, and app-specific login rules.
- Bind a real `AuthAuditLogger` where audit logging is required.
- Verify mail subject/from/reply-to values are app-configured.
- Test passkey login after every `web-auth/webauthn-lib` upgrade.
- Test password reset for both password-based and passwordless users.
- Provide a user settings page to list and revoke passkeys.
- Consider step-up auth before deleting all passkeys, changing email, changing password, or disabling 2FA.

## Residual risks

- Email remains an account recovery factor for passwordless users. If a user's mailbox is compromised, password reset can still create a usable password.
- Passkeys synced by platform vendors may have security properties that depend on the user's device account and cloud account protection.
- User identity lifecycle is app-owned, so package security depends on consumers implementing appropriate policy checks.
- Browser and OS WebAuthn support varies; fallback flows must be treated as security-sensitive recovery flows.

## Incident response notes

- To respond to suspected passkey compromise, revoke affected `auth_passkeys` rows and invalidate sessions.
- To respond to suspected email recovery compromise, rotate password, revoke sessions, review passkeys, and notify the user.
- To respond to dependency compromise, pin to a known-good tag, rebuild vendor assets, redeploy, and rotate secrets if needed.
- Preserve audit events, request metadata, and affected user IDs for investigation.
