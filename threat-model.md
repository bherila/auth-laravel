# Threat Model: bherila/auth-laravel

_Last reviewed: 2026-09-04 for the v0.11.0 OAuth/MCP server foundation. Re-review after route, controller, OAuth client/server, or `web-auth/webauthn-lib` changes._

## Scope

`bherila/auth-laravel` provides shared Laravel authentication services for BWH applications.

Covered package capabilities:

- OAuth 2.0 authorization-code + PKCE client mechanics, and the relying-party session it owns.
- Opt-in Passport authorization-server helpers: metadata, dynamic public-client registration, S256 PKCE and RFC 8707 resource-indicator enforcement, consent presentation, RFC 9728 protected-resource challenges, and resource-bound JWT access tokens.
- WebAuthn/passkey registration, deletion, and login APIs.
- Password reset APIs and Laravel mailables.
- Authenticated password change API.
- Email-based 2FA APIs and mailables.
- Database migrations for shared auth tables.
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
- Email-based 2FA codes and attempt tokens.
- WebAuthn credential IDs, public keys, counters, AAGUIDs, transports, and last-used timestamps.
- WebAuthn registration and authentication challenges stored in the Laravel session.
- CSRF tokens.
- Mail contents for password reset, password reset notice, and 2FA code emails.
- OAuth authorization state, authorization codes, refresh tokens, access-token JWTs, resource/audience bindings, registered redirect URIs, client scope restrictions, and consent decisions.
- Audit events and logs emitted by consuming apps.

## Trust boundaries

- Browser to Laravel app over HTTPS.
- Laravel app to database.
- Laravel app to configured mail transport.
- Laravel app session storage to WebAuthn challenge verification.
- Browser/client to the OAuth authorization server and consent UI.
- OAuth authorization server to the Passport token database and protected resource endpoint.
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
- `POST /api/auth/two-factor/verify`
- `POST /api/auth/two-factor/resend`
- `GET|POST /api/auth/two-factor/confirm/{token}` (user-clickable "this was me" link from 2FA email)
- `GET|POST /api/auth/two-factor/report/{token}` (user-clickable "this wasn't me" link from 2FA email)

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
- The consuming app rate-limits auth endpoints at the route or middleware layer.
- Users can access their configured email address for password reset and 2FA flows.

## Threats and mitigations

| Threat | Risk | Package controls | Consumer requirements |
| --- | --- | --- | --- |
| Passkey phishing or credential replay | Attacker replays a captured assertion or tricks a user into authenticating to the wrong origin. | WebAuthn challenge verification, relying-party ID, allowed origins, credential ID lookup, signature validation, counter update. | Use HTTPS, configure `APP_URL`, configure allowed origins for all production hostnames, avoid wildcard origin assumptions. |
| Reuse of WebAuthn challenges | Stolen or repeated challenge could be reused. | Registration and login challenges are stored in session and pulled during verification. | Use secure session storage and avoid sharing sessions across untrusted domains. |
| Cloned authenticator (counter rollback) | Attacker uses a cloned credential whose counter has not advanced past the stored value. | Counter validation is delegated to `web-auth/webauthn-lib`'s assertion checker; on success the new counter is stored. The package does not itself add a separate counter-regression check or alert on suspicious counter behavior. | Track which authenticators report counter `0` (always) vs. monotonic counters; for high-risk apps, surface counter-regression failures from the underlying library as audit events for review. |
| Passkey registration CSRF | Attacker attempts to add their passkey to a victim account. | Registration routes are registered with `web` + `auth` middleware groups by the package's route file. | Keep CSRF middleware enabled and same-site cookies on; do not strip the package middleware groups when re-publishing routes. |
| Passkey deletion CSRF | Attacker attempts to remove victim passkeys. | Delete endpoint requires authenticated user and CSRF-protected middleware. | Keep CSRF enabled and consider step-up auth for deleting the last remaining credential in high-risk apps. |
| Passkey enrollment from a stolen long-lived session | Attacker who has hijacked a session adds their own passkey to lock the victim out. | Package exposes the registration endpoint; it does not enforce recently-authenticated requirements. | High-risk apps must require re-auth (password or fresh passkey) within N minutes before the registration endpoint is reachable, e.g. via a `password.confirm` middleware. |
| Passkey list info disclosure | `GET /api/passkeys` returns AAGUIDs, transports, labels, and last-used timestamps; could fingerprint a victim's devices if exposed cross-user. | Endpoint requires authenticated user and only returns rows scoped to that user. | Do not expose this endpoint to admin/impersonation paths without re-checking authorization; redact AAGUIDs in any logs that may leave the trust boundary. |
| Password reset account enumeration | Attacker discovers whether an email has an account. | Reset requests go through `PasswordBroker::sendResetLink()`, so an unknown address, a throttled request, and a sent link share one response body, and the broker's timebox imposes a minimum execution time that flattens simple lookup timing differences. Mail is sent synchronously inside the callback, so transport latency beyond that minimum can still make a request for an existing account observably slower. | Keep generic copy in UI and mail flows; rate-limit reset requests. |
| Password reset token theft | Stolen email/token lets attacker set a password. | Uses Laravel password broker and hashed password update; reset token comparison is constant-time via the broker. | Require HTTPS, keep mail provider secure, set a short reset token expiry, notify user after reset. |
| Multiple outstanding password reset tokens | Older reset emails remain valid in inboxes after the user requests a new one. | Laravel's password broker stores one row per user and overwrites on new requests, invalidating prior tokens. | Do not customize the broker to keep historical tokens; verify behavior after Laravel upgrades. |
| Reset/2FA email flooding (mailbox abuse) | Attacker uses public reset/2FA endpoints to spam a victim's inbox or burn the app's mail-sender reputation. | None at the package level beyond endpoint shape. | Rate-limit per-IP and per-email at the route layer; cap resends per attempt window; alert on abnormal volume. |
| Stale sessions survive password change/reset | A session that was hijacked before the password change continues to work afterward. | **Partial.** Password reset rotates `remember_token` and regenerates the resetting device's session. Password change (`AuthenticatedPasswordController::update`) does **not** rotate the remember token, invalidate other devices, or call `Auth::logoutOtherDevices` — see "Known gaps" below. | Until the package change-password controller is hardened, consuming apps should layer their own session-revocation step (e.g., a controller wrapper that calls `Auth::logoutOtherDevices` and `$user->setRememberToken(Str::random(60))->save()`) on the change-password route. |
| 2FA code brute force | Attacker guesses emailed 2FA code. | Verification endpoint validates code/token using constant-time comparison and marks the attempt as used on success. Resend requires a still-valid attempt, so an expired challenge cannot extend itself. There is no per-attempt failure cap. | Rate-limit verify/resend, use short code lifetimes, log failures, lock the attempt row after N failures. |
| Fixed 2FA test code reaching a real deployment | The configured test code authenticates any account on a non-production deploy. | Off by default, and honoured only when the setting is on AND the environment is in `two_factor.test_code_environments` (`local`, `testing` by default) AND the account is flagged `is_test`. | Leave `BHERILA_AUTH_ALLOW_TEST_2FA_CODE` unset outside development; never flag a real account `is_test`. |
| Account state changes between first factor and session | An account disabled after its 2FA challenge (or during a password reset) still completes login. | `canLogin()` is rechecked immediately before `Auth::login()` on 2FA completion, and before the post-reset auto-login; the 2FA attempt is consumed either way. Change-password and passkey-management routes carry `RequireActiveUser`. | Implement `canLogin()` to reflect every account state that should block a login, and call it from the app's own password-login controller. |
| 2FA report endpoint abuse | Attacker triggers the "this wasn't me" link to lock out a legitimate login attempt, or replays it. | Token is single-use (`is_used` flag) and only marks the attempt suspicious; it does not authenticate or change account state. | Rate-limit by token and by IP; ensure the audit logger captures who reported and from what address. |
| Password reset on passwordless account | User with only passkeys needs recovery, or attacker abuses email recovery. | Passwordless users can still use email reset because Laravel users keep a random password hash. See "Design decisions" below. | Treat email account as a recovery factor and disclose this in UI; high-risk apps should disable email reset for passkey-only accounts and require admin recovery. |
| Normal password reset revokes passkeys unexpectedly | User loses access after routine reset. | Package does not automatically delete passkeys during reset. | Revoke passkeys only during explicit compromise/account-recovery flows; show passkey review UI after reset. |
| Session fixation after passkey login | Attacker forces victim into known session. | Passkey login regenerates the Laravel session. | Ensure app password login and signup paths also regenerate sessions. |
| Weak app-specific auth policy | Inactive, banned, or unverified users authenticate. | `AuthUserPolicy` interface controls whether passkey login is allowed and where to redirect. | Override policy for app-specific status checks and email verification requirements. |
| Missing audit visibility | Security events occur without detection. | Events are dispatched and `AuthAuditLogger` contract exists; the package logs through whatever logger consumers bind. | Bind a real audit logger in apps that need monitoring, alerting, or SIEM integration. Without one, key events are not retained. |
| OAuth resource confusion / token redirect | A bearer token issued for one protected resource is replayed at another resource or another Passport route in the same application, including after new issuance is disabled. | The opt-in repositories persist the validated resource through consent, authorization code, token and refresh exchange; bound JWTs carry it in `aud` and `resource`; bearer validation checks the stored binding, signed audience, configured issuer, route-declared expected resource, and revocation state. Scope lists are normalized from supported JSON, array, and collection casts before deciding whether a resource binding is required. The access-token validation repository remains active when issuance is disabled. Truly unbound tokens retain Passport-compatible handling only on unmarked routes; an expected-resource route or a resource-bearing JWT missing its database binding fails closed. Bound tokens fail closed on routes without an expected-resource declaration. | Configure the exact resource URI, run the OAuth metadata migration, enable `oauth_server.enabled` for issuance, and put `ExpectOAuthResource` before Passport authentication on each accepting route (or set the expectation before direct resource-server validation). Disabling issuance is not token revocation; revoke outstanding credentials separately when required. |
| Resource substitution during code or refresh exchange | A stolen/intercepted grant is exchanged for a different audience, or a refresh request adds an audience later. | Authorization-code and refresh-token repositories require the original resource, reject missing/different values, and preserve the binding on rotated access tokens. The refresh-token row owns its resource binding, so purging an expired parent access-token row does not erase the audience or invalidate a still-live refresh token. | Send the same `resource` value on authorization and every token request; publish the refresh-token resource column before enabling issuance; do not issue tokens through a bypass route or alternate repository. |
| Authorization resource state loss | Request-local or node-local cache state disappears between authorization, login, and consent, preventing the validated resource from reaching the code. | Resource state is keyed by a hash of Passport's opaque approval token, retained for the browser-session lifetime, and issuance fails closed when it cannot be recovered. | Use a persistent Laravel default cache store shared by every authorization-server node; never use the `array` store for this flow, and preserve the configured prefix for at least the authorization-state TTL. |
| OAuth issuer mix-up | A client accepts an authorization response or bearer token from an unintended issuer. | Issuer metadata is taken from the exact configured issuer; optional RFC 9207 decoration uses that exact value; resource-bound JWT validation checks `iss`. | Use one canonical issuer per deployment, enable RFC 9207 only when its middleware covers every authorization/consent response, and verify metadata after proxy/tenant changes. |
| OAuth authorization response leakage or redirect abuse | A browser/cache retains authorization state or errors, or an invalid/revoked client uses pre-validation as a redirector. | Authorization and consent responses carry `Cache-Control: no-store` and `Pragma: no-cache`. Errors redirect only after loading an active client and matching the exact registered callback; omission is accepted only when one callback is registered. | Keep package middleware on every authorization/consent route, preserve exact redirect registration, and revoke compromised clients rather than only hiding their UI. |
| Dynamic-client scope escalation | A public client registers narrowly and later asks for broader application permissions. | Registration scopes are checked against the application catalog and stored on the client; dynamic-client requests are always required to be a subset of registered scopes (or the configured catalog when registration omitted one); consent remains in the flow; refresh cannot add scopes. DCR parses its bounded raw JSON document so Laravel's empty-string normalization cannot change an explicitly empty scope into an omitted scope. | Apply the OAuth migration and make the configured scope catalog the sole source of application permissions. The legacy `enforce_registered_scopes` switch is not a security bypass. |
| Public-client secret misuse | A public MCP client receives a reusable secret or is treated as trusted merely because it used DCR. | DCR creates `confidential:false` clients with no response secret; only public auth-code + refresh grants are accepted; the shared consent path remains active. The accepted application types are `native` and `web`; loopback HTTP is allowed only for native/unspecified development clients, while hosted/web clients require HTTPS. | Do not add a client secret to native/loopback or hosted public clients, and do not mark dynamic clients first-party in an application policy/model override. |
| Static key with connection rights | A personal API token opted in to an MCP connection scope (`credentials.personal_token_connection_scopes`) is copied from a client config or log and used to connect as its owner, with no consent screen naming the client. | Off by default (`[]`); only listed scopes that are also `resource_required_scopes` entries, in the catalog and not excluded are offered, to personal tokens only; once opted in, every token carrying a connection scope is capped at `personal_token_connection_max_lifetime` (default `P30D`, invalid fails closed); the token is resource-bound and accepted only on `ExpectOAuthResource` routes; issuance stays browser-only with the secret shown once; listings flag connection tokens. | Opt in only for clients that cannot run OAuth; keep the cap short; removing a scope from the list does not revoke issued tokens, so revoke flagged tokens when withdrawing the option. |
| Protected-resource discovery failure | A client cannot discover the authorization server or does not understand the API challenge. | Reusable RFC 9728 metadata and `WWW-Authenticate` helpers include `authorization_servers`, supported scopes, bearer method, and `resource_metadata` when configured. | Route the metadata document at the exact configured URI and return the helper's challenge from the MCP endpoint's unauthenticated/insufficient-scope responses. |
| Disabled server still issues credentials | An operator turns off metadata/DCR but Passport's separately registered authorization or token routes continue processing existing clients and refresh grants. | `EnsureOAuthServerEnabled` returns a non-cacheable 404 before application-owned Passport routes execute. Package metadata and DCR controllers enforce the same opt-in switch themselves. | Install the gate on every Passport authorization/token route, clear cached configuration after changing the flag, and revoke existing credentials separately when required. |
| Unsafe client metadata retrieval | A URL-form client ID causes server-side fetches into private infrastructure. | Client ID Metadata Documents are not enabled or advertised in this release; no arbitrary client URL is fetched. | Use DCR compatibility for now. Do not add `client_id_metadata_document_supported` until the follow-up implementation includes URL identity resolution, bounded fetches, redirect policy, DNS/IP SSRF defenses, and safe caching. |
| Dependency compromise | Composer package or transitive dependency is compromised. | Package is versioned and installable from tagged GitHub source. | Pin Composer lockfiles, review dependency updates, run CI, monitor advisories. |

## Design decisions

- **Email is a recovery factor for passwordless accounts.** Laravel users keep a random password hash, so the email-based reset flow remains usable even for users who only have passkeys. This is a deliberate trade-off in favor of recovery over phishing-resistance. Apps that handle high-risk accounts (admin, finance, regulated data) should disable email reset for passkey-only users in their `AuthUserPolicy` and require an out-of-band recovery path.
- **`AuthAuditLogger` defaults to a no-op.** Apps that do not bind an implementation will silently lose detection signal for password changes, passkey registrations/deletions, suspicious 2FA reports, and failed verifications. Treat binding a real logger as a security requirement, not an enhancement.

## Known gaps

These are gaps in package behavior that the threat table flags above. They are listed here so they remain visible until fixed in the package itself.

- **Password change does not revoke other sessions.** `AuthenticatedPasswordController::update` updates the hash but does not call `Auth::logoutOtherDevices` and does not rotate the user's remember token. A hijacked session survives the password change. Mitigation: consumers wrap or replace the route until the controller is hardened.
- **Passkey registration has no recently-authenticated requirement.** Any authenticated session can add a credential. Apps should layer `password.confirm` (or equivalent) middleware on `/api/passkeys/register/options` and `/api/passkeys/register`.
- **No package-level rate limiting on auth endpoints.** 2FA verify/resend, 2FA report, and passkey assertion endpoints rely entirely on consumer-applied rate limits. Reset requests carry the password broker's own recently-created-token throttle, which is not a substitute for a route limiter. The package could ship sensible defaults via `RateLimiter` definitions.
- **No per-attempt failure or resend cap on 2FA.** An attempt row can absorb unlimited wrong codes until it expires, and each resend issues a fresh one.
- **2FA attempts are consumed with a read-then-write.** Two concurrent submissions of the same valid code can both pass the `isValid()` check before either marks the row used. Making consumption a single conditional update would close it.
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
- Configure `bherila-auth.passkeys.allowed_origins` for every trusted production origin.
- Ensure all auth routes are HTTPS-only in production.
- Ensure cookies are secure and same-site.
- Keep CSRF middleware enabled for browser auth routes.
- Add rate limiting to passkey options/auth, password reset, password change, and 2FA endpoints.
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
