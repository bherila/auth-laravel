# Changelog

Notable changes per release. Versions follow the tags published to
[Packagist](https://packagist.org/packages/bherila/auth-laravel); anything older than
the first entry here is in the git history.

## Unreleased

### Provider identity enforcement for browser sessions (opt-in)

- New `provider_identity` configuration section, off by default
  (`BHERILA_AUTH_PROVIDER_IDENTITY_ENABLED`).
- `ProviderIdentityPolicy` decides whether a provider identity may still act through a credential
  established at a given generation, independent of the credential type. Every credential of one
  person shares one status observation per freshness window (a configurable cache store), and a
  credential keeps the observation's time rather than "now", so sharing never extends freshness.
  A newer generation still ends an older credential; it is never adopted.
- `ProviderSession::establish()` wraps `remember()` for the login callback: with enforcement on, a
  login whose generation cannot be remembered is undone and reported as unavailable; with it off,
  the baseline is still remembered when available, so enabling enforcement later does not end
  every session at once.
- `RequireActiveProviderSession` middleware ends a browser session whose identity was disabled,
  deleted, reset or ungranted: log out, invalidate, new CSRF token, then a redirect
  (`expired_redirect_route`) or a JSON 401. An unavailable provider answers a retryable 503 and
  keeps the session. Unsafe methods always check freshly. Only stateful guards are checked.
- `ProviderBindingResolver` (default `ColumnProviderBindingResolver`, columns from configuration)
  says where an account's provider binding lives. Unbound accounts are left to the application's
  login policy; an incomplete binding or one naming another provider is refused, never treated as
  unbound.
- `ProviderSession::assertActive()` now goes through the shared policy; its behaviour for a single
  session is unchanged.

### Provider identity enforcement for OAuth credentials (opt-in, same switch)

- Authorization codes and access tokens record the provider subject and generation they were
  authorized under (new nullable columns, migration `add_provider_identity_to_oauth_credentials`);
  exchanged and refreshed tokens inherit the stamp instead of fetching a new generation.
- Bearer use is refused when the identity ended (401) and answers a retryable 503 when the provider
  is unavailable; refresh checks freshly and never consumes the refresh token during an outage.
- Credentials issued before enforcement have no stamp and are refused once it is enabled: connectors
  authorize again once.
- `ProviderIdentityTokens::verifyUser()` for a fresh check before privileged operations.
- `ProviderSessionExpired` and `ProviderStatusUnavailable` render as 401 and 503 when uncaught.
- The agent profile refuses Passport's transient-token cookie route.

### Identity tombstone consumer (opt-in)

- New `bherila-auth:consume-identity-tombstones {--limit=} {--max-pages=4}` reads the identity
  provider's pending deletion tombstone feed with the `oauth_client` credential, hands each
  tombstone to the application's `BWH\Auth\OAuth\Lifecycle\IdentityTombstoneHandler`, and
  acknowledges it only after the handler returns (its local deletion has committed). A handler
  failure leaves that tombstone unacknowledged and records it in a retry table, so it is retried
  first on every later run; the run continues, and the command exits non-zero.
  The cursor advances only after a whole page is recorded and is kept per provider/client; a lease
  in the cursor table (`lease_seconds`, default 900) keeps runs from overlapping, renewed before
  each handler call so that at least `handler_budget_seconds` (default 300) remain. Output and
  logs carry counts and tombstone ids, never subjects. See [docs/identity-tombstones.md](docs/identity-tombstones.md).
- Requests are paced to `requests_per_minute` (default 30) so a run leaves half of the provider's
  shared 60-a-minute reconciliation allowance to session status checks; pages default to 25.
- New `identity_tombstones` config section (`connection`, `table`, `retry_table`, `lease_seconds`,
  `handler_budget_seconds`, `page_limit`, `requests_per_minute`) and
  a separately published migration group, `bherila-auth-identity-tombstone-migrations`, for the
  cursor and retry tables.
- **Nothing changes until an application binds the handler**, publishes the migration and
  schedules the command.

### Shared reconciliation transport

- `ProviderIdentityStatusClient` now sends through an internal transport shared with the tombstone
  client. Its constructor, request, validation and exception messages are unchanged.

## v0.22.1 - 2026-10-10

### Personal API tokens may carry MCP connection scopes (opt-in)

- New `oauth_server.credentials.personal_token_connection_scopes` (default `[]`, off) names the
  connection scopes (`resource_required_scopes` entries, such as `mcp:use`) a personal API token
  may carry, for agent clients that reach an MCP endpoint only with a static bearer key. A listed
  scope is offered only if it is also in the scope catalog and not in `credentials.excluded_scopes`,
  and only to personal tokens, never to OAuth apps.
- New `oauth_server.credentials.personal_token_connection_max_lifetime` (default `P30D`) caps the
  lifetime of any token carrying a connection scope once the opt-in is on; a longer offered lifetime
  is refused with 422, and an invalid value offers no connection scope.
- Such a token is resource-bound like every personal token and accepted only on routes marked with
  `ExpectOAuthResource`. When opted in, the credentials index adds `token_connection_scopes`,
  `connection_token_lifetimes` and a per-token `connection` flag. `ApiCredentialService` gains
  `connectionScopes()`, `connectionScopesEnabled()`, `connectionLifetimes()`, `tokenScopes()` and
  `carriesConnectionScope()`; `ConfiguredGrantableScopes` gains static `catalog()` and
  `excludedScopes()`.
- **Tradeoff:** a long-lived static key with connection rights and no per-client consent screen.
  Removing a scope from the list stops new tokens, not issued ones. See the README.
- **With the default configuration nothing changes:** the same index, the same refusals and the
  same issued tokens.

## v0.22.0 - 2026-10-10

### Delegated access contract versions 1 and 2 removed (breaking)

- `DelegatedContract` speaks contract version 3 only. `DelegatedContract::VERSION_1` and
  `VERSION_2` are removed, with every version 1 and 2 request field, capability, state and access
  validator. `request()` and `response()` now default to `VERSION_3`; any other version is
  `unsupported_contract_version` (500).
- **Applications already on version 3 need no change.** The endpoint, the adapter interface and
  `AssertsDelegatedAccessAdapter` are unchanged. The provider drops its version 1 and 2 path:
  every call passing `VERSION_1` or `VERSION_2`, or relying on the old `VERSION_1` default, must
  pass `VERSION_3` or nothing.

### Receipts migration uses the receipt connection

- The receipts migration now checks for and creates its table on
  `bherila-auth.delegated_access.receipt_connection` rather than the default connection, which is
  where `DatabaseReceiptStore` reads and writes it. Applications that already copied this fix into
  their published migration need nothing; others with a separate receipt connection should create
  the table there.

## v0.21.0 - 2026-10-10

### Delegated access contract version 3 (breaking)

**The endpoint now serves contract version 3 only.** A request in version 1 or 2 is refused with
`invalid_request` (422), and adapter answers are validated as version 3. This is a coordinated
upgrade: every application serving the endpoint upgrades and implements the additions below in one
release, then the provider switches that application to version 3. A provider still on version 2
can no longer reach an upgraded application.

- **Search.** `subjects` and `workspaces` take an optional `query` (2 to 100 characters), matched
  case-insensitively on the label and email within the actor's scope, with the same cursor
  pagination. `DelegatedCursor::encode()` takes the query as a fourth argument and `after()` refuses
  a cursor from another search with `invalid_cursor`, now also `DelegatedRefusal::INVALID_CURSOR`.
- **Removal.** A new `remove` operation (`subject`, `expected_revision`, `operation_id`) strips the
  actor's whole projection, the application administrator flag included, keeps the account, its
  history and memberships outside the actor's view, refuses rather than removes part of it, and
  keeps the revision when there is nothing to remove. The endpoint refuses to send a removal answer
  that leaves anything in the projection. It is a write: `DELEGATED_ACCESS_WRITES_ENABLED` gates it.
- **`allowed_edits.remove`** (required boolean in every version 3 state): whether a removal by this
  actor would succeed now, a no-op included. False for an unprovisioned subject and whenever the
  removal would be refused; the contract refuses one offered over a protected membership or an
  administrator flag the actor may not change, and the conformance trait checks it both ways.
- **Metadata.** A state and each `subjects[]` listing entry may carry `provisioned_at`,
  `first_sign_in_at` and `last_seen_at` (ISO-8601 or null), and a workspace role a `description`.
- **Operation ids and receipts.** `update` and `remove` require an `operation_id` (32 to 64
  characters of `[A-Za-z0-9_-]`, case-sensitive, never the assertion `jti`). The endpoint claims each
  write in the new `bherila_auth_delegated_receipts` table (keyed by a digest of the id, so a
  case-insensitive collation cannot merge two ids) before the adapter runs, answers a repeat from the
  stored receipt without calling the adapter, refuses the same id on a different request with
  `invalid_request`, and answers a write still being decided with `operation_in_progress` (503). A
  claim left unfinished (a request that died mid-write) stops blocking after ten minutes
  (`DatabaseReceiptStore::PENDING_LEASE_SECONDS`): a repeat of the same request then claims it again
  and the adapter's revision check decides afresh. The
  new `receipt` operation returns the stored outcome or `unknown`. **Publish and run the
  `bherila-auth-delegated-access-migrations` again before upgrading**: writes are refused with
  `receipt_storage_unavailable` until the table exists. `DELEGATED_ACCESS_RECEIPT_CONNECTION`
  (defaulting to the nonce connection) chooses its connection.
- `bherila-auth:prune-delegated-nonces` also deletes receipts older than 30 days, when the receipts
  table is installed (it still succeeds without it); schedule it daily.
- `DelegatedRequestContext` carries the write's `operationId`.
- `ApplicationAccessAdapter::handle()` keeps its signature; it now receives `remove` and searches.
- `AssertsDelegatedAccessAdapter` drives version 3 and adds
  `assertDelegatedSearchStaysInScope()`, `assertDelegatedRemoveStripsOnlyTheManagedProjection()`,
  `assertDelegatedRemoveRefusedWithoutPartialChange()`, `assertDelegatedMetadataIsWellFormed()` and
  `assertDelegatedReceiptsReplayThroughTheEndpoint()`, which goes through the real route.

### Provider-side builders

- `DelegatedContract::VERSION_3`: `request()` and `response()` build and validate every version 3
  message, `receipt()` validates a receipt for the write it was asked about, and
  `operationId()`, `validOperationId()` and `validQuery()` are new.
- **Deprecated:** `DelegatedContract::VERSION_1` and `VERSION_2`, and the version 1 and 2 paths of
  `request()` and `response()`. They remain only so a provider can talk to applications that have
  not upgraded during the cutover, and are removed in the next release.
- `adapterAnswer()` now wraps and validates a version 3 answer.

## v0.20.0 - 2026-10-09

### Delegated access: account-only applications

- A version 2 `capabilities` response may advertise `workspace_roles: []`. The application is then
  account-only: accounts, the application administrator flag and provisioning, no workspaces. Every
  access value it sends or accepts carries `workspaces: []`. Workspace applications, their
  capabilities and their adapters are unchanged; a provider on an earlier release refuses the empty
  list as `invalid_response`. The README explains why the empty list, not a new flag, is the signal.
- `DelegatedContract::accountOnly()` says whether a capabilities response describes one, and
  `fitsCapabilities()` checks that an answer reports no memberships, offers no workspace edits and
  lists no workspaces for it.
- `DelegatedContract::rolesAreAdvertised()` now accepts an access value without memberships when no
  roles are advertised, and still refuses one whose capabilities carry no `workspace_roles` list.
- `AssertsDelegatedAccessAdapter` runs against an account-only adapter: the membership checks
  return rather than skip, any membership must be refused, and every answer must fit the
  capabilities. `assertDelegatedActorRefusedEverywhere()`'s workspace argument is optional for it.

## v0.19.0 - 2026-10-08

### Delegated access: issuer binding, request context, a write switch and normative update semantics

- The actor assertion's issuer must now be the sign-in provider (`oauth_client.base_url`, a
  trailing slash aside), or every request is refused with `invalid_verifier_configuration`. A
  subject is only meaningful in the namespace it was issued in. **Check `DELEGATED_ACCESS_ISSUER`
  against `oauth_client.base_url` before upgrading.**
- `DELEGATED_ACCESS_WRITES_ENABLED` (default `false`): until it is set, `update` is refused with
  `not_authorized` before the adapter. **Deployments accepting writes today must set it.**
- `DelegatedRequestContext` (issuer, subject, application, `jti`, operation) is bound in the
  container for the adapter's call, so application audit can correlate with the provider's.
- `DelegatedRefusal` names the refusal outcomes and their statuses, adding `protected_membership`
  and `role_not_grantable` (both 403).
- `DelegatedContract::adapterAnswer()` wraps and validates an adapter's version 2 answer exactly as
  the endpoint does (exact top-level and page-entry keys, then `response()`).
- The README states the update semantics every adapter owes, and
  `BWH\Auth\Testing\AssertsDelegatedAccessAdapter` checks them against an application's adapter.

## v0.18.0 - 2026-10-08

### Person-registered clients are held to their stored scope ceiling

- `EnforceOAuthResourceIndicator` now refuses an authorization request beyond a client's stored scopes
  (`invalid_scope`, before consent) for **any** client with a stored ceiling, not only
  self-registered ones. Apps that a person or the application registers with chosen permissions
  can no longer ask for more at the consent screen. Passport already dropped those scopes from
  the token, but the person was shown them and asked to approve them.
- Clients without stored scopes are unchanged. Self-registered clients without stored scopes
  still fail closed.

### Trusted proxies limited to Cloudflare's published ranges

- `BWH\Auth\Http\TrustedProxies` and the opt-in `bherila-auth.trusted_proxies` config
  (`BHERILA_AUTH_TRUSTED_PROXIES=true`, `TRUSTED_PROXIES`). When applied, X-Forwarded-For and its
  scheme are honoured only from the configured proxies, never the forwarded port or host:
  - `cloudflare` (the default), Cloudflare's published IPv4/IPv6 ranges;
  - an explicit list;
  - `*`, only where a firewall admits the proxy alone;
  - empty, to trust nothing.

  The client is the address the edge appended. A direct connection's forged headers are ignored.
  Off by default, so upgrading changes nothing.
- `bherila-auth:check-cloudflare-ranges` compares the trusted ranges with Cloudflare's published
  list and exits non-zero on drift. Run it from a scheduled CI job: a stale list fails quietly back
  into shared per-edge rate-limit budgets.

### Credential service: OAuth apps and personal API tokens

- `BWH\Auth\OAuth\Credentials\ApiCredentialService` and opt-in session routes
  (`oauth_server.credentials.enabled`, under `credentials.prefix`) for a person's own:
  - **personal API tokens:** chosen scopes, a lifetime from `credentials.token_lifetimes` (ISO-8601
    durations, so `PT4H` gives a short quick-setup token), and resource-bound;
  - **OAuth apps:** exact HTTPS or loopback redirects, public or confidential, created with their
    owner so they're never first-party, with a scope ceiling enforced at consent.
- **Secrets** are returned once in a no-store JSON body. Nothing is flashed or stored readable.
- **Issuance** answers to the OAuth server's kill switch; listing and revocation stay available.
- **Deleting an app** revokes its access and refresh tokens, on Passport's own connection.
- **Contracts the application can bind:**
  - `CredentialOwnerResolver`, the model that owns credentials (default: the user, or
    `credentials.owner_model`);
  - `GrantableScopes`, the scopes on offer (default: the catalog minus MCP-connection scopes and
    `credentials.excluded_scopes`). Bind your registry's REST scopes so no credential is offered a
    scope nothing uses.
- Personal tokens are told apart by owner and name, and a personal-access client is created only
  when none exists, so it never displaces another caller's.

### Operations tooling for the agent preset

- `bherila-auth:prune-dynamic-clients` (`--days`, `--pretend`) removes self-registered clients that
  are unused past `dynamic_clients.retention_days` (default 30), with their tokens and codes.
  - It keeps any client with a live access or refresh token.
  - It never touches person-registered clients.
  - It defers when a live refresh token can't be attributed to a client.
  - Schedule it daily.
- `BWH\Auth\Testing\AssertsAgentOAuthContract` lets an application check the agent-API OAuth
  contract against its own routes:
  - discovery;
  - a self-registered client completing PKCE with no `resource`;
  - tokens bound to the configured resource;
  - a protected route;
  - refresh.
- Keys and migrations: use Passport's `passport:keys`, and publish `bherila-auth-migrations` for the
  resource and registration columns.

### Agent API preset

- `BWH\Auth\OAuth\Server\AgentOAuthServer` gives the agent-API authorization-server profile in one
  call: `config()` for the `oauth_server` block, `passportMiddleware()`, and `routes()` for the
  discovery documents and self-registration.
- **What the profile sets:**
  - RFC 8707 binding to `APP_URL/api/v1`, with an omitted `resource` taken as that resource;
  - S256 PKCE for every client;
  - public-only self-registration;
  - `none`, `client_secret_basic` and `client_secret_post` advertised.
- Every URL comes from the application URL, so forks need no host-specific settings.

## v0.17.0 - 2026-10-08

### Opt in to binding credentials whose request omits `resource`

- `oauth_server.assume_omitted_resource` (`OAUTH_ASSUME_OMITTED_RESOURCE`, default `false`). When
  enabled, an authorization, token or refresh request that omits RFC 8707 `resource` is treated as
  naming the one configured resource, so its code, access token and refresh token are
  audience-bound to it. Generic OAuth clients that never send the parameter then receive
  credentials the application's `ExpectOAuthResource` routes accept, instead of an `invalid_target`
  refusal or an unbound token those routes reject. A different explicit resource is still
  refused at every boundary.
- With the option on, an unbound authorization code or refresh token issued before it was enabled
  can no longer be exchanged, because the request now names a resource the credential lacks; those
  clients authorize again.
- `OAuthResourceIndicator::assumesOmittedResource()` and `requestNamesResource()`;
  `requestResource()` returns the configured resource for an omitted parameter when the option is
  on.

## v0.16.0 - 2026-09-15

### Distinguish rejected tokens from introspection outages

- Active token contexts that are malformed, expired, not yet valid, or do not match the
  configured issuer/resource/audience now throw `OAuthTokenValidationException`. Resource
  servers can map that exception to 401 `invalid_token`, while mapping the parent
  `OAuthIntrospectionException` to a retryable 503 for configuration, transport, provider,
  and response-envelope failures.
- `OAuthTokenValidationException` extends `OAuthIntrospectionException`, preserving existing
  broad exception catches. Tokens reported `active: false` continue to return an inactive
  result without claims.

## v0.15.0 - 2026-09-14

### Serve the delegated access endpoint from the package

- `POST /application-access` (contract version 2) is served by `DelegatedAccessController` once an
  application binds `BWH\Auth\OAuth\DelegatedAccess\ApplicationAccessAdapter`. The route is absent
  without a binding and answers 404 until `DELEGATED_ACCESS_ENABLED`. Body bound, bearer,
  verification, nonce consumption, version and application checks, and response validation are
  the package's; the adapter decides authorization and returns the operation's fields.
- `DelegatedAccessSettings` reads `bherila-auth.delegated_access` (`DELEGATED_ACCESS_*` and an
  explicit `OAUTH_PROVIDER`). `NonceStore` defaults to `DatabaseNonceStore` on the configured
  connection. Requests are limited to 120/min per IP once enabled (429 `rate_limited`); a
  disabled endpoint answers 404 without counting. Answers must carry exactly the operation's
  top-level fields and encode within `MAX_RESPONSE_BYTES`, or they are reported and never sent.
  The `Bearer` scheme is matched case-insensitively.
- `DelegatedCursor` (encrypted keyset cursors within the 512-byte bound), `PendingAccount`
  (placeholder contact details for provisioned accounts), and the
  `bherila-auth:prune-delegated-nonces` command.

## v0.14.0 - 2026-09-14

### Delegated access contract version 2

- `DelegatedContract::request()` and `response()` take the agreed contract version as an optional
  last argument; the default is version 1, validated exactly as before. Version 2 carries
  application-defined workspace roles (`capabilities.controls.workspace_roles`), per-membership
  `editable` flags, a `provision` allowed edit, and provisioning through an `update` whose
  `expected_revision` is `null`, optionally with a `display_name`. `advertisedRoleIds()` and
  `rolesAreAdvertised()` let a provider check an access value against the roles an application
  advertised. An unsupported version is refused as a configuration error. See the README (#42).
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
