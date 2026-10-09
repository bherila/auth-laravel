# bherila/auth-laravel

Shared Laravel auth package for BWH applications.

The companion React component package is
[`bwh-auth`](https://github.com/bherila/auth-react).

Includes:

- OAuth 2.0 authorization-code client mechanics with PKCE and validated identity responses
- Opt-in [provider browser-session generation verification](docs/provider-session-verification.md)
- opt-in Passport authorization-server helpers for metadata, dynamic public-client registration,
  S256 PKCE, RFC 8707 resource binding, RFC 7662 backchannel introspection, and a shared consent experience
- WebAuthn/passkey registration and login
- email-code 2FA challenge service, API routes, and mailables
- password reset request/reset/change API routes and mailables
- passkey and 2FA database tables
- login audit logging: an owned `auth_audit_log` table, a default database logger, binary IP storage, optional read endpoints, and opt-in retention (see "Login audit logging")
- policy and audit contracts for app-specific behavior

## Upgrading to v0.12.0 (separate OAuth resource servers)

This release adds authenticated RFC 7662 token introspection for a protected resource
that is deployed separately from its Passport authorization server. It also makes the
three resource-aware Passport repositories extensible so an authorization-server app
can layer account, grant, or credential-version policy on top of the package checks
without replacing resource binding.

The authorization server owns the route and explicitly opts in. Pin each confidential
introspection client to one exact resource in server-side configuration; the request
cannot select or broaden that resource:

```php
use BWH\Auth\Http\Controllers\OAuthTokenIntrospectionController;

Route::post('/oauth/introspect', OAuthTokenIntrospectionController::class)
    ->middleware('throttle:60,1');

'oauth_server' => [
    // existing server configuration...
    'introspection' => [
        'enabled' => true,
        'clients' => [[
            'id' => env('OAUTH_INTROSPECTION_CLIENT_ID'),
            // Store only password_hash($secret, PASSWORD_DEFAULT) here.
            'secret_hash' => env('OAUTH_INTROSPECTION_CLIENT_SECRET_HASH'),
            'resource' => 'https://resource.example.test/mcp',
        ]],
    ],
],
```

The resource server configures the same confidential credential and its expected
issuer/resource, then resolves `OAuthTokenIntrospector`. The remote implementation does
not positively cache responses: revocation and authorization-server account policy are
therefore rechecked before every protected request.

```php
use BWH\Auth\OAuth\Introspection\OAuthTokenIntrospector;

$token = app(OAuthTokenIntrospector::class)->introspect($request->bearerToken() ?? '');
```

Set `OAUTH_INTROSPECTION_ENDPOINT`, `OAUTH_INTROSPECTION_CLIENT_ID`,
`OAUTH_INTROSPECTION_CLIENT_SECRET`, `OAUTH_RESOURCE_ISSUER`, and
`OAUTH_RESOURCE_URI`. A token the authorization server reports as inactive returns
`active=false` without claims. An `active: true` token with malformed claims, missing
binding, the wrong issuer/resource/audience, an expired `exp`, or a future `nbf` throws
`OAuthTokenValidationException`. Map either outcome to a 401 `invalid_token` response
with the appropriate `WWW-Authenticate` challenge so the client can reauthorize.
Configuration, connection, HTTP/client-authentication, and malformed response-envelope
failures throw `OAuthIntrospectionException`; map those to 503 because retrying may
succeed. Catch the validation subtype before its parent:

```php
use BWH\Auth\OAuth\Introspection\OAuthIntrospectionException;
use BWH\Auth\OAuth\Introspection\OAuthTokenValidationException;

try {
    $token = app(OAuthTokenIntrospector::class)->introspect($request->bearerToken() ?? '');
} catch (OAuthTokenValidationException) {
    // 401 invalid_token
} catch (OAuthIntrospectionException) {
    // 503 authorization server unavailable
}
```

`OAuthTokenValidationException` extends `OAuthIntrospectionException`, so existing broad
catches remain source-compatible while consumers adopt the more precise mapping.
The endpoint must use HTTPS (except loopback development) and the issuer's exact origin;
redirects are never followed, so neither the bearer token nor confidential-client
credential can be forwarded to another host.
The resource application must still map `sub` to a local account and enforce all local
authorization policy itself.

## Upgrading to v0.10.0 (breaking)

**Runtime floor.** This release requires **PHP 8.4+** and **Laravel 13**, dropping
PHP 8.3 and Laravel 12. Earlier releases advertised PHP 8.2 and Laravel 12 or 13, but
the code used typed class constants (PHP 8.3+) and CI only ever installed one
combination, so neither claim held. The supported set is now one line, and CI runs the
floor, the newest runtime, and `--prefer-lowest`.

Dropping a platform is a breaking change, so this ships as **v0.10.0**, not a 0.9.x
patch: for a pre-1.0 package `^0.9` means `>=0.9.0 <0.10.0`, which is exactly the
boundary that keeps a consumer still on PHP 8.3 from being upgraded into a package it
cannot run. Update the requirement deliberately, alongside the runtime:

```sh
composer require bherila/auth-laravel:^0.10
```

**Run the migrations.** Package migrations are published, not loaded, so
`composer update` alone does not apply them. Passkey registration writes `rp_id`,
which means an app that has not applied `2026_08_24_120000_add_rp_id_to_passkey_credentials`
fails when a user enrolls a passkey:

```sh
php artisan vendor:publish --tag=bherila-auth-migrations
php artisan migrate
```

**Republishing the config is optional now.** Package defaults are merged into the
published config key by key, so a `config/bherila-auth.php` that predates a release
no longer erases the nested defaults added since. Republish (`--tag=bherila-auth-config`,
`--force`) only if you want the new keys and comments in the file itself.

**Behaviour changes to check before deploying:**

- `two_factor.allow_test_code` now defaults to **false**, and even when true the fixed
  code is accepted only in the environments listed in `two_factor.test_code_environments`
  (`local`, `testing`) **and** only for accounts flagged `is_test`. Previously either the
  setting or an `is_test` account was enough, and the setting defaulted to on everywhere
  except `APP_ENV=production` — a staging deploy accepted `999999` for every account.
  All three conditions are required, so the environment variable alone is no longer
  enough outside `local` and `testing`: a staging deploy that genuinely needs the fixed
  code must set `BHERILA_AUTH_ALLOW_TEST_2FA_CODE=true`, add its environment to
  `two_factor.test_code_environments` in the published config, and flag the specific
  accounts `is_test`.
- `canLogin()` is now rechecked before the 2FA login completes and before the
  post-reset auto-login. A password reset still succeeds for a disallowed account, but
  it no longer hands out a session.
- `/api/change-password` and the authenticated passkey routes now carry
  `RequireActiveUser` in addition to `auth`, so they answer 403 for an account your
  policy will not log in.
- `POST /api/auth/forgot-password` goes through Laravel's password broker, so a second
  request within the broker's `throttle` window (`config/auth.php`, 60 seconds by
  default) sends no mail. The response is unchanged.
- `POST /api/auth/two-factor/resend` refuses an expired attempt instead of issuing a
  fresh code for it.
- The package dispatches Laravel's `PasswordResetLinkSent` and `PasswordReset` events.

OAuth/MCP authorization-server changes described below ship in `v0.11.0`. Consumers should not enable
`oauth_server.enabled` until they have run the OAuth metadata migration and added the
resource-aware Passport middleware/configuration.

## Upgrading to v0.11.0 (OAuth/MCP server)

This is an opt-in server capability. Existing OAuth clients and the identity-provider
role keep Passport's normal unbound-token behavior unless an application enables
`oauth_server.enabled` and routes the server helpers. When Passport is installed, the
package keeps validation of previously issued resource-bound tokens active even after
the issuance switch is disabled; it delegates unbound token issuance and persistence to
Passport while disabled. An application that currently owns custom resource-aware Passport
repositories should migrate to the package repositories only after verifying its
configured resource and applying the new migration; remove duplicate bindings so one
repository is responsible for the resource checks.

The configured resource must match what the MCP client sends and what the protected
endpoint represents. For example, if the endpoint is `/api/v1/mcp`, do not silently use
`/api/v1` unless that base URI is intentionally the resource covering all of those
endpoints. Update the protected-resource metadata URL and API `WWW-Authenticate`
challenge at the same time. If the metadata URL is omitted, the helper derives the
RFC 9728 path-based well-known URL from `resource`.

## Upgrading to v0.5.0 (breaking)

This release adds a required method to the `AuthUserPolicy` contract:

```php
public function canLogin(Authenticatable $user, Request $request): bool;
```

It is the single gate for account-state checks (active, approved, not disabled)
and is now enforced by the new `RequireActiveUser` middleware on the package's
audit routes, so a role-only admin gate can no longer let a pending or disabled
account through.

Because the contract gained a required method, this is a **breaking change** and
must be released as **v0.5.0** (not a 0.4.x patch) so consumers opt in. Consuming
apps that **implement `AuthUserPolicy` directly** must add `canLogin()` when they
upgrade — typically delegating to their model:

```php
public function canLogin(Authenticatable $user, Request $request): bool
{
    return $user instanceof User && $user->canLogin() && $user->hasVerifiedEmail();
}
```

Apps that extend `DefaultAuthUserPolicy` inherit a working `canLogin()` (it
duck-types `$user->canLogin()`, falls back to `is_disabled`, defaults to `true`)
and need no change.

## Install

```sh
composer require bherila/auth-laravel
php artisan vendor:publish --tag=bherila-auth-config
php artisan vendor:publish --tag=bherila-auth-migrations
php artisan migrate
```

Routes are auto-registered by `BWH\\Auth\\AuthServiceProvider`; consuming apps should not copy or publish package route files. Publishable assets are limited to config, migrations, and optional mail views.

Publish mail views only if the consuming app wants to customize the package email templates:

```sh
php artisan vendor:publish --tag=bherila-auth-views
```

Consumers install from Packagist and should not add a GitHub VCS repository entry.
For unreleased local package development only, use a Composer path repository:

```json
{
  "repositories": [
    {
      "type": "path",
      "url": "../auth-laravel",
      "options": { "symlink": true }
    }
  ]
}
```

Then run `composer require bherila/auth-laravel:@dev`. Composer reads the
repository-root `composer.json` and autoloads the package from `src`. Remove the
path override before validating a published release.

## Configuration

Published config lives at `config/bherila-auth.php`. Important settings:

- `routes.prefix`: defaults to `api`, so package endpoints are under `/api/...`.
- `routes.middleware`: defaults to `['web']` so session auth and CSRF work in Laravel/Vite apps.
- `routes.passkeys`, `routes.password_resets`, `routes.change_password`, and `routes.two_factor`: enable or disable route families independently when an app owns one part of the auth surface locally.
- `password_resets.reset_url`: reset-page URL generated into password reset emails. Defaults to `{APP_URL}/reset-password/{token}?email={email}`.
- `password_resets.verify_email_on_reset`: optionally marks verified-email users verified after a successful reset.
- `password_resets.redirect_after_reset`: JSON redirect returned after a successful reset.
- `BHERILA_AUTH_PASSWORD_RESET_MAIL_SUBJECT`: optional reset-link mailable subject override.
- `BHERILA_AUTH_PASSWORD_NOTICE_MAIL_SUBJECT`: optional password reset/change notice subject override.
- `two_factor.expires_minutes`: 2FA code expiry. Defaults to 15 minutes.
- `two_factor.allow_test_code`: allows the configured test code. Defaults to `false`; when enabled it applies only in `two_factor.test_code_environments` and only to accounts flagged `is_test`.
- `two_factor.test_code_environments`: environments in which the test code may be honoured. Defaults to `['local', 'testing']`; an empty list means any environment.
- `BHERILA_AUTH_TWO_FACTOR_MAIL_SUBJECT`: optional email 2FA subject override.
- `passkeys.user_verification`: WebAuthn user verification requirement. Defaults to `preferred`; set to `required` for passkeys used as a stronger security factor.
- `passkeys.resident_key`: WebAuthn resident key requirement. Defaults to `preferred`.
- `throttle.enabled`: enables audit-log-backed password-login lockout. Defaults to `false`.
- `throttle.max_attempts`: failed attempts allowed for the same key before lockout. Defaults to `5`.
- `throttle.decay_minutes`: lockout/window length. Defaults to `15`.
- `throttle.key`: how failed attempts are grouped — `email` (per account, across all IPs), `ip` (per source, across all accounts), or `email_ip` (per account+source pair). Defaults to `email_ip`; any unrecognized value falls back to `email_ip`.
- `users.force_change_password_attribute`: optional boolean column to clear after password reset/change, such as `force_change_pw`.
- `migrations.drop_tables_on_rollback`: defaults to `false` so package rollbacks do not drop existing app auth tables.

Enabling `throttle.enabled` only changes the package service behavior. Apps that use their own password-login controller must still call `ThrottlesLoginAttempts` or the `LoginThrottle` contract from that controller before attempting credentials. Publishing the config alone does not intercept custom `/login` routes.

The package migration uses `Schema::hasTable()` before creating its tables. This lets existing apps such as bwh-php keep an already-created passkey table without migration failure. It does not alter existing tables, so apps with older or different schemas should either point the package config at compatible tables or add an app-local migration for schema reconciliation. Rollback table drops are disabled by default to avoid deleting pre-existing auth data.

## API routes

With the default prefix, the package registers:

- `POST /api/auth/forgot-password`
- `POST /api/auth/reset-password`
- `POST /api/change-password`
- `POST /api/auth/two-factor/verify`
- `POST /api/auth/two-factor/resend`
- `GET /api/auth/two-factor/confirm/{token}`
- `POST /api/auth/two-factor/confirm/{token}`
- `GET /api/auth/two-factor/report/{token}`
- `POST /api/auth/two-factor/report/{token}`
- `GET /api/passkeys`
- `POST /api/passkeys/register/options`
- `POST /api/passkeys/register`
- `DELETE /api/passkeys/{id}`
- `POST /api/passkeys/auth/options`
- `POST /api/passkeys/auth`

When `audit.routes_enabled` is true (off by default), it also registers `GET /api/auth/audit-log`, `POST /api/auth/audit-log/{id}/suspicious`, and `GET /api/auth/audit-log/all`. See "Login audit logging".

## Ownership boundary

This package owns Laravel services, API routes, database migrations, controllers, and auth mailables. It intentionally does not ship application page Blade wrappers or Vite entrypoints. Each consuming app should create its own Blade pages and Vite entrypoints, then mount the shared `bwh-auth` React components where useful.

The package does include Markdown Blade templates for its mailables under `bherila-auth::emails.*`. Those are email templates, not page wrappers, and can be published/overridden with `php artisan vendor:publish --tag=bherila-auth-views`.

## Password reset integration

The package owns the JSON API endpoints and mailables. The consuming app owns the pages, including Blade wrappers and Vite entrypoints.

Create pages such as `/forgot-password` and `/reset-password/{token}` and mount
the shared `bwh-auth` components from the companion `auth-react` repository:

```tsx
import { PasswordResetRequestForm, ResetPasswordForm } from 'bwh-auth';
import { getAuthComponents } from '@/lib/auth-components';

export function ForgotPasswordPage() {
  return <PasswordResetRequestForm components={getAuthComponents()} />;
}

export function ResetPasswordPage({ token, email }: { token: string; email: string }) {
  return <ResetPasswordForm components={getAuthComponents()} token={token} email={email} />;
}
```

The reset email uses `password_resets.reset_url`. Set `BHERILA_AUTH_PASSWORD_RESET_URL` when the app uses a different route shape.

## Authenticated password change

The package registers `POST /api/change-password` behind `auth` middleware. It expects `current_password`, `password`, and `password_confirmation`, updates the authenticated user's password, sends `PasswordResetNoticeMail`, and returns JSON suitable for `bwh-auth`'s `ChangePasswordForm`.

The consuming app owns where this appears, such as an account settings page or dialog.

## Email 2FA integration

The package intentionally does not own password credential login because each app has different user approval, lockout, and onboarding rules. After the consuming app verifies email/password and decides the user may proceed, start a package 2FA challenge instead of logging in immediately:

```php
use BWH\Auth\Services\TwoFactorService;

$attempt = app(TwoFactorService::class)->startChallenge(
    $user,
    $request,
    $request->boolean('remember'),
);

return response()->json([
    'success' => true,
    'requires_2fa' => true,
    'attempt_token' => $attempt->token,
    'message' => 'A verification code has been sent to your email address.',
]);
```

The consuming app also owns the 2FA page wrapper and Vite entrypoint, for example `/login/two-factor/{token}`:

```tsx
import { TwoFactorForm } from 'bwh-auth';
import { getAuthComponents } from '@/lib/auth-components';

export function TwoFactorPage({ token }: { token: string }) {
  return <TwoFactorForm components={getAuthComponents()} attemptToken={token} />;
}
```

`TwoFactorForm` posts to `/api/auth/two-factor/verify`, can resend via `/api/auth/two-factor/resend`, and can report suspicious attempts via `POST /api/auth/two-factor/report/{token}`.

Email confirmation and report links are side-effect-free `GET` pages. The user must submit a CSRF-protected `POST` to complete login or report suspicious activity, which prevents common email security scanners from consuming one-shot login links.

## Mailables

Included mailables for password reset, password reset/change notices, and email 2FA:

- `BWH\Auth\Mail\TwoFactorLoginMail`
- `BWH\Auth\Mail\PasswordResetMail`
- `BWH\Auth\Mail\PasswordResetNoticeMail`

Views are loaded from the `bherila-auth::emails.*` namespace and can be overridden by publishing Laravel views if needed.

## App Integration

### OAuth authorization-server integration

Applications exposing a Passport-protected API can reuse the package's server-side
protocol and consent UX without enabling any routes automatically. Configure
`bherila-auth.oauth_server`, then point application-owned routes and middleware at:

- `BWH\Auth\Http\Controllers\OAuthMetadataController`
- `BWH\Auth\Http\Controllers\OAuthDynamicClientRegistrationController`
- `BWH\Auth\Http\Middleware\EnsureOAuthServerEnabled`
- `BWH\Auth\Http\Middleware\EnforceOAuthPkce`
- `BWH\Auth\Http\Middleware\EnforceOAuthResourceIndicator`
- `BWH\Auth\Http\Middleware\ExpectOAuthResource`
- `BWH\Auth\Http\Middleware\AppendOAuthAuthorizationResponseIssuer` (only when RFC 9207 is enabled)
- `BWH\Auth\OAuth\Server\OAuthProtectedResource`
- `bherila-auth::oauth.authorize`

The smallest MCP server configuration is conceptually:

```php
'oauth_server' => [
    'enabled' => true,
    'issuer' => 'https://example.test',
    'resource' => 'https://example.test/mcp',
    'protected_resource_metadata_url' =>
        'https://example.test/.well-known/oauth-protected-resource/mcp',
    'scopes' => [
        'mcp:use' => 'Connect through MCP',
    ],
'resource_required_scopes' => ['mcp:use'],
],
```

Register the same application-owned catalog with Passport during application
boot; package configuration defines policy but does not mutate Passport's global
scope registry:

```php
Passport::tokensCan(config('bherila-auth.oauth_server.scopes', []));
```

`resource` is the exact protected-resource identifier, not merely the authorization
server origin; its path and trailing slash are significant. The application declares which entries in its own scope catalog require
that resource. Set `protected_resource_scopes` when this protected resource should
advertise only a subset of the server catalog. The package carries the validated value through authorization state,
consent, the authorization-code record, token exchange, refresh-token exchange, the
signed JWT `aud` (and `resource`) claims, and the access- and refresh-token records. Its
Passport repository binding also checks the signed audience and issuer on every bearer
request, so a token issued for one configured resource cannot be replayed at another one.

Authorization resource state spans the authorization, login, and consent requests.
Configure Laravel's default cache repository as a persistent store shared by every
authorization-server node; the `array` store is request/process-local and is not
suitable. If that state is unavailable, the package fails closed rather than issuing
an unbound credential. Keep its TTL at least as long as the browser session lifetime
(the package defaults to that lifetime) and do not evict the configured
`authorization_state.cache_prefix` during an active authorization flow.

Add `EnsureOAuthServerEnabled` before the PKCE/resource middleware on every Passport
authorization and token route. The package's metadata and registration controllers
already honor the switch themselves, but Passport routes remain application-owned and
registered independently. Without this route middleware, changing
`oauth_server.enabled` to false does not by itself stop Passport from processing an
existing client or refresh grant. The switch hides issuance routes; revoke existing
credentials separately when an incident requires immediate credential invalidation.

When Passport is installed, the package keeps its resource-aware access-token repository
bound so outstanding bound credentials remain audience-restricted. Enabling
`oauth_server.enabled` additionally binds the resource-aware authorization-code and
refresh-token repositories and access-token entity. Routes are still application-owned.
A typical app exposes the two metadata controller methods and
uses Passport's routes with `EnsureOAuthServerEnabled`, `EnforceOAuthPkce`, and
`EnforceOAuthResourceIndicator`.
If the application has its own Passport client model, extend `ResourceClient` (or apply
the same dynamic-client `firstParty()`/`skipsAuthorization()` behavior) rather than
replacing that model with Passport's default; the package never overrides a custom model.
For an API challenge, return `OAuthProtectedResource::unauthorizedResponse()` (or
`insufficientScopeResponse([...])`) so `WWW-Authenticate` includes the configured
`resource_metadata` URI.

Put `ExpectOAuthResource` before `auth:api` (or call
`OAuthResourceIndicator::expectConfiguredFor($request)` before invoking Passport's
resource server directly) on every endpoint that accepts the bound credential.
Resource-bound tokens fail closed on Passport-protected routes that do not declare
the expected audience, preventing an MCP token from being replayed at a different
API in the same application.

The package migration `2026_09_02_000000_add_oauth_server_metadata` adds the reusable
Passport client registration fields and authorization-code, access-token, and refresh-token
resource-binding fields when they are absent. Refresh tokens retain their resource directly,
so Passport may purge an expired access-token row without invalidating a longer-lived refresh.
Publish and run migrations before enabling the server. If an application uses custom
column names or a custom Passport client model, configure `auth_code_resource_column`,
`resource_column`, and `refresh_token_resource_column`, and ensure the scopes attribute
is stored as an array/collection cast or JSON/string list the middleware can normalize.
Auth-code scope persistence likewise honors array, JSON, and collection casts rather than
double-encoding them. A missing resource column fails closed before a bound credential
can be issued. Enabling
the resource-aware Passport binding also switches new access tokens to the package
issuer/audience format; legacy Passport JWTs without the package `iss` claim are
rejected by the resource repository. Revoke or allow existing access tokens to expire,
then reauthorize clients after the migration rather than carrying old bearer tokens
across the cutover.

Dynamic registration is opt-in in metadata: configure a registration endpoint and keep
`dynamic_clients.enabled` true only when the application has routed the controller.
Unknown metadata is ignored as required by RFC 7591. The accepted profile is a public
authorization-code client: `authorization_code` + `refresh_token`, `code`, and `none`.
Native clients may use HTTPS or explicit loopback development redirect URIs; hosted/web
clients must use HTTPS redirect URIs. The response never contains a reusable client
secret. A supplied registration scope is an upper bound; an omitted scope explicitly
registers the configured server catalog as the upper bound, while an explicitly empty
scope registers no scopes. On authorization requests, an omitted scope uses the
Passport default scopes; an explicitly empty scope is rejected rather than silently
falling back to those defaults.
Registered-scope enforcement is always on for dynamic clients; the legacy
`enforce_registered_scopes` setting is retained only so published configs remain readable.
Dynamic registration does not grant consent or bypass the application policy.

Authorization and consent responses are non-cacheable. Package pre-validation redirects
errors only to an active client's exact registered callback; when `redirect_uri` is
omitted, the sole registered callback is used, while ambiguous, malformed, unknown, or
revoked-client destinations receive a local error instead.

RFC 9207 issuer identification is disabled by default. If enabled, install the issuer
middleware on every Passport authorization/consent route; otherwise leave the metadata
flag disabled. The package currently advertises DCR for compatibility but does not
advertise Client ID Metadata Documents and does not fetch arbitrary client URLs. CIMD
support is intentionally deferred until URL-client identity resolution and hardened
SSRF-safe document retrieval can be shipped together; see the [focused CIMD design
issue](https://github.com/bherila/auth-laravel/issues/30).

For a manual Codex smoke test, expose the protected-resource metadata and challenge
routes publicly, configure DCR, and run the client against the exact protected-resource
URL:

```sh
codex mcp add example --url https://example.test/mcp
codex mcp login example
```

The package test suite exercises the Passport lifecycle and registration fixtures; a
deployed application should still complete this browser/consent check in Codex (and,
when applicable, ChatGPT developer mode) before claiming client interoperability.

The shared consent view uses `oauth_server.consent` copy and labels so applications can
retain domain-specific language without copying security-sensitive forms or styling.
It warns when a client registered dynamically and shows the validated return URI.

### Agent API preset

An application that lets agents act for its users (MCP clients, and REST/OpenAPI connectors) runs its own authorization server through this package. The identity provider only signs people in. `AgentOAuthServer` applies the whole profile from one call, with every URL derived from `APP_URL`, so forks and self-hosted deployments need no host-specific settings:

```php
// config/bherila-auth.php
use BWH\Auth\OAuth\Server\AgentOAuthServer;

'oauth_server' => AgentOAuthServer::config(App\Support\Scopes::descriptions(), [
    'resource_required_scopes' => ['mcp:use'],   // if an MCP connection scope must carry a resource
]),

// config/passport.php
'middleware' => AgentOAuthServer::passportMiddleware(),

// routes/web.php (outside the web group: machine endpoints)
AgentOAuthServer::routes();
```

| Setting | Value |
|---|---|
| Resource | `APP_URL/api/v1` (RFC 8707). An omitted `resource` is taken as this one; a different explicit resource is refused. |
| PKCE | S256 required for every client |
| Self-registration | `POST /oauth/register`, public clients only, `throttle:10,60` |
| Token endpoint auth methods advertised | `none`, `client_secret_basic`, `client_secret_post`. Confidential clients are only ones a person registers. |
| Discovery routes | `/.well-known/oauth-authorization-server` and `/.well-known/oauth-protected-resource/api/v1`. That's the only path whose `resource` matches, per RFC 9728. Point your MCP endpoint's `WWW-Authenticate resource_metadata` at it. A deployment mounted under a path must route the host-root well-known URL to the app. |
| Kill switch | `OAUTH_SERVER_ENABLED` |
| Passport side (applied by the package) | The scope catalog through `Passport::tokensCan()` (unless you register your own), the packaged consent view (unless you bind one), and the device-code grant off, because it would bypass the PKCE gate |

Overrides merge recursively, and a list replaces the preset's list outright.

### Agent preset operations

- **Prune stale self-registrations daily:** `Schedule::command('bherila-auth:prune-dynamic-clients')->daily();`. The retention window is `oauth_server.dynamic_clients.retention_days`, and `last_used_at_column` must be set for recent use to count.
- **Test your app's contract:** `use BWH\Auth\Testing\AssertsAgentOAuthContract;` in a feature test, then call `assertAgentOAuthDiscovery()` and `assertAgentOAuthLifecycle($user, 'your:scope', '/api/v1/some-protected-route')`.
- **Keys:** `php artisan passport:keys`, kept out of version control, with the path set by `passport.key_path` or `PASSPORT_*_KEY`.

### API credentials (OAuth apps and personal API tokens)

Some agent connectors run the OAuth authorization-code flow; others ask for an API key. Enable the credential service to let a signed-in person create either kind for themselves:

```php
'oauth_server' => AgentOAuthServer::config($scopes, [
    'credentials' => [
        'enabled' => true,
        'token_lifetimes' => ['PT4H', 'P30D', 'P90D', 'P365D'],
    ],
]),
```

**Routes** (under `credentials.prefix`, session middleware `['web', 'auth']`):

| Method and path | Does |
|---|---|
| `GET /` | Scopes on offer, lifetimes, and the person's tokens and apps, with finished URLs |
| `POST /tokens` | Create an API token |
| `DELETE /tokens/{id}` | Revoke a token |
| `POST /apps` | Register an OAuth app |
| `DELETE /apps/{id}` | Delete an app |

All return JSON. Each new secret appears once, in a `201` no-store body. While the OAuth server is switched off, the two `POST` routes answer 404 and the index returns null issuance URLs.

Bind `GrantableScopes` to offer only the scopes your REST operations use. Bind `CredentialOwnerResolver`, or set `credentials.owner_model`, when your API guard loads a different model from the web guard.

### OAuth client integration

`BWH\Auth\OAuth\OAuthClient` owns state and PKCE generation, authorization redirects,
authorization-code exchange, and validation of the provider identity response. The consuming
application still owns local-user lookup/provisioning, account-state policy, login, auditing,
and the post-login destination.

Configure `OAUTH_PROVIDER`, `OAUTH_PROVIDER_URL`, `OAUTH_CLIENT_ID`,
`OAUTH_CLIENT_SECRET`, and `OAUTH_REDIRECT_URI`, then delegate from the app controller:

```php
public function redirect(Request $request, OAuthClient $oauth): RedirectResponse
{
    return $oauth->redirect($request);
}

public function callback(Request $request, OAuthClient $oauth): RedirectResponse
{
    $identity = $oauth->identityFromCallback($request);
    $user = $this->resolveLocalUser($identity);

    Auth::login($user);
    $request->session()->regenerate();

    return redirect()->intended('/');
}
```

The package deliberately does not match or bind users by email. That decision is
application-specific and must not silently replace a trusted provider-subject binding.

#### Signing out, and the application list

Two things every relying party needs, and which four of them had drifted apart on before
they were lifted here.

`BWH\Auth\Concerns\SignsOutThroughProvider` ends the local session and then hands off to
the provider's end-session endpoint. Ending only the local session is not signing out: the
provider still recognises the person, so the next protected page sends them back for
authorization and is handed an identity with no prompt — a button that visibly does nothing.

```php
class OAuthLoginController extends Controller
{
    use SignsOutThroughProvider;

    public function logout(Request $request, OAuthClient $oauth): RedirectResponse
    {
        return $this->signOutThroughProvider($request, $oauth);
    }

    // Optional; a no-op unless the application keeps an audit trail.
    protected function afterLocalSignOut(Request $request, ?Authenticatable $user): void
    {
        $this->auditLoggedOut($request, $user);
    }
}
```

Pass a second argument to choose where the provider returns the person; it defaults to this
application's root and must be absolute, because the provider validates it against the
origins registered for this client. An address it does not recognise lands them on the
provider rather than being followed, so a misconfiguration degrades instead of becoming an
open redirect.

`BWH\Auth\OAuth\ProviderApplications` holds the sibling applications the provider reported,
so an app switcher can render without a second round trip. Store it in the callback once the
application has decided to admit the person, and read it where the page is composed:

```php
ProviderApplications::remember($request, $identity->apps);   // in callback()
ProviderApplications::forRequest($request);                  // in Blade, Inertia, a view composer
```

Keeping it server-side is the point: the set of applications that exist is never compiled
into a JavaScript bundle, so downloading the front end tells an anonymous visitor nothing
about what else is deployed. Gate the injection on the person being signed in.

`OAuthClient::isConfigured()` answers whether a client has been issued for this application
without aborting, which the other methods cannot do — they 503 on a missing setting, the
right answer for a half-configured deploy and the wrong one for an app that is meant to run
without a provider at all. Use it to 404 the OAuth routes, or to fall back to a local
sign-in, in environments that have no client.

Bind `BWH\Auth\Contracts\AuthUserPolicy` when an app needs custom login gates or redirects.

Bind `BWH\Auth\Contracts\AuthAuditLogger` only when an app wants to override the built-in audit behavior (for example, to mirror events into its own broader audit table). Most apps should instead use the database driver described below.

### canLogin() — the single gate for account state

`AuthUserPolicy::canLogin()` is the **single source of truth** for "is this account allowed to proceed through any login flow." The default implementation duck-types `$user->canLogin()` and falls back to checking `$user->is_disabled`. Apps with additional account-state columns (e.g. `approved_at`, `email_verified_at`, or a role whitelist) must bind a custom policy and encode **all** conditions in `canLogin()`:

```php
// app/Auth/AppUserPolicy.php
class AppUserPolicy extends DefaultAuthUserPolicy
{
    public function canLogin(Authenticatable $user, Request $request): bool
    {
        return $user->approved_at !== null
            && ! $user->is_disabled;
    }
}

// AppServiceProvider::register()
$this->app->bind(AuthUserPolicy::class, AppUserPolicy::class);
```

The package calls `canLogin()` automatically from:

- `RequireActiveUser` middleware, applied to all package audit-log routes
- `canPasskeyLogin()` in the default policy (passkey auth delegates here)
- The 2FA `completeLogin()` path delegates through `redirectAfterLogin()`; if the user should be
  blocked at that point, `canLogin()` must return false so the redirect sends them away from the app

Apps must also call `canLogin()` from their own:

1. **Primary password-login controller** — before `Auth::attempt()` or after resolving the user.
2. **Email-verification callback** — after marking the email verified, call `canLogin()` and use
   `redirectAfterLogin()` (not a hardcoded path) so a just-verified but still-pending user goes to
   the pending page rather than into the app. Hardcoding `/pending` in the verification handler
   causes approved users who verified their email to be falsely shown the pending page.

### Protecting admin gates against pending/disabled accounts

When setting `audit.admin_ability`, the Gate ability definition must verify **both** admin role and active-account state. The package applies `RequireActiveUser` on top, but your Gate definition should be correct independently (it may be called from other locations):

```php
// AppServiceProvider::boot()
Gate::define('admin-only', function (User $user) {
    // WRONG: only checks role — a pending admin bypasses account-state checks
    // return $user->is_admin;

    // CORRECT: role AND account state
    return $user->is_admin
        && $user->approved_at !== null
        && ! $user->is_disabled;
});
```

### Backfilling approved_at after adding an approval column

If you add an `approved_at` (nullable, null = pending) column to your existing `users` table, every pre-existing row will be null after migration, instantly locking out all current users — including the primary admin. Before deploying the migration to production, add a backfill step in your migration (or a separate migration) to grandfather existing rows:

```php
// In your migration's up() method, after adding the column:
DB::table('users')
    ->whereNull('approved_at')
    ->update(['approved_at' => now()]);
```

Alternatively, make null mean "approved" and use a different sentinel (e.g. a `pending` boolean), but document the convention clearly.

## Login audit logging

The package can own a single append-only audit log for authentication events, so consuming apps no longer hand-roll their own login-audit table and writer.

### Enable it

```sh
php artisan vendor:publish --tag=bherila-auth-config
php artisan vendor:publish --tag=bherila-auth-migrations
php artisan migrate
```

Then set the driver in `.env`:

```
BHERILA_AUTH_AUDIT_DRIVER=database
```

The driver defaults to `null` (a no-op `NullAuthAuditLogger`), so an app that has not published/run the migration is unaffected and never hits a missing table. Setting it to `database` binds `DatabaseAuthAuditLogger`, which writes one row per event into the `bherila-auth.audit.table` table (default `auth_audit_log`).

### What gets recorded

The package's own controllers/services already report passkey, 2FA, and password reset/change events. For **primary password login and logout**, the package does not own the login controller, so the app calls the contract from its own login flow. Use the `LogsAuthEvents` trait:

```php
use BWH\Auth\Concerns\LogsAuthEvents;

class LoginController
{
    use LogsAuthEvents;

    public function login(Request $request)
    {
        // ... resolve $user, attempt credentials ...
        if (! $ok) {
            $this->auditLoginFailed($request, $user, $request->input('email'), 'Invalid credentials');
            // ...
        }

        $this->auditLoginSucceeded($request, $user); // method defaults to 'password'
    }

    public function logout(Request $request)
    {
        $this->auditLoggedOut($request, $request->user());
        // ...
    }
}
```

`auth_method` is a free-form string (e.g. `password`, `passkey`, `two_factor`, `dev`). Failed logins for unknown emails are recorded with a null `user_id` and the attempted `email`.

### Schema

`auth_audit_log` columns: `id`, `user_id` (nullable), `acting_user_id` (nullable), `email`, `event`, `auth_method`, `succeeded`, `reason`, `ip_address` (`varbinary(16)` on MySQL / `blob` on SQLite, via `BWH\Auth\Casts\BinaryIpAddressCast`), `user_agent`, `session_id`, `is_suspicious`, `metadata` (json), timestamps. Event-name constants live on `BWH\Auth\Models\AuthAuditLog` (`EVENT_LOGIN_SUCCEEDED`, etc.). The client IP is resolved via `BWH\Auth\Support\ClientIp`, which uses Laravel's `Request::ip()` — so it only honours `X-Forwarded-*` headers from configured trusted proxies. **Apps behind Cloudflare or a load balancer must configure Laravel's TrustProxies** (in `bootstrap/app.php`) so the real client IP is recorded; otherwise forwarded headers are ignored to prevent audit-log IP spoofing.

### Read endpoints (optional)

Set `BHERILA_AUTH_AUDIT_ROUTES=true` to register read endpoints (the package ships no UI; render your own and call these or query `AuthAuditLog`):

- `GET /api/auth/audit-log` — the authenticated user's own history (paginated)
- `POST /api/auth/audit-log/{id}/suspicious` — flag/unflag one of the user's own entries
- `GET /api/auth/audit-log/all` — cross-user admin list, gated by the `bherila-auth.audit.admin_ability` Gate ability (route returns 403 unless that ability is configured and allowed)

### Retention

Retention is **off by default** (`bherila-auth.audit.retention_days = null`), so nothing is ever pruned. To enable pruning, set `BHERILA_AUTH_AUDIT_RETENTION_DAYS` and run the artisan command:

```bash
php artisan bherila-auth:prune-audit-log
```

The command deletes all rows older than `bherila-auth.audit.retention_days` and prints the count of removed rows. It is a no-op when `retention_days` is `null`.

To run it automatically, add it to your application's scheduler (optional):

```php
// bootstrap/app.php or a scheduler
$schedule->command('bherila-auth:prune-audit-log')->daily();
```

You can also continue to use Laravel's built-in prune infrastructure if you prefer:

```php
Schedule::command('model:prune', ['--model' => [\BWH\Auth\Models\AuthAuditLog::class]])->daily();
```

> **Since 0.4.2.** The `bherila-auth:prune-audit-log` artisan command was added in 0.4.2.

> **Since 0.2.0.** The audit-log table, default database logger, `BinaryIpAddressCast`, `ClientIp`, the `LogsAuthEvents` trait, read endpoints, retention, and the `loginSucceeded`/`loginFailed`/`loggedOut` contract methods were added in 0.2.0. The contract gained methods; implementations should extend `BWH\Auth\Services\AbstractAuthAuditLogger` (which provides no-op defaults) rather than implementing the interface directly.

## Trusted proxies

Every per-client limit, including login throttling, client registration, token exchange and your own API throttles, keys on `Request::ip()`. Behind a CDN that's the edge's address unless the edge is trusted, so every client behind one edge shares a budget. Trusting `*` is unsafe wherever the origin also answers direct connections, because anyone could forge their address.

Opt in to let the package configure Laravel's `TrustProxies` for you:

```dotenv
BHERILA_AUTH_TRUSTED_PROXIES=true
TRUSTED_PROXIES=cloudflare   # or a comma-separated list, or * behind a firewall, or empty
```

| `TRUSTED_PROXIES` | Trusts |
|---|---|
| `cloudflare` (default) | Cloudflare's published IPv4/IPv6 ranges, shipped with the package (`TrustedProxies::CLOUDFLARE`), or `bherila-auth.trusted_proxies.cloudflare` if you pin your own list |
| `10.0.0.1, 192.0.2.0/24` | exactly those addresses and ranges; `cloudflare` can appear in the list too |
| `*` | every peer; only safe when a firewall admits nothing but the proxy |
| empty | nothing; right when no proxy is in front |

- **Headers honoured:** only `X-Forwarded-For` and `-Proto`. Never `X-Forwarded-Port` (Cloudflare passes a client-supplied one through) or `X-Forwarded-Host`.
- **The client address** is the rightmost one that isn't a trusted proxy, i.e. the address the edge appended. Anything the client wrote further left is ignored.
- **Drift check:** run `php artisan bherila-auth:check-cloudflare-ranges` from a scheduled CI job. It exits `1` with an add/remove list when Cloudflare revises its ranges, and `2` if they can't be fetched.

## Login throttling

The package can also enforce a password-login lockout using the same append-only `auth_audit_log` table. It is **off by default** and has no effect until a consuming app enables it and calls the service from its own password-login controller:

```
BHERILA_AUTH_AUDIT_DRIVER=database
BHERILA_AUTH_THROTTLE_ENABLED=true
BHERILA_AUTH_THROTTLE_MAX_ATTEMPTS=5
BHERILA_AUTH_THROTTLE_DECAY_MINUTES=15
# email | ip | email_ip (default)
BHERILA_AUTH_THROTTLE_KEY=email_ip
```

This package does not wrap arbitrary app `/login` routes. If the app disables package auth routes or owns primary login locally, the local login controller is responsible for inspecting the throttle before `Auth::attempt()` and recording blocked attempts.

Use `BWH\Auth\Concerns\ThrottlesLoginAttempts` alongside `LogsAuthEvents`:

```php
use BWH\Auth\Concerns\LogsAuthEvents;
use BWH\Auth\Concerns\ThrottlesLoginAttempts;

class LoginController
{
    use LogsAuthEvents;
    use ThrottlesLoginAttempts;

    public function login(Request $request)
    {
        $email = $request->input('email');
        $state = $this->inspectLoginThrottle($request, null, $email);

        if ($state->locked) {
            $this->auditLoginBlocked($request, null, $email, 'password', $state);

            return response()->json([
                'message' => 'Too many login attempts.',
                'retry_after' => $state->availableInSeconds(),
            ], 429);
        }

        // ... attempt credentials ...
        if (! $ok) {
            $this->auditLoginFailed($request, $user, $email, 'Invalid credentials');
            // ...
        }

        $this->auditLoginSucceeded($request, $user);
    }
}
```

The throttle counts recent `login_failed` rows matching the auth method and the configured `throttle.key`: the normalized email (`email`), the resolved client IP (`ip`), or both (`email_ip`, the default). Second-factor failures (`two_factor_failed`) are excluded by event, so a wrong 2FA code never counts toward credential lockout. A later `login_succeeded` row for the same key resets the count. Blocked requests can be recorded as `login_blocked` rows via `auditLoginBlocked()`, but those rows do not extend the lockout window.

Pick the key strategy to match your threat model: `email` mitigates per-account credential stuffing but lets an attacker lock a victim out by spamming failures for their address; `ip` bounds a single noisy source but can affect users behind a shared NAT/CGNAT egress; `email_ip` (default) is the most conservative and only locks a specific account+source pair.

Because throttling is audit-log-backed, apps must enable the database audit driver, run the package audit migration, record failed/successful primary login events, and configure Laravel trusted proxies correctly.

## Delegated application access verification

`BWH\Auth\OAuth\DelegatedAccess` provides consumer primitives for the
[delegated application access contract](https://github.com/bherila/auth-manager/issues/33).
It does not install a signing service or grant application access, and it exposes a route only
when an application binds an adapter ([Serving the endpoint](#serving-the-endpoint)).
`lcobucci/jwt` is an explicit runtime dependency; Passport
remains optional for consumers that do not run an authorization server.

Construct `ActorAssertionVerifier` from trusted local configuration: the exact
HTTPS issuer, the exact HTTPS adapter endpoint, the application registry key,
a `kid => RSA public key PEM` map, and a `NonceStore`. Issuers may not contain a
path other than `/`; a trailing issuer slash is removed before exact claim matching.
URLs may not contain credentials, query strings, or fragments.
Keys and endpoint URLs are never discovered from assertion headers.

```php
use BWH\Auth\OAuth\DelegatedAccess\ActorAssertionVerifier;
use BWH\Auth\OAuth\DelegatedAccess\DatabaseNonceStore;

$verifier = new ActorAssertionVerifier(
    issuer: 'https://identity.example.test',
    endpoint: 'https://application.example.test/application-access',
    application: 'example-app',
    publicKeys: ['integration-v1' => $pinnedPublicKeyPem],
    nonces: new DatabaseNonceStore($dedicatedNonceDatabaseConnection),
);
$actorSubject = $verifier->verify($assertion, $request->method(), $request->getContent());
```

Verification requires RS256, the `application-access+jwt` type, an exact audience,
issuer, application and POST method, and the SHA-256 of the **original request
bytes**. Assertions last at most 60 seconds with five seconds of clock tolerance.
Successful verification atomically consumes the nonce through expiry plus that
tolerance. `DatabaseNonceStore` writes a dedicated `bherila_auth_delegated_nonces`
table, independently of application cache. Cache flushes and Redis evictions
cannot erase these records. Provision the table before enabling the adapter:

```sh
php artisan vendor:publish --tag=bherila-auth-delegated-access-migrations
```

Apply the published migration through the application's normal reviewed deployment
process, on the same connection passed to the store. It is not published with the
ordinary package migrations, and its rollback deliberately retains nonce records.
The store's database connection must be shared and durable across every adapter
worker and deployment, and must be outside any business transaction so a later
rollback cannot undo consumption. In-memory SQLite and active transactions are
rejected. Use the primary writable database connection; do not place this table in
an ephemeral database or restore it to an earlier snapshot while assertions remain
valid. Only a unique-key conflict is treated as replay; other database failures
become a 503 refusal. `pruneExpired()` may be scheduled for maintenance and deletes
only expired entries. There is no ordinary cache adapter or fallback.

Custom `NonceStore` implementations must provide equivalent durable atomic
first-use semantics through expiry, including restarts, maintenance, and failure
handling. Never catch a replay-storage failure and continue authentication.

The returned subject identifies the actor only. Resolve that actor using the
configured issuer and exact subject, then enforce current local eligibility and
access-administration authority **before** target discovery or mutation. Resolve
targets separately; verification does not authorize them, provision users, or
replace application-owned tenant, last-administrator, revision, or audit rules.
No ordinary OAuth-token fallback is permitted on the adapter endpoint.

`DelegatedContract::request()` validates operation input and builds its versioned
envelope. `response()` validates an envelope; pass the expected target subject as
its fourth argument for `read` and `update` to enforce exact subject echo.
Consumers must separately enforce `MAX_REQUEST_BYTES`/`MAX_RESPONSE_BYTES`, JSON
parsing, transport authentication, and operation authorization. The contract
bounds subjects to 191 bytes, revisions to 128 bytes, cursors to 512 bytes,
pages to 50 entries, and access updates to 100 unique workspace memberships.
An unprovisioned response carries null revision/access and no allowed edits.
`DelegatedAccessException` exposes a generic `outcome` and HTTP `status`; do not
log assertions or private key material when handling it.

### Contract version 2

Version 2 lets an application describe its own workspace roles, and lets a provider provision an
account for a subject the application has not seen yet
([#42](https://github.com/bherila/auth-laravel/issues/42)). Version 1 is unchanged and stays the
default: pass the version both sides agreed on as the last argument to `request()` and
`response()`.

- `capabilities.controls` is exactly `{application_admin, workspace_roles, provisioning}`.
  `workspace_roles` lists up to 16 `{id, label}` entries, ids up to 64 bytes and labels up to 255,
  most senior first. An empty list makes the application account-only (below).
- `access.workspaces[]` is `{id, role}` in an update and `{id, role, editable}` in a read or
  update response. A membership reported `editable: false` must be sent back unchanged, and the
  application refuses an update that changes it. `rolesAreAdvertised($capabilities, $access)`
  checks an access value against the roles a capabilities response advertised;
  `advertisedRoleIds()` lists them.
- `allowed_edits` is exactly `{application_admin, workspaces, provision}`. An unprovisioned response
  still carries null revision and access and no administrator or workspace edits, but may set
  `provision: true`. A provisioned response always sets it false.
- An `update` whose `expected_revision` is `null` provisions an unprovisioned subject, and only
  that update may carry `display_name` (up to 255 bytes): contact data for the new account, never
  an identity key. The application still binds the account to the verified issuer and the exact
  subject, and answers 409 when the subject is already provisioned.
- A version this package does not implement is a configuration error
  (`unsupported_contract_version`, status 500), not a refusal of any request.

#### Account-only applications

An application with accounts but no workspaces advertises `workspace_roles: []`. It is then
account-only: what can be managed is whether a person has an account, through provisioning, and
the application administrator flag.

- Every access value carries `workspaces: []`: an `update` and a provisioning `update` send it, and
  a `read` or `update` state reports it. A state never offers `allowed_edits.workspaces`. The
  application answers `workspaces` with an empty page and refuses an update naming any membership
  (`invalid_request` or `role_not_grantable`).
- Provisioning sends `application_admin` as the actor chose it. A provider asks for that choice
  explicitly rather than defaulting it, and the application still decides whether this actor may
  create an administrator.
- `accountOnly($capabilities)` says whether a capabilities response describes one.
  `rolesAreAdvertised($capabilities, $access)` accepts only `workspaces: []` for it, as it accepts
  only advertised roles otherwise, so a provider's existing check covers outgoing access.
  `fitsCapabilities($capabilities, $response)` checks an answer the shape validators cannot: for an
  account-only application, no memberships and no workspace edits in a state and an empty
  `workspaces` page. It is always true for a workspace application.

The empty role list is the signal, rather than a separate flag such as `controls.workspaces: false`:

- **One spelling, no contradictions.** Roles are the only way a membership can be expressed, so an
  application with none can hold no memberships whatever a flag said. A flag would add two states to
  define and refuse (no workspaces with roles, workspaces without any) and say nothing new.
- **Workspace applications are untouched.** Their capabilities, adapters and providers keep exactly
  the shape they have; `controls` keeps its exact key set. A new key would be required of every
  application, or optional with two spellings of the same answer.
- **Older providers fail closed.** A provider on an earlier release refuses `workspace_roles: []` as
  `invalid_response`, as it would refuse an unknown key, so it shows an error rather than a
  workspace screen with no roles to choose.
- **A misconfigured workspace application cannot leak through.** One that advertises no roles by
  mistake is treated as account-only, and every state it reports with a membership fails
  `fitsCapabilities()`, which a provider checks before rendering it.

### Serving the endpoint

The package serves `POST /application-access` for contract version 2. The application supplies
only what is its own: an adapter deciding who may manage access and what they may see and change.

1. Implement `BWH\Auth\OAuth\DelegatedAccess\ApplicationAccessAdapter` and bind it in a service
   provider's `register()`. Binding it is the opt-in: without a binding there is no route.

   ```php
   $this->app->bind(ApplicationAccessAdapter::class, MyApplicationAccessAdapter::class);
   ```

2. Publish and apply the nonce migration (`bherila-auth-delegated-access-migrations`, above).
3. Configure the deployment:

   | Variable | Meaning |
   |---|---|
   | `DELEGATED_ACCESS_ENABLED` | `true` to answer; the route answers 404 otherwise |
   | `DELEGATED_ACCESS_WRITES_ENABLED` | `true` to accept `update`; default `false`, so a new deployment is read-only |
   | `DELEGATED_ACCESS_ISSUER` | the provider's exact HTTPS issuer; must be the sign-in provider (`oauth_client.base_url`) |
   | `DELEGATED_ACCESS_ENDPOINT` | this endpoint's exact HTTPS URL, as the provider is configured to call it |
   | `DELEGATED_ACCESS_APPLICATION` | this application's key in the provider's registry |
   | `DELEGATED_ACCESS_PUBLIC_KEYS` | the provider's integration public keys, `key-id\|/path/to/public.pem`, comma-separated |
   | `OAUTH_PROVIDER` | must be set explicitly; it names the issuer local identity bindings are stored under |
   | `DELEGATED_ACCESS_NONCE_CONNECTION` | optional; the nonce table's connection, default connection otherwise |

   `bherila-auth.delegated_access.path` (default `/application-access`) and `per_minute` (default
   120 per client IP) are config-only. The limit is applied inside the controller after the enabled
   check, so a disabled endpoint answers 404 and never 429. If any listed key
   file is unreadable, `OAUTH_PROVIDER` is unset or disagrees with `oauth_client.provider`, or
   `DELEGATED_ACCESS_ISSUER` is not the sign-in provider's `oauth_client.base_url` (a trailing
   slash aside), every request is refused with `invalid_verifier_configuration`. That last check
   keeps a subject in the namespace it was issued in: the adapter resolves it under
   `bindingIssuer()`, which is only right if the provider asserting it is the one people sign in
   with. To rotate, list both public
   keys, switch the provider to the new key id, then remove the old one.

4. Schedule `bherila-auth:prune-delegated-nonces` if the table should not grow without bound. It
   deletes expired nonces only.

The controller refuses an oversize body (`MAX_REQUEST_BYTES`) and a missing bearer before
verification. It verifies the assertion and consumes its nonce before parsing the body, then
requires version 2 and this application's key. The adapter's `handle($actorSubject, $payload)`
receives `operation` plus that operation's fields, and returns that operation's response fields.
The controller adds `contract_version`, `application` and `operation`, validates the whole answer
(including the subject echo for `read` and `update`), and sends it with `Cache-Control: no-store`.
A `DelegatedAccessException` thrown by the adapter is sent as its outcome and status. An answer
outside the contract is reported and becomes `internal_error` (500), never sent. Until
`DELEGATED_ACCESS_WRITES_ENABLED` is set, an `update` is refused with `not_authorized` (403) after
verification and before the adapter, so an application can stop accepting changes without
touching the provider.

While the adapter runs, the container holds a `DelegatedRequestContext` with the verified
`issuer`, `subject`, `application`, `jti` and `operation`. Resolve it (or inject it into an adapter
bound with `bind()`) to record `jti` with the application's own audit, correlating the provider's
attempt and result records. `jti` is a single-use nonce: never key a retry on it. The binding is
removed when the call returns.

Laravel may read a JSON body in global middleware before any controller runs, so bound this
route's body to the same 64 KiB at the web server where you can. Nothing in front may rewrite the
body or strip `Authorization`: the assertion is bound to the exact bytes.

Helpers for adapters:

- `DelegatedAccessSettings::bindingIssuer()` is the provider name to resolve actors and targets
  under, the same one sign-in binds.
- `DelegatedCursor` encodes an encrypted keyset cursor bound to the actor and the operation:
  `encode($actor, $operation, $lastKeyShown)`, and `after($actor, $operation, $payload)` returns
  0 for a first page and refuses a foreign or tampered cursor with `invalid_cursor`. It stays within
  the contract's 512-byte bound for any subject length.
- `BWH\Auth\OAuth\PendingAccount::email($provider, $subject)` and `name($label, $subject)` give a
  provisioned account's placeholder contact details until first sign-in. The address is under
  `.invalid` and is never a linking key.

An account-only adapter answers `capabilities` with `workspace_roles: []`, `workspaces` with
`{"workspaces": [], "next_cursor": null}`, and every state with `workspaces: []` in `access` and
`workspaces: false` in `allowed_edits`. It authorizes each of those operations exactly as a
workspace application does. The endpoint validates each answer on its own and cannot hold it to
the capabilities; the conformance assertions below do.

What remains the adapter's: match the verified actor to a local account through its binding and
refuse (`not_authorized`, 403) unless it is active and may manage access. Show only what that actor
may manage. Compare revisions under the same locks the changes take (`revision_conflict`, 409).
Provision only an unbound subject, bound to `bindingIssuer()` and the exact subject, never by
adopting a row found by address. Keep the application's own last-administrator and audit rules.

#### Update semantics (normative)

The provider holds no authority of its own; whatever the adapter does not enforce is not enforced.

1. **Authorize every operation**, `capabilities` and the listings included. An actor who may not
   manage access learns nothing, not even the roles.
2. **An update replaces the actor's projection, never the subject's whole access.** Memberships in
   workspaces the actor cannot see are outside the request and survive it unchanged.
3. **`editable` and `allowed_edits` describe rules; they do not delegate them.** A membership
   reported as not editable is refused whether the update changes its role or omits it. A change to
   `application_admin` is refused unless both the capabilities and this read allow it.
4. **Roles are checked against what this actor may grant**, not only against what was advertised.
   Never infer a hierarchy from the order roles are advertised in.
5. **Change through the application's own domain service, under its locks, and compare the
   revision under those locks.** Validation, revision and every rule above are decided on the
   rows the change takes.
6. **A refusal changes nothing** and uses one of these outcomes (`BWH\Auth\OAuth\DelegatedAccess\DelegatedRefusal`):

   | Outcome | Status | When |
   |---|---|---|
   | `not_authorized` | 403 | the actor may not manage access, or may not see or change this target or workspace |
   | `protected_membership` | 403 | the update changes or omits a membership reported as not editable |
   | `role_not_grantable` | 403 | a role this actor may not grant, or one never advertised |
   | `not_provisioned` | 404 | a read of an unknown subject, when not reported as unprovisioned |
   | `revision_conflict` | 409 | a stale revision, or provisioning a subject already bound |
   | `invalid_request` | 422 | well formed, but not something this application can apply |

   A provider acts on the status when it does not know the outcome, so the newer outcomes reuse
   statuses it already handles. Never refuse with a 5xx: for a write the provider must then assume
   the change may have happened.
7. **An account-only application takes no memberships.** An update naming one is refused, and the
   application administrator flag is the whole of what an ordinary update changes. Its own rules,
   such as refusing self-demotion or demoting the last administrator, are reported as
   `allowed_edits.application_admin: false` for that target and still enforced.

`BWH\Auth\Testing\AssertsDelegatedAccessAdapter` checks rules 1 to 7 against an application's real
adapter and tables. Implement `delegatedAccessTruth($subject)` by reading the tables directly and
`delegatedAccessManager()`, seed a target with an editable membership, a protected one and one
outside the manager's view, then call:

```php
$this->assertDelegatedActorRefusedEverywhere($stranger, $target, $workspaceId);
$this->assertDelegatedProtectedMembershipsHold($manager, $target);
$this->assertDelegatedApplicationAdminFollowsAllowedEdits($manager, $target);
$this->assertDelegatedStaleRevisionRefused($manager, $target);
$this->assertDelegatedUnadvertisedRoleRefused($manager, $target);
$this->assertDelegatedUpdateKeepsUnseenMemberships($manager, $target);
```

Each refused attempt must leave `delegatedAccessTruth()` exactly as it was.

For an account-only application, `delegatedAccessTruth()` returns `workspaces: []` and the same
calls apply. Omit the workspace argument to `assertDelegatedActorRefusedEverywhere()`. The
membership checks return without checking anything (they never skip, which would end the test
method), `assertDelegatedUnadvertisedRoleRefused()` checks that any membership is refused, and every
answer is checked with `fitsCapabilities()`. Exercise the administrator flag with a target the actor
may not change: the actor themselves where self-demotion is refused, or the last administrator.

```php
$this->assertDelegatedActorRefusedEverywhere($ordinaryAccount, $target);
$this->assertDelegatedApplicationAdminFollowsAllowedEdits($administrator, $administrator);
$this->assertDelegatedStaleRevisionRefused($administrator, $target);
$this->assertDelegatedUnadvertisedRoleRefused($administrator, $target);
$this->assertDelegatedUpdateKeepsUnseenMemberships($administrator, $target);
```
