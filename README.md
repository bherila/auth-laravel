# bherila/auth-laravel

Shared Laravel auth package for BWH applications.

The companion React component package is
[`bwh-auth`](https://github.com/bherila/auth-react).

Includes:

- OAuth 2.0 authorization-code client mechanics with PKCE and validated identity responses
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
`OAUTH_RESOURCE_URI`. Inactive tokens and well-formed active tokens that fail issuer,
resource, audience, expiry, or not-before validation return `active=false` without claims.
Missing or null resource/audience binding also returns an inactive result. Configuration,
connection, HTTP/client-authentication failures, and malformed responses or claim types
still throw `OAuthIntrospectionException`. Applications can map an inactive result to
an invalid-token response (401) and an exception to an unavailable-authority response
(503), so clients can reauthorize when a token is invalid instead of retrying an outage.
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
