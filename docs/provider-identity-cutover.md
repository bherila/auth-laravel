# Provider identity cutover

Before cutover, `BHERILA_AUTH_PROVIDER_IDENTITY_ENABLED` is an ordinary switch: an application
can turn [provider lifecycle enforcement](provider-session-verification.md) on, watch it, and
turn it off again. Once the application relies on the identity provider to end access
(disabling, deleting or resetting a person, removing their grant to this application), that
switch is a liability. Turning it off, on purpose or not, lets browser sessions and OAuth
credentials the provider has ended keep working here. A configuration rollback, a redeploy of
an older environment file or a recovery that restores stale settings can all do that silently.

Recording the cutover makes enforcement a committed state of the installation. The record
lives in the application's own database, not in configuration. While it is recorded and not
withdrawn, enforcement stays on whatever the setting says.

## What the lock covers

`BWH\Auth\OAuth\Session\ProviderIdentityEnforcement::enabled()` is the one place that decides
whether enforcement is on. It is true when the setting is on **or** a cutover is recorded.
Everything that enforces asks it:

| Path | Effect while enforcement is on |
| --- | --- |
| `RequireActiveProviderSession` (browser sessions) | An ended identity is signed out; an unavailable provider answers 503 |
| `ProviderSession::establish()` (sign-in callback) | A sign-in that cannot be verified is undone and answered 503 |
| `ProviderIdentityTokens` (OAuth codes, access and refresh tokens) | Unstamped or ended credentials are refused; renewals check freshly |

An application that calls `config('bherila-auth.provider_identity.enabled')` itself to decide
whether to enforce something should ask `app(ProviderIdentityEnforcement::class)->enabled()`
instead, or the lock will not cover that path.

## Adopting it

1. **Publish the migration.** The package publishes its migrations rather than loading them,
   so copy the new one into the application and let the deployment run it:

   ```bash
   php artisan vendor:publish --tag=bherila-auth-migrations
   ```

   Existing published files are left alone; only
   `2026_11_18_000000_create_provider_identity_cutover_table` is new. It creates
   `provider_identity_cutover` and skips if the table already exists. Creating it changes
   nothing: with no row, enforcement follows the setting exactly as before.

2. **Turn enforcement on and verify it.** Follow the
   [quick start](provider-session-verification.md#quick-start): the login callback records a
   baseline, the middleware is on every session route, the status cache is shared by every
   worker, and `BHERILA_AUTH_PROVIDER_IDENTITY_ENABLED=true`. Confirm in production that an
   account the provider disables loses its session and its tokens here.

3. **Record the cutover**, once, on the production host:

   ```bash
   php artisan bherila-auth:provider-identity-cutover record
   ```

   `record` refuses unless the table exists, the setting is on, and the identity provider
   client (`oauth_client.provider`, `base_url`, `client_id`, `client_secret`) is configured: it
   locks in only a configuration already proven to work. Running it again keeps the first
   record. It logs a notice naming the provider.

4. **Check it on every deploy.** Add `check` after migrations run:

   ```bash
   php artisan bherila-auth:provider-identity-cutover check
   ```

   It succeeds when no cutover is recorded, or when one is and the configuration agrees. It
   fails (exit 1) when a cutover is recorded but the setting is off or the provider client is
   unconfigured, naming each problem, so a drifted configuration is fixed before it ships
   instead of running every protected request into a 503.

5. **Confirm** with `status`:

   ```text
   $ php artisan bherila-auth:provider-identity-cutover
   Configured: on
   Cutover: recorded at 2026-01-01 00:00:00 for example-provider
   Enforcement: on
   ```

## The command

`bherila-auth:provider-identity-cutover {action=status} {--force}`

| Action | What it does | Exit |
| --- | --- | --- |
| `status` (default) | Shows the setting, the recorded cutover (or its withdrawal) and whether enforcement is on | 0 |
| `record` | Records the cutover, as above. Keeps an existing record. Re-records after a withdrawal | 0, or 1 when refused |
| `check` | For deploys: fails when a recorded cutover disagrees with the configuration | 0 or 1 |
| `withdraw` | Hands enforcement back to the setting. Asks for confirmation; `--force` skips it | 0, or 1 when declined |

Any other action is refused with exit 1.

## Failure modes

The lock never lets a request through that enforcement would refuse.

| Situation | Result |
| --- | --- |
| Cutover recorded, setting off | Enforcement stays on. `check` fails the deploy |
| Cutover recorded, provider client unconfigured | Protected requests and sign-ins answer 503; nothing is let through. `check` fails the deploy |
| Provider unavailable | Retryable 503; sessions and refresh tokens are kept. Not a reason to withdraw |
| Setting off and the database cannot be read | The query error propagates (500); enforcement is never assumed off |
| Table not migrated yet | No cutover: enforcement follows the setting. `record` refuses |
| Database restored from a backup taken before the cutover | The record is gone with it: run `record` again after such a restore |

With the setting on, the record is never read, so a database problem cannot affect the
decision.

## Withdrawing

Withdraw only to leave the identity provider on purpose, for example when moving the
application back to local accounts. The order matters:

1. Make sure the application has another way to sign people in and to end access.
2. Run `php artisan bherila-auth:provider-identity-cutover withdraw` and confirm. The row is
   kept, with `withdrawn_at` set, and a warning is logged.
3. Only then set `BHERILA_AUTH_PROVIDER_IDENTITY_ENABLED=false` and deploy.

Every process picks up the withdrawal within a minute. To lock again later, run `record`.

## Separate database connection

`provider_identity.cutover_connection` (`BHERILA_AUTH_PROVIDER_IDENTITY_CUTOVER_CONNECTION`)
names the connection holding the record; null uses the default connection. Set it when the
application keeps package tables on another connection, and run the migration on that
connection. The command reads and writes the same connection.

## How the record is read

- With the setting on, `enabled()` answers without touching the database.
- With the setting off, each process reads the single row (`id = 1`, `withdrawn_at` null) at
  most once a minute, so a cutover recorded or withdrawn elsewhere takes effect everywhere
  within a minute. `record`, `withdraw` and `status` clear the cached answer in their own
  process (`forget()`).
- The read never queries the schema catalog: bearer-token validation must stay one indexed
  read. A missing table is recognized from the query error (SQLSTATE `42S02` on MySQL and
  MariaDB, `42P01` on PostgreSQL, `no such table` on SQLite).
- Inside an open transaction the read runs under a savepoint, so a missing table cannot abort
  the surrounding transaction (PostgreSQL would otherwise refuse every later statement).

## Testing an application

Under `RefreshDatabase` the published migration creates the table and no row, so tests behave
as before and follow the setting. To exercise the lock, record a cutover as production would:

```php
config(['bherila-auth.provider_identity.enabled' => true]);
$this->artisan('bherila-auth:provider-identity-cutover', ['action' => 'record'])->assertSuccessful();
config(['bherila-auth.provider_identity.enabled' => false]);

$this->assertTrue(app(ProviderIdentityEnforcement::class)->enabled());
```

`ProviderIdentityEnforcement` is a singleton that caches its answer for a minute. A test that
inserts or deletes the row directly should call `app(ProviderIdentityEnforcement::class)->forget()`
or travel past the minute.
