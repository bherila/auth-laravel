# Identity tombstones

When the identity provider deletes a person, it disables them at once and records a
tombstone for their OAuth subject. Each application that could hold data about that
person reads the provider's pending tombstone feed, applies its own deletion policy,
and acknowledges each tombstone once that deletion has committed. The provider
hard-deletes its own record after every application has acknowledged, or after its
retention window (30 days by default), whichever comes first; an application that
was unavailable still receives the tombstone afterwards.

This package supplies the consumer side: a feed client, a cursor table and the
`bherila-auth:consume-identity-tombstones` command. The application supplies the
deletion policy. Nothing happens until it binds a handler.

## 1. Implement and bind the handler

```php
use BWH\Auth\OAuth\Lifecycle\IdentityTombstone;
use BWH\Auth\OAuth\Lifecycle\IdentityTombstoneHandler;
use Illuminate\Support\Facades\DB;

final class DeleteProviderIdentity implements IdentityTombstoneHandler
{
    public function handle(IdentityTombstone $tombstone): void
    {
        DB::transaction(function () use ($tombstone): void {
            $user = User::query()
                ->where('oauth_provider', $tombstone->provider)
                ->where('oauth_subject', $tombstone->subject)
                ->lockForUpdate()
                ->first();

            // Already deleted (or never here): nothing to do, and that is success.
            if ($user === null) {
                return;
            }

            // The application's own policy: delete, anonymize, keep attribution...
            $user->delete();
        });
    }
}
```

```php
// In an application service provider's register():
$this->app->bind(IdentityTombstoneHandler::class, DeleteProviderIdentity::class);
```

The tombstone carries the configured `bherila-auth.oauth_client.provider`, the opaque
subject, the tombstone id and the provider's timestamps, and nothing else: no name,
email address or credential. Match on the stored provider/subject binding, exactly and
case-sensitively; never on email, and never by treating the subject as a number.

### What returning and throwing mean

- **Returning** states that the local deletion has **committed**. The command
  acknowledges the tombstone straight after, and an acknowledgement is how the provider
  learns this application's cascade is complete. Commit inside `handle()`; do not rely
  on an outer transaction, queue a job and return, or return before the work is durable.
- **Throwing** leaves the tombstone unacknowledged. The command logs the tombstone id and
  the exception class (not its message, which may name the person), carries on with the
  next tombstone, and exits non-zero. The tombstone is recorded in the retry table and
  retried first on every later run, so a failure never waits for the feed to drain and
  never holds up newer tombstones. Log any detail you need inside the handler, under your
  own policy.

### Idempotency

A handler **will** see the same tombstone, and the same subject, more than once: after a
run that stopped before acknowledging, an acknowledgement the provider did not confirm, a
page read again after an outage, or two deletions that resolve to one local record. Each
call must be safe to repeat, and a subject with no local record must count as done.

## 2. Install the tables

```bash
php artisan vendor:publish --tag=bherila-auth-identity-tombstone-migrations
php artisan migrate
```

The cursor table holds the feed cursor per provider/client and the lease that keeps two
runs from overlapping. The retry table holds tombstones whose handler failed: the
tombstone id, the opaque subject, the provider's timestamps, the number of attempts and
the last attempt time. Both live on `bherila-auth.identity_tombstones.connection` (the
default connection unless set), which must be durable and shared by every server that
runs the command. Each migration does nothing if its table already exists and keeps it on
rollback.

## 3. Schedule the command

```php
// routes/console.php
use Illuminate\Support\Facades\Schedule;

Schedule::command('bherila-auth:consume-identity-tombstones')->everyFiveMinutes();
```

The command authenticates with the existing `bherila-auth.oauth_client` client id and
secret over HTTPS (loopback HTTP only in `local`/`testing`) and never follows redirects.
Each run:

1. takes the lease, or exits 0 with "skipped" while another run holds it;
2. retries recorded failures, least recently attempted first (up to `--limit` of them),
   acknowledging each one whose handler now succeeds;
3. reads up to `--max-pages` (default 10) pages of `--limit` tombstones (default
   `identity_tombstones.page_limit`, at most 100), starting from the stored cursor;
4. hands each tombstone to the handler and acknowledges it when the handler returns, or
   records it for a retry when the handler throws;
5. stores the next cursor once every tombstone on the page has been handled or recorded
   as failed, and clears it when the provider reports no more pages, so the next cycle
   starts from the oldest unacknowledged tombstone.

A retry row is removed when its tombstone is acknowledged, when the provider reports that
the tombstone is no longer assigned to this application (HTTP 404 on acknowledgement), or
once the tombstone's `purge_after` has passed. The provider still delivers a tombstone
that was never acknowledged, so one dropped at the end of the purge window comes back
when the feed cycles.

It exits non-zero when no handler is bound, either table is missing, the provider
settings are missing or untrusted, the feed is unavailable or malformed, an
acknowledgement fails, or any handler call throws. The single summary line holds counts
only, so scheduler output and alerts never contain subjects.

A page that the provider answered with malformed data is refused whole. A failed
acknowledgement stops the run before the rest of its page and leaves the cursor where it
was; the page is read again next time, which is safe. When the provider throttles
(HTTP 429) a run waits out its `Retry-After`, at most 60 seconds and three times, then
stops until the next run. The provider's reconciliation throttle is shared with
[session status checks](provider-session-verification.md), so a large backlog drains
over several runs rather than all at once. If the provider refuses the stored cursor
(for example after the client credential changed), the cursor is cleared and the next
run starts from the oldest. Cursors are also kept per provider base URL and client id,
so a new client never sends an old client's cursor.

## Configuration

```php
'identity_tombstones' => [
    'connection' => env('BHERILA_AUTH_IDENTITY_TOMBSTONE_CONNECTION'),
    'table' => 'bherila_auth_identity_tombstone_cursors',
    'retry_table' => 'bherila_auth_identity_tombstone_retries',
    'page_limit' => (int) env('BHERILA_AUTH_IDENTITY_TOMBSTONE_PAGE_LIMIT', 100),
],
```

## What this does not do

Acknowledging a tombstone does not end sessions inside the application; the provider has
already revoked its own tokens, and session revalidation is a separate integration
([provider session verification](provider-session-verification.md)). A status check is
not a deletion acknowledgement, and an acknowledgement is not proof that every
application has deleted its data, only this one.
