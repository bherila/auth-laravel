# Durable OAuth credential revocation

Applications issuing Passport credentials may opt into
`bherila-auth.oauth_server.revocation.enabled` after running the package migrations
on `passport.connection`. The default is false. Passport remains optional. The
migration creates no tables when Passport's access-token table is absent; rerun
or publish the migration after installing Passport in that case.

The package repositories serialize persistence with revocation on an owner guard
row, on Passport's connection. Access tokens, refresh tokens and authorization
codes inherit a durable connection lineage. A code exchange and every refresh
rotation remain in the same lineage; a new authorization creates a separate one.
The guard and the credential save (including synchronous Passport events) share
one transaction. A revoked lineage cannot persist a child, however long a grant
stalled between validation and persistence. Refusals use OAuth `invalid_grant`.

## Application revocation operations

`OAuthCredentialOwners::revokeAll()` and `revokeAllForOwnerId()` use the durable
owner barrier automatically when enabled. They still revoke Passport rows and
announce access-token revocations through Passport's repository.

Applications with their own selection, audit and result semantics can wrap the
existing row revocation in `CredentialLineages`:

```php
use BWH\Auth\OAuth\Server\CredentialLineages;

$lineages->revokingOwner($ownerId, $clientIdOrNull, function () {
    // Revoke the selected owner's refresh tokens, codes and access tokens,
    // using Passport's connection. Return the application's result.
});

$lineages->revokingConnection($ownerId, $authenticatedAccessTokenId,
    function (array $familyAccessTokenIds) {
        // Revoke only this owner's rows in this connection's rotation family.
        // Keep any owner/client selection and audit requirements here.
    });
```

These callbacks execute inside the guard transaction; a callback failure rolls
back the barrier and the row changes together. Database failures propagate;
there is no cache fallback or successful revocation result on database failure.
The connection API checks a known lineage's owner before invoking the callback.
For a legacy ID with no lineage and no surviving owned access row it returns only
the selected ID; the callback must still scope its selection to the owner. A
refresh validated while the guard is enabled adopts its parent before rotating,
so even a purged parent is then known durably.

A broad barrier rejects previously started issuance decisions and old grants,
while a fresh authorization after revocation is allowed. A connection barrier
ends only that lineage, preserving other connections for the same owner/client.
Provider identity and resource/audience checks continue to apply independently.
Directly updating Passport's revoked columns is insufficient to protect an
already validated, in-flight exchange; use these operations for revocation.

## Issuance boundary and extensions

When enabled, the provider prepends `CaptureOAuthRevocationContext` to Passport's
code authorization/approval, token, and personal token creation routes. It captures
the revocation sequence before controller grant decisions. The repositories also
capture an immutable context when allocating a new code or access-token entity.
For a custom issuer doing remote identity or authorization checks before creating
its entity, wrap the entire decision in:

```php
$result = $lineages->duringIssue(fn () => $issuer->checkAndIssue());
```

The helper restores the prior request context in `finally`, including on failure.
Custom OAuth endpoints must install the snapshot middleware before their grant
checks. Manually constructing an entity and bypassing repository allocation has
no issuance context and fails closed when enabled. Custom repository subclasses
retain the protected persistence hooks; the final public methods enforce the
guard around those hooks. All credential models and writes must use Passport's
connection. Cross-connection models are refused.

The lock order is broad-revocation clock, owner guard, lineage/membership, then
Passport credentials. Persistence takes the owner guard without locking the
clock. The clock advances only on broad revocations; unrelated owners can issue
credentials concurrently. Current locking reads avoid adopting an old
REPEATABLE READ snapshot. Keep callbacks short and never acquire these locks in
reverse order in application code.

## Migration, retention and release

The migration registers existing identifiable credentials at sequence zero in
batches of 100. It includes attributable refresh tokens whose access rows have
already been purged, and retains their parent membership. Registration is marked
complete once; replaying the migration never enrolls later rows. New repositories
register their own credentials atomically. An unregistered credential, including
an older process's late write, fails closed on use/exchange. This prevents lazy
adoption from turning a revoked connection's untracked child into a new lineage.

Unknown-owner/client refreshes require fresh authorization. Rotations completed
before registration cannot be reconstructed; existing access/refresh families are
registered independently. Pause issuance and drain old grants, migrate, deploy
the new repositories/revoker in every process, then enable issuance. Credentials
issued with enforcement disabled after this one-time migration are unregistered
and require fresh authorization when enforcement is enabled later. Do not remove
the completion marker to enroll new rows under live traffic.

`passport:purge` may remove expired/revoked Passport rows without removing lineage,
membership or scope records. These tables contain credential identifiers and
owner/client associations, never bearer secrets or encrypted refresh-token values.
They deliberately have no TTL and no foreign keys to purgeable Passport rows.
Migration rollback preserves the revocation tables; removing them is an explicit
retirement decision after all associated grants expire. Token purge retention and
dynamic-client pruning keep their existing application policies.

Ship this opt-in API as v0.27.0 after its PR is approved and merged. Publish a
signed annotated tag through the existing Release workflow (signature check,
GitHub release, Packagist update). Consumers can require `^0.27.0` and commit the
exact resolved `composer.lock` reference. No development path repository or
unreleased branch should reach a deployed consumer.
