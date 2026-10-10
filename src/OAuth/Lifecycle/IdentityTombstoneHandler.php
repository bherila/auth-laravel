<?php

namespace BWH\Auth\OAuth\Lifecycle;

/**
 * The application's deletion policy for a person the identity provider deleted.
 *
 * Binding an implementation is the opt-in: `bherila-auth:consume-identity-tombstones`
 * reads the provider's tombstone feed only when one is bound.
 *
 * Returning normally means this application's local deletion has committed, and the
 * tombstone is acknowledged to the provider straight after; an acknowledgement is a
 * statement that the cascade is complete, not a delivery receipt. Throw instead when
 * the deletion did not commit: the tombstone stays unacknowledged and comes back in a
 * later run.
 *
 * The same tombstone, and the same subject, can be delivered more than once (a run
 * that stopped before acknowledging, a lost acknowledgement, a repeated page), so an
 * implementation must be idempotent: a subject with no local record is already done.
 * Do not wrap this call in an outer database transaction, or "committed" is not true
 * when it returns.
 *
 * Finish well inside `identity_tombstones.handler_budget_seconds`: the run's lease cannot be
 * renewed during this call, so only a call within that budget is guaranteed never to run
 * concurrently with a later delivery of the same tombstone. A later, sequential retry must
 * always be safe.
 */
interface IdentityTombstoneHandler
{
    public function handle(IdentityTombstone $tombstone): void;
}
