<?php

namespace BWH\Auth\Testing;

use BWH\Auth\OAuth\DelegatedAccess\ApplicationAccessAdapter;
use BWH\Auth\OAuth\DelegatedAccess\DelegatedAccessException;
use BWH\Auth\OAuth\DelegatedAccess\DelegatedContract;
use BWH\Auth\OAuth\DelegatedAccess\DelegatedRefusal;
use BWH\Auth\OAuth\DelegatedAccess\DelegatedRequestContext;
use BWH\Auth\OAuth\DelegatedAccess\NonceStore;
use DateTimeImmutable;
use Illuminate\Foundation\Testing\TestCase;
use Illuminate\Testing\TestResponse;
use Lcobucci\JWT\Encoding\ChainedFormatter;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token\Builder;
use stdClass;
use Symfony\Component\HttpFoundation\Response;

/**
 * Assert the mutation semantics every delegated access adapter owes, whatever its domain.
 *
 * The package verifies who is asking and that each message has the contract's shape. Everything
 * the adapter enforces is invisible to it, and an update is easy to get wrong in the same few ways:
 * treating the actor's projection as the whole truth and deleting what the actor cannot see,
 * trusting `editable` or `allowed_edits` as hints the provider will honour, or checking a revision
 * outside the locks. These drive the adapter the way the endpoint does and check the application's
 * own record afterwards, not the adapter's answer.
 *
 * Seed the scenario each assertion names, then implement {@see delegatedAccessTruth()} by reading
 * the application's tables directly. Every refused attempt must leave that record exactly as it was.
 *
 * An account-only application (one advertising no workspace roles) runs the same assertions. The
 * parts that need memberships return instead of checking them, never skip, and each answer is also
 * checked to report no workspaces, since the endpoint cannot see that rule.
 *
 * Contract version 3 adds search, removal, metadata and operation receipts:
 * {@see assertDelegatedSearchStaysInScope()}, {@see assertDelegatedRemoveStripsOnlyTheManagedProjection()},
 * {@see assertDelegatedRemoveRefusedWithoutPartialChange()}, {@see assertDelegatedMetadataIsWellFormed()}
 * and {@see assertDelegatedReceiptsReplayThroughTheEndpoint()}, which drives the real endpoint.
 *
 * @mixin TestCase
 */
trait AssertsDelegatedAccessAdapter
{
    /**
     * The application's own record of a subject's access, read without going through the adapter.
     *
     * Include every membership, not only those any particular actor manages.
     *
     * An account-only application has no workspaces, so its `workspaces` is always empty.
     *
     * @return array{application_admin: bool, workspaces: array<string, string>} workspace id => role id
     */
    abstract protected function delegatedAccessTruth(string $subject): array;

    /** An actor who may manage access, whose capabilities response is the application's. */
    abstract protected function delegatedAccessManager(): string;

    /**
     * An actor who may not manage access is refused every operation, including the read-only ones,
     * searches and removal.
     *
     * The update names `$workspace` with an advertised role. An account-only application has neither,
     * so there the update carries no memberships and `$workspace` may be omitted.
     */
    protected function assertDelegatedActorRefusedEverywhere(string $actor, string $target, ?string $workspace = null): void
    {
        $before = $this->delegatedAccessRecord($target);
        if ($this->delegatedAccessAccountOnly()) {
            $memberships = [];
        } else {
            $this->assertNotNull($workspace, 'Name a workspace for the update');
            $memberships = [['id' => $workspace, 'role' => $this->delegatedAccessRoles()[0]]];
        }
        $payloads = [
            ['operation' => 'capabilities'],
            ['operation' => 'subjects', 'limit' => 50],
            ['operation' => 'subjects', 'limit' => 50, 'query' => substr($target, 0, 2).'x'],
            ['operation' => 'workspaces', 'limit' => 50],
            ['operation' => 'workspaces', 'limit' => 50, 'query' => 'workspace'],
            ['operation' => 'read', 'subject' => $target],
            ['operation' => 'update', 'subject' => $target, 'expected_revision' => 'any-revision',
                'access' => ['application_admin' => false, 'workspaces' => $memberships], 'operation_id' => DelegatedContract::operationId()],
            $this->delegatedRemovePayload($target, 'any-revision'),
        ];

        foreach ($payloads as $payload) {
            $this->assertDelegatedRefusal([DelegatedRefusal::NOT_AUTHORIZED], $actor, $payload, $payload['operation'].' by an actor who may not manage access');
        }
        $this->assertSame($before, $this->delegatedAccessRecord($target), 'Refusals change nothing');
    }

    /**
     * An update replaces only what the actor was shown. Memberships outside the actor's view survive
     * a resubmitted read, and survive removing everything the actor may remove.
     *
     * For an account-only application only the first part applies: resubmitting a read changes nothing.
     */
    protected function assertDelegatedUpdateKeepsUnseenMemberships(string $actor, string $target): void
    {
        $accountOnly = $this->delegatedAccessAccountOnly();
        $state = $this->delegatedAccessRead($actor, $target);
        $before = $this->delegatedAccessRecord($target);
        $shown = array_column($state['access']['workspaces'], 'id');
        $unseen = array_diff_key($before['workspaces'], array_flip($shown));
        if (! $accountOnly) {
            $this->assertNotSame([], $unseen, 'Seed the target with a membership in a workspace the actor does not manage');
        }

        $resubmitted = $this->delegatedAccessUpdate($actor, $target, $state['revision'], $state['access']['workspaces'], $state['access']['application_admin']);
        $this->assertSame($before, $this->delegatedAccessRecord($target), 'Resubmitting what was read changes nothing');
        if ($accountOnly) {
            // No memberships, seen or unseen, to keep or remove.
            return;
        }

        $protected = array_values(array_filter($resubmitted['access']['workspaces'], static fn (array $m): bool => ! $m['editable']));
        try {
            $this->delegatedAccessUpdate($actor, $target, $resubmitted['revision'], $protected, $resubmitted['access']['application_admin']);
        } catch (DelegatedAccessException $refusal) {
            // Removing the editable memberships may be refused for the application's own reasons, such as a
            // last administrator. Then it must change nothing.
            $this->assertSame($before, $this->delegatedAccessRecord($target), 'A refused removal changes nothing');

            return;
        }

        $after = $this->delegatedAccessRecord($target);
        foreach ($unseen as $id => $role) {
            $this->assertSame($role, $after['workspaces'][$id] ?? null, "Unseen membership {$id} survives an update that omits it");
        }
        foreach ($protected as $membership) {
            $this->assertSame($membership['role'], $after['workspaces'][$membership['id']] ?? null, "Protected membership {$membership['id']} survives");
        }
    }

    /**
     * A membership the read marked not editable can be neither removed by omission nor given another
     * role. `editable` describes the rule; the adapter still enforces it.
     */
    protected function assertDelegatedProtectedMembershipsHold(string $actor, string $target): void
    {
        if ($this->delegatedAccessAccountOnly()) {
            // No memberships to protect. Returning, not skipping, keeps the assertions after this one.
            return;
        }

        $state = $this->delegatedAccessRead($actor, $target);
        $before = $this->delegatedAccessRecord($target);
        $memberships = $state['access']['workspaces'];
        $protected = array_values(array_filter($memberships, static fn (array $m): bool => ! $m['editable']));
        $this->assertNotSame([], $protected, 'Seed the target with a membership the actor can see but may not change');
        $refusals = [DelegatedRefusal::PROTECTED_MEMBERSHIP, DelegatedRefusal::NOT_AUTHORIZED, DelegatedRefusal::INVALID_REQUEST];

        foreach ($protected as $membership) {
            $without = array_values(array_filter($memberships, static fn (array $m): bool => $m['id'] !== $membership['id']));
            $this->assertDelegatedRefusal($refusals, $actor, $this->delegatedUpdatePayload($target, $state['revision'], $without, $state['access']['application_admin']), "omitting protected membership {$membership['id']}");

            foreach (array_diff($this->delegatedAccessRoles(), [$membership['role']]) as $role) {
                $changed = array_map(static fn (array $m): array => $m['id'] === $membership['id'] ? ['role' => $role] + $m : $m, $memberships);
                $this->assertDelegatedRefusal([...$refusals, DelegatedRefusal::ROLE_NOT_GRANTABLE], $actor, $this->delegatedUpdatePayload($target, $state['revision'], $changed, $state['access']['application_admin']), "changing protected membership {$membership['id']} to {$role}");
            }
        }
        $this->assertSame($before, $this->delegatedAccessRecord($target), 'Refusals change nothing');
    }

    /**
     * Application administration changes only where both the capabilities and this read allow it.
     *
     * Where this actor may change it for this target there is nothing to refuse, and the assertion
     * returns without checking. Seed an actor who may not to exercise it: one without the control at
     * all, an actor reading themselves where self-demotion is refused, or the last administrator. It
     * never skips: a skip would end the whole test method and silently drop the assertions after it.
     */
    protected function assertDelegatedApplicationAdminFollowsAllowedEdits(string $actor, string $target): void
    {
        $capabilities = $this->delegatedAccessCall($actor, ['operation' => 'capabilities']);
        $state = $this->delegatedAccessRead($actor, $target);
        if ($capabilities['controls']['application_admin'] && $state['allowed_edits']['application_admin']) {
            return;
        }

        $before = $this->delegatedAccessRecord($target);
        $flipped = $this->delegatedUpdatePayload($target, $state['revision'], $state['access']['workspaces'], ! $state['access']['application_admin']);
        $this->assertDelegatedRefusal([DelegatedRefusal::NOT_AUTHORIZED, DelegatedRefusal::PROTECTED_MEMBERSHIP, DelegatedRefusal::INVALID_REQUEST], $actor, $flipped, 'changing application administration');
        $this->assertSame($before, $this->delegatedAccessRecord($target), 'Refusals change nothing');
    }

    /**
     * An update against anything but the current revision is refused as a conflict and changes nothing.
     *
     * It resends exactly what was read, so no other rule the adapter applies first can refuse it.
     */
    protected function assertDelegatedStaleRevisionRefused(string $actor, string $target): void
    {
        $state = $this->delegatedAccessRead($actor, $target);
        $before = $this->delegatedAccessRecord($target);

        $this->assertDelegatedRefusal([DelegatedRefusal::REVISION_CONFLICT], $actor, $this->delegatedUpdatePayload($target, 'stale-'.hash('sha256', $state['revision']), $state['access']['workspaces'], $state['access']['application_admin']), 'an update against a stale revision');
        $this->assertSame($before, $this->delegatedAccessRecord($target), 'A conflict changes nothing');
    }

    /**
     * A role the application did not advertise is refused, even in a membership the actor may edit.
     *
     * An account-only application advertises none, so there any membership at all is refused.
     */
    protected function assertDelegatedUnadvertisedRoleRefused(string $actor, string $target): void
    {
        $state = $this->delegatedAccessRead($actor, $target);
        $before = $this->delegatedAccessRecord($target);
        if ($this->delegatedAccessAccountOnly()) {
            $membership = ['id' => 'workspace-'.bin2hex(random_bytes(4)), 'role' => 'unadvertised-'.bin2hex(random_bytes(4))];
            $this->assertDelegatedRefusal([DelegatedRefusal::ROLE_NOT_GRANTABLE, DelegatedRefusal::INVALID_REQUEST, DelegatedRefusal::NOT_AUTHORIZED], $actor, $this->delegatedUpdatePayload($target, $state['revision'], [$membership], $state['access']['application_admin']), 'a workspace membership in an account-only application');
            $this->assertSame($before, $this->delegatedAccessRecord($target), 'Refusals change nothing');

            return;
        }

        $memberships = $state['access']['workspaces'];
        $editable = array_values(array_filter($memberships, static fn (array $m): bool => $m['editable']));
        $this->assertNotSame([], $editable, 'Seed the target with a membership the actor may change');

        $role = 'unadvertised-'.bin2hex(random_bytes(4));
        $changed = array_map(static fn (array $m): array => $m['id'] === $editable[0]['id'] ? ['role' => $role] + $m : $m, $memberships);
        $this->assertDelegatedRefusal([DelegatedRefusal::ROLE_NOT_GRANTABLE, DelegatedRefusal::INVALID_REQUEST], $actor, $this->delegatedUpdatePayload($target, $state['revision'], $changed, $state['access']['application_admin']), 'an unadvertised role');
        $this->assertSame($before, $this->delegatedAccessRecord($target), 'Refusals change nothing');
    }

    /**
     * A search finds only what the actor could already see, and reveals nothing beyond it: not an
     * entry, not a cursor to a further page.
     *
     * Seed entries matching `$query` both inside the actor's view and outside it, and entries
     * matching `$outOfScopeQuery` only outside it (another tenant, a workspace the actor does not
     * manage). The search is walked one entry per page, so every cursor is exercised, and compared
     * with the unfiltered listing and with the same search in one page. A query's cursor is then
     * presented with another search, which must be refused as `invalid_cursor` or stay in scope.
     *
     * An account-only application lists no workspaces, so its `workspaces` search is checked to
     * be empty and the rest returns.
     *
     * @param  'subjects'|'workspaces'  $operation
     */
    protected function assertDelegatedSearchStaysInScope(string $actor, string $operation, string $query, string $outOfScopeQuery): void
    {
        $this->assertContains($operation, ['subjects', 'workspaces'], 'Search is on subjects or workspaces');
        foreach ([$outOfScopeQuery, ...($operation === 'workspaces' && $this->delegatedAccessAccountOnly() ? [$query] : [])] as $hidden) {
            foreach ([1, 50] as $limit) {
                $page = $this->delegatedAccessCall($actor, ['operation' => $operation, 'query' => $hidden, 'limit' => $limit]);
                $this->assertSame([], $page[$operation], "A search matching only what the actor may not see finds nothing ({$operation}, limit {$limit})");
                $this->assertNull($page['next_cursor'], "A search matching only what the actor may not see offers no further page ({$operation}, limit {$limit})");
            }
        }
        if ($operation === 'workspaces' && $this->delegatedAccessAccountOnly()) {
            return;
        }

        $scope = $this->delegatedAccessListing($actor, $operation, null, 50);
        $walked = $this->delegatedAccessListing($actor, $operation, $query, 1);
        $this->assertNotSame([], $walked, "Seed an entry the actor may see that matches the {$operation} query");
        $this->assertSame(array_values(array_unique($walked)), $walked, 'A search walked page by page shows each entry once');
        foreach ($walked as $found) {
            $this->assertContains($found, $scope, "Search found {$found}, which the actor's unfiltered {$operation} listing does not show");
        }
        $whole = $this->delegatedAccessListing($actor, $operation, $query, 50);
        sort($whole);
        $sorted = $walked;
        sort($sorted);
        $this->assertSame($whole, $sorted, 'A search finds the same entries whatever the page size');

        // A cursor belongs to its search. Presented with another one it is refused, or stays in scope.
        $first = $this->delegatedAccessCall($actor, ['operation' => $operation, 'query' => $query, 'limit' => 1]);
        if ($first['next_cursor'] === null) {
            return;
        }
        foreach ([['query' => $outOfScopeQuery], []] as $other) {
            try {
                $page = $this->delegatedAccessCall($actor, ['operation' => $operation, 'limit' => 50, 'cursor' => $first['next_cursor'], ...$other]);
            } catch (DelegatedAccessException $refusal) {
                $this->assertSame(DelegatedRefusal::INVALID_CURSOR, $refusal->outcome, 'A cursor presented with another search is refused as invalid_cursor');

                continue;
            }
            foreach ($page[$operation] as $entry) {
                $this->assertContains($entry[$operation === 'subjects' ? 'subject' : 'id'], $scope, 'A cursor presented with another search stays in the actor\'s scope');
            }
        }
    }

    /**
     * `remove` strips the actor's whole projection, application administration included, and nothing
     * else: memberships outside the actor's view survive and the account stays. Removing again, with
     * nothing left to remove, changes nothing and keeps the revision. A stale revision is refused.
     *
     * Seed a target the actor may remove entirely (every membership it sees editable, and an
     * administrator flag, if set, that it may change) with a membership outside the actor's view.
     * An account-only target needs no membership: the administrator flag is the projection.
     */
    protected function assertDelegatedRemoveStripsOnlyTheManagedProjection(string $actor, string $target): void
    {
        $accountOnly = $this->delegatedAccessAccountOnly();
        $state = $this->delegatedAccessRead($actor, $target);
        $before = $this->delegatedAccessRecord($target);
        $shown = array_column($state['access']['workspaces'], 'id');
        $unseen = array_diff_key($before['workspaces'], array_flip($shown));
        ksort($unseen);
        if (! $accountOnly) {
            $this->assertNotSame([], $unseen, 'Seed the target with a membership in a workspace the actor does not manage');
        }
        foreach ($state['access']['workspaces'] as $membership) {
            $this->assertTrue($membership['editable'], "Seed a target whose memberships the actor may all remove; {$membership['id']} is not editable");
        }
        if ($state['access']['application_admin']) {
            $this->assertTrue($state['allowed_edits']['application_admin'], 'Seed a target whose administrator flag the actor may change, or one without it');
        }
        $this->assertTrue($state['allowed_edits']['remove'], 'allowed_edits.remove is true where a removal succeeds');

        $this->assertDelegatedRefusal([DelegatedRefusal::REVISION_CONFLICT], $actor, $this->delegatedRemovePayload($target, 'stale-'.hash('sha256', $state['revision'])), 'a removal against a stale revision');
        $this->assertSame($before, $this->delegatedAccessRecord($target), 'A conflict changes nothing');

        try {
            $removed = $this->delegatedAccessCall($actor, $this->delegatedRemovePayload($target, $state['revision']));
        } catch (DelegatedAccessException $refusal) {
            $this->fail("Removing everything the actor may remove was refused ({$refusal->outcome})");
        }
        $after = $this->delegatedAccessRecord($target);
        $this->assertFalse($after['application_admin'], 'Removal clears application administration');
        $this->assertSame($unseen, $after['workspaces'], 'Removal takes every membership the actor manages and nothing outside its view');

        try {
            $kept = $this->delegatedAccessCall($actor, ['operation' => 'read', 'subject' => $target]);
        } catch (DelegatedAccessException $refusal) {
            $this->fail("The account and its history remain after removal, but a read was refused ({$refusal->outcome})");
        }
        $this->assertTrue($kept['provisioned'], 'The account and its history remain after removal');
        $this->assertSame($removed['revision'], $kept['revision'], 'Removal answers the state it left');
        $this->assertTrue($kept['allowed_edits']['remove'], 'allowed_edits.remove is true where removing again would be a no-op');

        try {
            $again = $this->delegatedAccessCall($actor, $this->delegatedRemovePayload($target, $removed['revision']));
        } catch (DelegatedAccessException $refusal) {
            $this->fail("Removing a subject with nothing left to remove is a no-op, but it was refused ({$refusal->outcome})");
        }
        $this->assertSame($removed['revision'], $again['revision'], 'Removing a subject with nothing left to remove keeps its revision');
        $this->assertSame($after, $this->delegatedAccessRecord($target), 'Removing a subject with nothing left to remove changes nothing');
    }

    /**
     * A removal the actor cannot make whole is refused, changes nothing (not even the parts the actor
     * could have removed on their own), and was never offered: the read said `allowed_edits.remove`
     * false.
     *
     * Seed a target with a membership the actor sees but may not change, or an administrator flag it
     * may not change: the actor themselves where self-demotion is refused, or the last administrator.
     * Or an actor who may read the target but not remove it.
     */
    protected function assertDelegatedRemoveRefusedWithoutPartialChange(string $actor, string $target): void
    {
        $state = $this->delegatedAccessRead($actor, $target);
        $before = $this->delegatedAccessRecord($target);

        $this->assertDelegatedRefusal([DelegatedRefusal::PROTECTED_MEMBERSHIP, DelegatedRefusal::NOT_AUTHORIZED, DelegatedRefusal::INVALID_REQUEST],
            $actor, $this->delegatedRemovePayload($target, $state['revision']), 'removing a subject with something the actor may not remove');
        $this->assertSame($before, $this->delegatedAccessRecord($target), 'A refused removal changes nothing, not even what the actor could have removed');
        $this->assertFalse($state['allowed_edits']['remove'], 'allowed_edits.remove is false where a removal is refused');
    }

    /**
     * Metadata is an observation of the past: each timestamp present is no later than now, and the
     * last time a person was seen is not before their first sign-in. That holds for the target's
     * state and for every entry in the actor's `subjects` listing. The contract has already held each
     * to its shape. Pass a target whose metadata the application knows, to exercise it.
     */
    protected function assertDelegatedMetadataIsWellFormed(string $actor, string $target): void
    {
        $this->assertDelegatedObservations($this->delegatedAccessRead($actor, $target), "{$target}'s state");

        $cursor = null;
        $pages = 0;
        do {
            $page = $this->delegatedAccessCall($actor, ['operation' => 'subjects', 'limit' => 50] + ($cursor === null ? [] : ['cursor' => $cursor]));
            foreach ($page['subjects'] as $entry) {
                $this->assertDelegatedObservations($entry, "the listing entry for {$entry['subject']}");
            }
            $cursor = $page['next_cursor'];
            $this->assertLessThan(1000, ++$pages, 'A subjects listing ends');
        } while ($cursor !== null);
    }

    /**
     * @param  array<string, mixed>  $value  a state or a `subjects` entry
     */
    private function assertDelegatedObservations(array $value, string $where): void
    {
        $now = new DateTimeImmutable('+5 minutes');
        $times = [];
        foreach (DelegatedContract::STATE_METADATA as $field) {
            if (is_string($value[$field] ?? null)) {
                $times[$field] = new DateTimeImmutable($value[$field]);
                $this->assertLessThanOrEqual($now, $times[$field], "{$field} in {$where} is an observation, so it is not in the future");
            }
        }
        if (isset($times['first_sign_in_at'], $times['last_seen_at'])) {
            $this->assertGreaterThanOrEqual($times['first_sign_in_at'], $times['last_seen_at'], "last_seen_at in {$where} is not before first_sign_in_at");
        }
    }

    /**
     * Through the real endpoint: a write repeated with its `operation_id` is answered from the
     * receipt, byte for byte, without reaching the adapter; the `receipt` operation reports it; the
     * same operation id on a different request is refused and changes nothing; and an operation id
     * never sent is unknown.
     *
     * The application's adapter must be bound in a service provider so the route exists, and the
     * receipts migration applied to the test database. This configures the endpoint for the test
     * with a signing key of its own, keeping the application's sign-in provider name.
     */
    protected function assertDelegatedReceiptsReplayThroughTheEndpoint(string $actor, string $target): void
    {
        $calls = $this->delegatedAccessCountAdapterCalls();
        $read = $this->delegatedAccessEndpoint($actor, ['operation' => 'read', 'subject' => $target]);
        $this->assertSame(200, $read->status(), 'Seed a provisioned target the actor can read through the endpoint');
        $state = $read->json();
        $write = $this->delegatedUpdatePayload($target, $state['revision'], $state['access']['workspaces'], $state['access']['application_admin']);

        $seen = $calls->calls;
        $first = $this->delegatedAccessEndpoint($actor, $write);
        $this->assertContains($first->status(), [200, 403, 404, 409, 422], 'A write is answered with a state or a refusal');
        $this->assertGreaterThan($seen, $calls->calls, 'The first attempt of an operation reaches the adapter');
        $after = $this->delegatedAccessRecord($target);

        $seen = $calls->calls;
        $again = $this->delegatedAccessEndpoint($actor, $write);
        $this->assertSame([$first->status(), $first->getContent()], [$again->status(), $again->getContent()], 'A repeated operation gets the stored answer');
        $this->assertSame($seen, $calls->calls, 'A repeated operation never reaches the adapter');

        $contract = new DelegatedContract;
        $application = (string) config('bherila-auth.delegated_access.application');
        $receipt = $this->delegatedAccessEndpoint($actor, ['operation' => 'receipt', 'operation_id' => $write['operation_id']]);
        $this->assertSame(200, $receipt->status());
        $known = $contract->receipt($receipt->json(), $application, $contract->request($application, $write, DelegatedContract::VERSION_3));
        $this->assertSame(['known', $first->status(), $first->json()], [$known['status'], $known['response_status'] ?? null, $known['response'] ?? null], 'The receipt holds the answer that was sent');

        $conflict = $this->delegatedAccessEndpoint($actor, [...$write, 'expected_revision' => 'another-'.hash('sha256', (string) $state['revision'])]);
        $this->assertSame([422, ['error' => 'invalid_request']], [$conflict->status(), $conflict->json()], 'The same operation id on another request is refused');
        $this->assertSame($seen, $calls->calls, 'A conflicting operation never reaches the adapter');
        $this->assertSame($after, $this->delegatedAccessRecord($target), 'A conflicting operation changes nothing');

        $unknown = $this->delegatedAccessEndpoint($actor, ['operation' => 'receipt', 'operation_id' => DelegatedContract::operationId()]);
        $this->assertSame('unknown', $unknown->json('status'), 'An operation never sent is unknown');
    }

    /**
     * POST a version 3 request to the real endpoint as `$actor`, signed with a key this configures.
     *
     * @param  array<string, mixed>  $input  `operation` plus its fields
     * @return TestResponse<Response>
     */
    protected function delegatedAccessEndpoint(string $actor, array $input): TestResponse
    {
        $this->assertTrue(app('router')->has('bherila-auth.delegated-access'), 'Bind ApplicationAccessAdapter in a service provider\'s register() so the endpoint route exists');
        $key = $this->delegatedAccessEndpointKey();
        $application = (string) config('bherila-auth.delegated_access.application');
        $body = (string) json_encode(['contract_version' => DelegatedContract::VERSION_3, 'application' => $application, ...$input], JSON_UNESCAPED_SLASHES);
        $now = new DateTimeImmutable('@'.time());
        $assertion = Builder::new(new JoseEncoder, ChainedFormatter::withUnixTimestampDates())
            ->withHeader('typ', 'application-access+jwt')
            ->withHeader('kid', 'conformance')
            ->issuedBy((string) config('bherila-auth.delegated_access.issuer'))
            ->relatedTo($actor)
            ->permittedFor((string) config('bherila-auth.delegated_access.endpoint'))
            ->issuedAt($now)->expiresAt($now->modify('+60 seconds'))
            ->identifiedBy(bin2hex(random_bytes(32)))
            ->withClaim('application', $application)
            ->withClaim('method', 'POST')
            ->withClaim('body_sha256', hash('sha256', $body))
            ->getToken(new Sha256, InMemory::plainText($key))
            ->toString();

        return $this->call('POST', (string) config('bherila-auth.delegated_access.path', '/application-access'), [], [], [], [
            'CONTENT_TYPE' => 'application/json',
            'HTTP_ACCEPT' => 'application/json',
            'HTTP_AUTHORIZATION' => 'Bearer '.$assertion,
        ], $body);
    }

    /**
     * Configure the endpoint to trust a key generated for this test, and return its private half.
     *
     * Keeps the application's `oauth_client.provider`, which its adapter resolves bindings under. The
     * nonce store is replaced with an in-memory one, since the database store rightly refuses a
     * test transaction; the receipt store is the real one.
     */
    private function delegatedAccessEndpointKey(): string
    {
        $configured = app()->bound('bherila-auth.testing.delegated-signing-key') ? app('bherila-auth.testing.delegated-signing-key') : null;
        if (is_string($configured)) {
            return $configured;
        }

        $pair = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        $this->assertNotFalse($pair, 'Generate a signing key');
        openssl_pkey_export($pair, $private);
        $path = (string) tempnam(sys_get_temp_dir(), 'delegated-conformance-');
        file_put_contents($path, openssl_pkey_get_details($pair)['key'] ?? '');
        $this->beforeApplicationDestroyed(static function () use ($path): void {
            @unlink($path);
        });

        $issuer = rtrim((string) config('bherila-auth.oauth_client.base_url'), '/');
        if (! str_starts_with($issuer, 'https://')) {
            $issuer = 'https://identity.example.test';
            config(['bherila-auth.oauth_client.base_url' => $issuer]);
        }
        config([
            'bherila-auth.delegated_access.enabled' => true,
            'bherila-auth.delegated_access.writes_enabled' => true,
            'bherila-auth.delegated_access.issuer' => $issuer,
            'bherila-auth.delegated_access.endpoint' => 'https://application.example.test/application-access',
            'bherila-auth.delegated_access.application' => (string) config('bherila-auth.delegated_access.application') ?: 'application',
            'bherila-auth.delegated_access.public_keys' => 'conformance|'.$path,
            'bherila-auth.delegated_access.oauth_provider' => (string) config('bherila-auth.oauth_client.provider'),
            'bherila-auth.delegated_access.per_minute' => 100000,
        ]);
        app()->instance(NonceStore::class, new class implements NonceStore
        {
            /** @var array<string, true> */
            private array $seen = [];

            public function consume(string $key, int $seconds): bool
            {
                if (isset($this->seen[$key])) {
                    return false;
                }

                return $this->seen[$key] = true;
            }
        });
        app()->instance('bherila-auth.testing.delegated-signing-key', (string) $private);

        return (string) $private;
    }

    /**
     * Count the adapter's calls from now on, however it is bound. Each call wraps afresh with its own
     * counter, so a binding replaced since an earlier wrap is still counted.
     *
     * @return stdClass `calls`: how many times the adapter has been called since
     */
    private function delegatedAccessCountAdapterCalls(): stdClass
    {
        $counter = new stdClass;
        $counter->calls = 0;
        app()->extend(ApplicationAccessAdapter::class, static fn (ApplicationAccessAdapter $adapter): ApplicationAccessAdapter => new class($adapter, $counter) implements ApplicationAccessAdapter
        {
            public function __construct(private ApplicationAccessAdapter $inner, private stdClass $counter) {}

            public function handle(string $actorSubject, array $payload): array
            {
                $this->counter->calls++;

                return $this->inner->handle($actorSubject, $payload);
            }
        });

        return $counter;
    }

    /**
     * Every identifier a listing shows, walking its cursors to the end.
     *
     * @return list<string>
     */
    private function delegatedAccessListing(string $actor, string $operation, ?string $query, int $limit): array
    {
        $found = [];
        $cursor = null;
        $cursors = [];
        do {
            $page = $this->delegatedAccessCall($actor, ['operation' => $operation, 'limit' => $limit]
                + ($query === null ? [] : ['query' => $query]) + ($cursor === null ? [] : ['cursor' => $cursor]));
            $this->assertLessThanOrEqual($limit, count($page[$operation]), "A {$operation} page holds at most the limit asked for");
            foreach ($page[$operation] as $entry) {
                $found[] = (string) $entry[$operation === 'subjects' ? 'subject' : 'id'];
            }
            $cursor = $page['next_cursor'];
            $this->assertNotContains($cursor, $cursors, "A {$operation} listing never returns to a cursor it already gave");
            $cursors[] = $cursor;
            $this->assertLessThan(1000, count($cursors), "A {$operation} listing ends");
        } while ($cursor !== null);

        return $found;
    }

    /**
     * Call the adapter as the endpoint does, with the request context bound, and validate the answer
     * against contract version 3 as the endpoint would before sending it.
     *
     * This calls the adapter directly, so it bypasses the endpoint's receipts: every call reaches the
     * adapter. {@see delegatedAccessEndpoint()} goes through the endpoint.
     *
     * @param  array<string, mixed>  $payload
     * @return array<string, mixed> the operation's fields, with the envelope added
     */
    protected function delegatedAccessCall(string $actor, array $payload): array
    {
        $application = (string) config('bherila-auth.delegated_access.application', 'application');
        $contract = new DelegatedContract;
        $contract->request($application, $payload, DelegatedContract::VERSION_3);

        $container = app();
        $container->instance(DelegatedRequestContext::class, new DelegatedRequestContext(
            (string) config('bherila-auth.delegated_access.issuer', 'https://identity.example.test'),
            $actor, $application, bin2hex(random_bytes(32)), (string) $payload['operation'],
            is_string($payload['operation_id'] ?? null) ? $payload['operation_id'] : null,
        ));
        try {
            $fields = $container->make(ApplicationAccessAdapter::class)->handle($actor, $payload);
        } catch (DelegatedAccessException $refusal) {
            // The endpoint sends a refusal as it is, so it has to be one a provider can act on.
            $this->assertSame(DelegatedRefusal::STATUSES[$refusal->outcome] ?? null, $refusal->status, "The adapter refused {$payload['operation']} with a named outcome and its status, not {$refusal->outcome} ({$refusal->status})");

            throw $refusal;
        } finally {
            $container->forgetInstance(DelegatedRequestContext::class);
        }

        try {
            $answer = $contract->adapterAnswer($fields, $application, (string) $payload['operation'], $payload['subject'] ?? null);
        } catch (DelegatedAccessException) {
            $this->fail("The adapter's answer to {$payload['operation']} is outside the contract; the endpoint would send internal_error instead");
        }

        // The endpoint validates one answer at a time and cannot see this; a provider holding the
        // capabilities refuses an account-only application's answer that reports workspaces.
        if (in_array($payload['operation'], ['workspaces', 'read', 'update', 'remove'], true)) {
            $this->assertTrue($contract->fitsCapabilities($this->delegatedAccessCapabilities(), $answer), "The adapter's answer to {$payload['operation']} reports workspaces, but the application advertises no workspace roles");
        }

        return $answer;
    }

    /**
     * @return array<string, mixed> a provisioned state
     */
    protected function delegatedAccessRead(string $actor, string $target): array
    {
        $state = $this->delegatedAccessCall($actor, ['operation' => 'read', 'subject' => $target]);
        $this->assertTrue($state['provisioned'], 'Seed a provisioned target the actor can see');

        return $state;
    }

    /**
     * @param  list<array{id: string, role: string, editable?: bool}>  $memberships
     * @return array<string, mixed>
     */
    protected function delegatedAccessUpdate(string $actor, string $target, string $revision, array $memberships, bool $applicationAdmin): array
    {
        return $this->delegatedAccessCall($actor, $this->delegatedUpdatePayload($target, $revision, $memberships, $applicationAdmin));
    }

    /**
     * The advertised role ids, from capabilities as an authorized actor would see them.
     *
     * @return list<string>
     */
    protected function delegatedAccessRoles(): array
    {
        return array_column($this->delegatedAccessCapabilities()['controls']['workspace_roles'], 'id');
    }

    /**
     * Capabilities as the application advertises them to {@see delegatedAccessManager()}.
     *
     * @return array<string, mixed>
     */
    protected function delegatedAccessCapabilities(): array
    {
        return $this->delegatedAccessCall($this->delegatedAccessManager(), ['operation' => 'capabilities']);
    }

    /** Whether the application advertises no workspace roles, so it has accounts and no workspaces. */
    protected function delegatedAccessAccountOnly(): bool
    {
        return (new DelegatedContract)->accountOnly($this->delegatedAccessCapabilities());
    }

    /**
     * @param  list<string>  $outcomes
     * @param  array<string, mixed>  $payload
     */
    protected function assertDelegatedRefusal(array $outcomes, string $actor, array $payload, string $what): void
    {
        try {
            $this->delegatedAccessCall($actor, $payload);
        } catch (DelegatedAccessException $refusal) {
            $this->assertContains($refusal->outcome, $outcomes, "Refused {$what} with an expected outcome");

            return;
        }

        $this->fail("Accepted {$what}");
    }

    /**
     * {@see delegatedAccessTruth()} in a stable order, so a rewrite that changes nothing compares equal.
     *
     * @return array{application_admin: bool, workspaces: array<string, string>}
     */
    private function delegatedAccessRecord(string $subject): array
    {
        $truth = $this->delegatedAccessTruth($subject);
        ksort($truth['workspaces']);

        return $truth;
    }

    /**
     * @param  list<array{id: string, role: string, editable?: bool}>  $memberships
     * @return array<string, mixed>
     */
    private function delegatedUpdatePayload(string $target, string $revision, array $memberships, bool $applicationAdmin): array
    {
        return ['operation' => 'update', 'subject' => $target, 'expected_revision' => $revision, 'access' => [
            'application_admin' => $applicationAdmin,
            'workspaces' => array_map(static fn (array $m): array => ['id' => $m['id'], 'role' => $m['role']], $memberships),
        ], 'operation_id' => DelegatedContract::operationId()];
    }

    /**
     * @return array<string, mixed>
     */
    private function delegatedRemovePayload(string $target, string $revision): array
    {
        return ['operation' => 'remove', 'subject' => $target, 'expected_revision' => $revision, 'operation_id' => DelegatedContract::operationId()];
    }
}
