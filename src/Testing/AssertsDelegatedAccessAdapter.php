<?php

namespace BWH\Auth\Testing;

use BWH\Auth\OAuth\DelegatedAccess\ApplicationAccessAdapter;
use BWH\Auth\OAuth\DelegatedAccess\DelegatedAccessException;
use BWH\Auth\OAuth\DelegatedAccess\DelegatedContract;
use BWH\Auth\OAuth\DelegatedAccess\DelegatedRefusal;
use BWH\Auth\OAuth\DelegatedAccess\DelegatedRequestContext;

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
 * @mixin \PHPUnit\Framework\TestCase
 */
trait AssertsDelegatedAccessAdapter
{
    /**
     * The application's own record of a subject's access, read without going through the adapter.
     *
     * Include every membership, not only those any particular actor manages.
     *
     * @return array{application_admin: bool, workspaces: array<string, string>} workspace id => role id
     */
    abstract protected function delegatedAccessTruth(string $subject): array;

    /** An actor who may manage access, whose capabilities response is the application's. */
    abstract protected function delegatedAccessManager(): string;

    /**
     * An actor who may not manage access is refused every operation, including the read-only ones.
     */
    protected function assertDelegatedActorRefusedEverywhere(string $actor, string $target, string $workspace): void
    {
        $before = $this->delegatedAccessRecord($target);
        $payloads = [
            ['operation' => 'capabilities'],
            ['operation' => 'subjects', 'limit' => 50],
            ['operation' => 'workspaces', 'limit' => 50],
            ['operation' => 'read', 'subject' => $target],
            ['operation' => 'update', 'subject' => $target, 'expected_revision' => 'any-revision',
                'access' => ['application_admin' => false, 'workspaces' => [['id' => $workspace, 'role' => $this->delegatedAccessRoles()[0]]]]],
        ];

        foreach ($payloads as $payload) {
            $this->assertDelegatedRefusal([DelegatedRefusal::NOT_AUTHORIZED], $actor, $payload, $payload['operation'].' by an actor who may not manage access');
        }
        $this->assertSame($before, $this->delegatedAccessRecord($target), 'Refusals change nothing');
    }

    /**
     * An update replaces only what the actor was shown. Memberships outside the actor's view survive
     * a resubmitted read, and survive removing everything the actor may remove.
     */
    protected function assertDelegatedUpdateKeepsUnseenMemberships(string $actor, string $target): void
    {
        $state = $this->delegatedAccessRead($actor, $target);
        $before = $this->delegatedAccessRecord($target);
        $shown = array_column($state['access']['workspaces'], 'id');
        $unseen = array_diff_key($before['workspaces'], array_flip($shown));
        $this->assertNotSame([], $unseen, 'Seed the target with a membership in a workspace the actor does not manage');

        $resubmitted = $this->delegatedAccessUpdate($actor, $target, $state['revision'], $state['access']['workspaces'], $state['access']['application_admin']);
        $this->assertSame($before, $this->delegatedAccessRecord($target), 'Resubmitting what was read changes nothing');

        $protected = array_values(array_filter($resubmitted['access']['workspaces'], static fn (array $m): bool => ! $m['editable']));
        try {
            $this->delegatedAccessUpdate($actor, $target, $resubmitted['revision'], $protected, $resubmitted['access']['application_admin']);
        } catch (DelegatedAccessException $refusal) {
            // Removing the editable memberships may be refused for the application's own reasons, such as a
            // last administrator. Then it must change nothing.
            $this->assertNotSame(503, $refusal->status, 'A refusal is a 4xx, never an unknown result');
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
     * returns without checking. Seed an actor who may not to exercise it. It never skips: a skip
     * would end the whole test method and silently drop the assertions after it.
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
     */
    protected function assertDelegatedUnadvertisedRoleRefused(string $actor, string $target): void
    {
        $state = $this->delegatedAccessRead($actor, $target);
        $before = $this->delegatedAccessRecord($target);
        $memberships = $state['access']['workspaces'];
        $editable = array_values(array_filter($memberships, static fn (array $m): bool => $m['editable']));
        $this->assertNotSame([], $editable, 'Seed the target with a membership the actor may change');

        $role = 'unadvertised-'.bin2hex(random_bytes(4));
        $changed = array_map(static fn (array $m): array => $m['id'] === $editable[0]['id'] ? ['role' => $role] + $m : $m, $memberships);
        $this->assertDelegatedRefusal([DelegatedRefusal::ROLE_NOT_GRANTABLE, DelegatedRefusal::INVALID_REQUEST], $actor, $this->delegatedUpdatePayload($target, $state['revision'], $changed, $state['access']['application_admin']), 'an unadvertised role');
        $this->assertSame($before, $this->delegatedAccessRecord($target), 'Refusals change nothing');
    }

    /**
     * Call the adapter as the endpoint does, with the request context bound, and validate the answer
     * against contract version 2 as the endpoint would before sending it.
     *
     * @param  array<string, mixed>  $payload
     * @return array<string, mixed> the operation's fields, with the envelope added
     */
    protected function delegatedAccessCall(string $actor, array $payload): array
    {
        $application = (string) config('bherila-auth.delegated_access.application', 'application');
        $contract = new DelegatedContract;
        $contract->request($application, $payload, DelegatedContract::VERSION_2);

        $container = app();
        $container->instance(DelegatedRequestContext::class, new DelegatedRequestContext(
            (string) config('bherila-auth.delegated_access.issuer', 'https://identity.example.test'),
            $actor, $application, bin2hex(random_bytes(32)), (string) $payload['operation'],
        ));
        try {
            $fields = $container->make(ApplicationAccessAdapter::class)->handle($actor, $payload);
        } finally {
            $container->forgetInstance(DelegatedRequestContext::class);
        }

        return $contract->response(
            ['contract_version' => DelegatedContract::VERSION_2, 'application' => $application, 'operation' => $payload['operation'], ...$fields],
            $application, (string) $payload['operation'], $payload['subject'] ?? null, DelegatedContract::VERSION_2,
        );
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
            $this->assertSame(DelegatedRefusal::STATUSES[$refusal->outcome] ?? null, $refusal->status, "Refused {$what} with the outcome's status");

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
            'workspaces' => array_values(array_map(static fn (array $m): array => ['id' => $m['id'], 'role' => $m['role']], $memberships)),
        ]];
    }
}
