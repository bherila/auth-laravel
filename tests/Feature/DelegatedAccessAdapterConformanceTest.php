<?php

namespace BWH\Auth\Tests\Feature;

use BWH\Auth\OAuth\DelegatedAccess\ApplicationAccessAdapter;
use BWH\Auth\OAuth\DelegatedAccess\DelegatedAccessException;
use BWH\Auth\OAuth\DelegatedAccess\DelegatedRefusal;
use BWH\Auth\Testing\AssertsDelegatedAccessAdapter;
use BWH\Auth\Tests\Fixtures\InMemoryAccessAdapter;
use BWH\Auth\Tests\TestCase;
use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\SkippedTest;

/**
 * The adapter conformance assertions pass a conformant adapter and catch each way to break one.
 */
class DelegatedAccessAdapterConformanceTest extends TestCase
{
    use AssertsDelegatedAccessAdapter;

    private InMemoryAccessAdapter $adapter;

    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);

        // Bound before the provider boots, as an application binds it, so the endpoint route exists.
        $app->bind(ApplicationAccessAdapter::class, fn (): ApplicationAccessAdapter => $this->adapter);
    }

    protected function defineDatabaseMigrations(): void
    {
        parent::defineDatabaseMigrations();
        $this->loadMigrationsFrom(__DIR__.'/../../database/delegated-access-migrations');
    }

    protected function setUp(): void
    {
        $this->adapter = new InMemoryAccessAdapter;
        // w1: editable by the manager; w2: visible but protected; w3: outside the manager's view.
        $this->adapter->memberships['target'] = ['w1' => 'member', 'w2' => 'owner', 'w3' => 'member'];
        // Everything the manager sees of removable it may remove; w3 is outside its view.
        $this->adapter->memberships['removable'] = ['w1' => 'member', 'w3' => 'owner'];
        // Only in a workspace the manager does not manage.
        $this->adapter->memberships['outsider'] = ['w3' => 'member'];
        $this->adapter->labels = ['target' => 'Example Target', 'removable' => 'Removable Person', 'outsider' => 'Example Outsider'];
        $this->adapter->emails = ['removable' => 'removable@example.test'];
        $this->adapter->metadata['removable'] = ['provisioned_at' => '2026-09-01T10:00:00Z', 'first_sign_in_at' => '2026-09-02T08:15:00+02:00', 'last_seen_at' => '2026-10-09T17:45:00Z'];

        parent::setUp();
    }

    protected function delegatedAccessTruth(string $subject): array
    {
        return ['application_admin' => $this->adapter->admins[$subject] ?? false, 'workspaces' => $this->adapter->memberships[$subject] ?? []];
    }

    protected function delegatedAccessManager(): string
    {
        return 'manager';
    }

    public function test_a_conformant_adapter_passes_every_assertion(): void
    {
        $this->assertDelegatedActorRefusedEverywhere('stranger', 'target', 'w1');
        $this->assertDelegatedProtectedMembershipsHold('manager', 'target');
        $this->assertDelegatedApplicationAdminFollowsAllowedEdits('manager', 'target');
        $this->assertDelegatedStaleRevisionRefused('manager', 'target');
        $this->assertDelegatedUnadvertisedRoleRefused('manager', 'target');
        $this->assertDelegatedSearchStaysInScope('manager', 'subjects', 'Example', 'Outsider');
        $this->assertDelegatedSearchStaysInScope('manager', 'subjects', 'example.test', 'Outsider');
        $this->assertDelegatedSearchStaysInScope('manager', 'workspaces', 'Workspace', 'w3');
        $this->assertDelegatedMetadataIsWellFormed('manager', 'removable');
        $this->assertSame('2026-10-09T17:45:00Z', $this->delegatedAccessCall('manager', ['operation' => 'subjects', 'query' => 'Removable'])['subjects'][0]['last_seen_at']);
        $this->assertDelegatedRemoveRefusedWithoutPartialChange('manager', 'target');
        $this->assertDelegatedReceiptsReplayThroughTheEndpoint('manager', 'target');
        $this->assertDelegatedRemoveStripsOnlyTheManagedProjection('manager', 'removable');
        $this->assertDelegatedUpdateKeepsUnseenMemberships('manager', 'target');

        // The update removed what the manager may remove from target, and the removal everything it
        // may remove from removable; nothing else changed.
        $this->assertEquals(['w2' => 'owner', 'w3' => 'member'], $this->adapter->memberships['target']);
        $this->assertSame(['w3' => 'owner'], $this->adapter->memberships['removable']);
        $this->assertSame(['w3' => 'member'], $this->adapter->memberships['outsider']);
    }

    public function test_removal_clears_an_application_administrator_the_actor_may_change(): void
    {
        $this->adapter->adminEditable = true;
        $this->adapter->admins['removable'] = true;

        $this->assertDelegatedRemoveStripsOnlyTheManagedProjection('manager', 'removable');
        $this->assertFalse($this->adapter->admins['removable']);

        $this->adapter->broken['keep_application_admin_on_removal'] = true;
        $this->adapter->admins['target'] = true;
        unset($this->adapter->memberships['target']['w2']);
        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('Removal clears application administration');
        $this->assertDelegatedRemoveStripsOnlyTheManagedProjection('manager', 'target');
    }

    /** An adapter may apply its own rules before comparing revisions; the stale-revision check must not trip them. */
    public function test_the_stale_revision_check_passes_an_adapter_that_checks_its_rules_first(): void
    {
        $this->adapter->keepsAMember = ['w1'];

        $this->assertDelegatedStaleRevisionRefused('manager', 'target');
    }

    /** Where the actor may change application administration, the rest of the method still runs. */
    public function test_the_application_admin_check_never_skips_the_assertions_after_it(): void
    {
        $this->adapter->adminEditable = true;

        try {
            $this->assertDelegatedApplicationAdminFollowsAllowedEdits('manager', 'target');
        } catch (SkippedTest) {
            $this->fail('Skipping would drop every assertion after this one');
        }
        $this->assertDelegatedStaleRevisionRefused('manager', 'target');
    }

    /** The receipts assertion counts the adapter however it is bound, including a binding replaced since. */
    public function test_the_receipt_assertion_sees_the_adapter_after_its_binding_is_replaced(): void
    {
        $this->assertDelegatedReceiptsReplayThroughTheEndpoint('manager', 'target');
        $this->app->instance(ApplicationAccessAdapter::class, $this->adapter);
        $this->assertDelegatedReceiptsReplayThroughTheEndpoint('manager', 'target');
    }

    /**
     * @return array<string, array{string, string, list<string>}>
     */
    public static function violations(): array
    {
        return [
            'reads open to an unauthorized actor' => ['refuse_only_writes', 'assertDelegatedActorRefusedEverywhere', ['stranger', 'target', 'w1']],
            'an update replaces unseen memberships' => ['replace_wholesale', 'assertDelegatedUpdateKeepsUnseenMemberships', ['manager', 'target']],
            'editable is trusted to the provider' => ['trust_editable', 'assertDelegatedProtectedMembershipsHold', ['manager', 'target']],
            'application administration granted regardless' => ['grant_application_admin', 'assertDelegatedApplicationAdminFollowsAllowedEdits', ['manager', 'target']],
            'revisions not compared' => ['ignore_revision', 'assertDelegatedStaleRevisionRefused', ['manager', 'target']],
            'revisions not compared on removal' => ['ignore_revision', 'assertDelegatedRemoveStripsOnlyTheManagedProjection', ['manager', 'removable']],
            'any role accepted' => ['accept_any_role', 'assertDelegatedUnadvertisedRoleRefused', ['manager', 'target']],
            'a refusal sent as a server error' => ['refuse_removal_with_a_server_error', 'assertDelegatedUpdateKeepsUnseenMemberships', ['manager', 'target']],
            'an answer with a field the endpoint refuses' => ['answer_an_extra_field', 'assertDelegatedStaleRevisionRefused', ['manager', 'target']],
            'a search beyond the actor\'s scope' => ['search_beyond_scope', 'assertDelegatedSearchStaysInScope', ['manager', 'subjects', 'Example', 'Outsider']],
            'a cursor counting what the actor may not see' => ['cursor_counts_beyond_scope', 'assertDelegatedSearchStaysInScope', ['manager', 'subjects', 'Example', 'Outsider']],
            'a workspace cursor counting what the actor may not see' => ['cursor_counts_beyond_scope', 'assertDelegatedSearchStaysInScope', ['manager', 'workspaces', 'Workspace', 'w3']],
            'a query ignored' => ['ignore_query', 'assertDelegatedSearchStaysInScope', ['manager', 'workspaces', 'Workspace', 'w3']],
            'a removal taking unseen memberships' => ['remove_unseen_memberships', 'assertDelegatedRemoveStripsOnlyTheManagedProjection', ['manager', 'removable']],
            'a refused removal leaving part of it done' => ['remove_partially', 'assertDelegatedRemoveRefusedWithoutPartialChange', ['manager', 'target']],
            'a removal deleting the account' => ['remove_the_account', 'assertDelegatedRemoveStripsOnlyTheManagedProjection', ['manager', 'removable']],
            'an empty removal changing the revision' => ['bump_revision_on_an_empty_removal', 'assertDelegatedRemoveStripsOnlyTheManagedProjection', ['manager', 'removable']],
            'metadata from the future' => ['metadata_from_the_future', 'assertDelegatedMetadataIsWellFormed', ['manager', 'removable']],
            'listing metadata from the future' => ['listing_metadata_from_the_future', 'assertDelegatedMetadataIsWellFormed', ['manager', 'target']],
        ];
    }

    /**
     * @param  list<string>  $arguments
     */
    #[DataProvider('violations')]
    public function test_each_assertion_catches_its_violation(string $flaw, string $assertion, array $arguments): void
    {
        $this->adapter->broken[$flaw] = true;

        try {
            $this->{$assertion}(...$arguments);
        } catch (AssertionFailedError $caught) {
            // Caught by the rule itself, not by a scenario that no longer fits the seed.
            $this->assertStringNotContainsString('Seed', $caught->getMessage());

            return;
        }

        $this->fail("{$assertion} passed an adapter with {$flaw}");
    }

    public function test_every_refusal_has_a_status_a_provider_already_understands(): void
    {
        foreach (DelegatedRefusal::STATUSES as $outcome => $status) {
            $this->assertContains($status, [403, 404, 409, 422], $outcome);
            $refusal = DelegatedRefusal::of($outcome);
            $this->assertInstanceOf(DelegatedAccessException::class, $refusal);
            $this->assertSame([$outcome, $status], [$refusal->outcome, $refusal->status]);
        }

        $this->expectException(\InvalidArgumentException::class);
        DelegatedRefusal::of('internal_error');
    }
}
