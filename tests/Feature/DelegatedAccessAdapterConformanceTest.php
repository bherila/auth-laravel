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

    protected function setUp(): void
    {
        parent::setUp();
        $this->adapter = new InMemoryAccessAdapter;
        // w1: editable by the manager; w2: visible but protected; w3: outside the manager's view.
        $this->adapter->memberships['target'] = ['w1' => 'member', 'w2' => 'owner', 'w3' => 'member'];
        $this->app->instance(ApplicationAccessAdapter::class, $this->adapter);
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
        $this->assertDelegatedUpdateKeepsUnseenMemberships('manager', 'target');

        // The last assertion removed what the manager may remove, and nothing else.
        $this->assertEquals(['w2' => 'owner', 'w3' => 'member'], $this->adapter->memberships['target']);
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
            'any role accepted' => ['accept_any_role', 'assertDelegatedUnadvertisedRoleRefused', ['manager', 'target']],
            'a refusal sent as a server error' => ['refuse_removal_with_a_server_error', 'assertDelegatedUpdateKeepsUnseenMemberships', ['manager', 'target']],
            'an answer with a field the endpoint refuses' => ['answer_an_extra_field', 'assertDelegatedStaleRevisionRefused', ['manager', 'target']],
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
