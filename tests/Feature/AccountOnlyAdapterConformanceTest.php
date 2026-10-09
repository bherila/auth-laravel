<?php

namespace BWH\Auth\Tests\Feature;

use BWH\Auth\OAuth\DelegatedAccess\ApplicationAccessAdapter;
use BWH\Auth\Testing\AssertsDelegatedAccessAdapter;
use BWH\Auth\Tests\Fixtures\AccountOnlyAccessAdapter;
use BWH\Auth\Tests\TestCase;
use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\Attributes\DataProvider;

/**
 * The adapter conformance assertions run against an account-only adapter: no workspace roles, only
 * application administration and provisioning. The membership parts return; nothing is skipped.
 */
class AccountOnlyAdapterConformanceTest extends TestCase
{
    use AssertsDelegatedAccessAdapter;

    private AccountOnlyAccessAdapter $adapter;

    protected function setUp(): void
    {
        parent::setUp();
        $this->adapter = new AccountOnlyAccessAdapter;
        // manager and other are administrators; target is an ordinary account.
        $this->adapter->accounts = ['manager' => true, 'other' => true, 'target' => false];
        $this->app->instance(ApplicationAccessAdapter::class, $this->adapter);
    }

    protected function delegatedAccessTruth(string $subject): array
    {
        return ['application_admin' => $this->adapter->accounts[$subject] ?? false, 'workspaces' => []];
    }

    protected function delegatedAccessManager(): string
    {
        return 'manager';
    }

    public function test_a_conformant_account_only_adapter_passes_every_assertion(): void
    {
        $this->assertTrue($this->delegatedAccessAccountOnly());

        $this->assertDelegatedActorRefusedEverywhere('target', 'other');
        $this->assertDelegatedProtectedMembershipsHold('manager', 'target');
        // Self-demotion is refused, so this exercises the refusal rather than returning early.
        $this->assertDelegatedApplicationAdminFollowsAllowedEdits('manager', 'manager');
        $this->assertDelegatedApplicationAdminFollowsAllowedEdits('manager', 'target');
        $this->assertDelegatedStaleRevisionRefused('manager', 'target');
        $this->assertDelegatedUnadvertisedRoleRefused('manager', 'target');
        $this->assertDelegatedUpdateKeepsUnseenMemberships('manager', 'target');

        // Every assertion ran to the end and changed nothing.
        $this->assertSame(['manager' => true, 'other' => true, 'target' => false], $this->adapter->accounts);
    }

    public function test_the_last_administrator_cannot_be_demoted(): void
    {
        $this->adapter->accounts = ['manager' => true, 'target' => false];

        $this->assertFalse($this->delegatedAccessRead('manager', 'manager')['allowed_edits']['application_admin']);
        $this->assertDelegatedApplicationAdminFollowsAllowedEdits('manager', 'manager');
        $this->assertTrue($this->adapter->accounts['manager']);
    }

    public function test_provisioning_carries_no_memberships_and_an_explicit_administrator_flag(): void
    {
        $unprovisioned = $this->delegatedAccessCall('manager', ['operation' => 'read', 'subject' => 'newcomer']);
        $this->assertFalse($unprovisioned['provisioned']);
        $this->assertTrue($unprovisioned['allowed_edits']['provision']);

        $created = $this->delegatedAccessCall('manager', ['operation' => 'update', 'subject' => 'newcomer', 'expected_revision' => null,
            'display_name' => 'Example Newcomer', 'access' => ['application_admin' => true, 'workspaces' => []]]);
        $this->assertSame(['application_admin' => true, 'workspaces' => []], $created['access']);
        $this->assertTrue($this->adapter->accounts['newcomer']);
    }

    /**
     * @return array<string, array{string, string, list<string>}>
     */
    public static function violations(): array
    {
        return [
            'reads open to an actor who may not manage access' => ['refuse_only_writes', 'assertDelegatedActorRefusedEverywhere', ['target', 'other']],
            'a workspace membership accepted' => ['accept_workspaces', 'assertDelegatedUnadvertisedRoleRefused', ['manager', 'target']],
            'self-demotion allowed' => ['allow_self_demotion', 'assertDelegatedApplicationAdminFollowsAllowedEdits', ['manager', 'manager']],
            'a read reporting a membership' => ['report_workspaces', 'assertDelegatedStaleRevisionRefused', ['manager', 'target']],
            'revisions not compared' => ['ignore_revision', 'assertDelegatedStaleRevisionRefused', ['manager', 'target']],
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
            $this->assertStringNotContainsString('Seed', $caught->getMessage());

            return;
        }

        $this->fail("{$assertion} passed an adapter with {$flaw}");
    }
}
