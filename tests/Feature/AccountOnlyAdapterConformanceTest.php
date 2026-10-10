<?php

namespace BWH\Auth\Tests\Feature;

use BWH\Auth\OAuth\DelegatedAccess\ApplicationAccessAdapter;
use BWH\Auth\OAuth\DelegatedAccess\DelegatedContract;
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
        $this->adapter = new AccountOnlyAccessAdapter;
        // manager and other are administrators; target is an ordinary account; service accounts are
        // never shown to anybody.
        $this->adapter->accounts = ['manager' => true, 'other' => true, 'target' => false, 'service-target' => false];
        $this->adapter->metadata['target'] = ['provisioned_at' => '2026-09-01T10:00:00Z', 'first_sign_in_at' => null, 'last_seen_at' => null];

        parent::setUp();
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
        $this->assertDelegatedSearchStaysInScope('manager', 'subjects', 'target', 'service');
        $this->assertDelegatedSearchStaysInScope('manager', 'workspaces', 'anything', 'nothing');
        $this->assertDelegatedMetadataIsWellFormed('manager', 'target');
        $this->assertDelegatedReceiptsReplayThroughTheEndpoint('manager', 'target');
        // Removal is refused for the actor themselves, and is a no-op for an ordinary account.
        $this->assertDelegatedRemoveRefusedWithoutPartialChange('manager', 'manager');
        $this->assertDelegatedRemoveStripsOnlyTheManagedProjection('manager', 'target');

        // Every assertion ran to the end and changed nothing.
        $this->assertSame(['manager' => true, 'other' => true, 'target' => false, 'service-target' => false], $this->adapter->accounts);

        // Removing another administrator clears the flag and keeps the account.
        $this->assertDelegatedRemoveStripsOnlyTheManagedProjection('manager', 'other');
        $this->assertSame(['manager' => true, 'other' => false, 'target' => false, 'service-target' => false], $this->adapter->accounts);

        // Now manager is the last administrator, which nobody may remove.
        $this->assertFalse($this->delegatedAccessRead('manager', 'manager')['allowed_edits']['application_admin']);
        $this->assertDelegatedRemoveRefusedWithoutPartialChange('manager', 'manager');
        $this->assertTrue($this->adapter->accounts['manager']);
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
            'display_name' => 'Example Newcomer', 'access' => ['application_admin' => true, 'workspaces' => []], 'operation_id' => DelegatedContract::operationId()]);
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
            'a search showing hidden accounts' => ['search_service_accounts', 'assertDelegatedSearchStaysInScope', ['manager', 'subjects', 'target', 'service']],
            'self-removal allowed' => ['allow_self_removal', 'assertDelegatedRemoveRefusedWithoutPartialChange', ['manager', 'manager']],
            'a removal deleting the account' => ['remove_the_account', 'assertDelegatedRemoveStripsOnlyTheManagedProjection', ['manager', 'other']],
            'revisions not compared on removal' => ['ignore_revision', 'assertDelegatedRemoveStripsOnlyTheManagedProjection', ['manager', 'other']],
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
