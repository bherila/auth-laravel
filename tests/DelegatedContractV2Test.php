<?php

namespace BWH\Auth\Tests;

use BWH\Auth\OAuth\DelegatedAccess\DelegatedAccessException;
use BWH\Auth\OAuth\DelegatedAccess\DelegatedContract;
use PHPUnit\Framework\TestCase;

/**
 * Contract version 2: application-defined workspace roles, per-membership edit flags and
 * provisioning of unprovisioned subjects (bherila/auth-laravel#42).
 *
 * Version 1 is untouched and keeps its own tests. Every case here names the version explicitly,
 * because the version is what an application and its provider agree on.
 */
class DelegatedContractV2Test extends TestCase
{
    private const APP = 'example-app';

    public function test_version_one_remains_the_default_and_cannot_accept_a_v2_shape(): void
    {
        $contract = new DelegatedContract;

        $this->assertSame(1, $contract->request(self::APP, ['operation' => 'capabilities'])['contract_version']);
        $this->assertSame(2, $contract->request(self::APP, ['operation' => 'capabilities'], 2)['contract_version']);

        $this->refused(fn () => $contract->request(self::APP, $this->update(), 1), 422);
        $this->refused(fn () => $contract->response($this->capabilities(), self::APP, 'capabilities', null, 1), 503);
        $this->refused(fn () => $contract->request(self::APP, ['operation' => 'capabilities'], 3), 500);
    }

    public function test_an_update_names_roles_within_their_bounds(): void
    {
        $contract = new DelegatedContract;
        $access = ['application_admin' => false, 'workspaces' => array_map(
            static fn (int $id): array => ['id' => (string) $id, 'role' => str_repeat('r', 64)],
            range(1, 100),
        )];

        $this->assertSame($access, $contract->request(self::APP, $this->update(['access' => $access]), 2)['access']);

        foreach ([
            'a role id longer than 64 bytes' => [['id' => 'w1', 'role' => str_repeat('r', 65)]],
            'an empty role id' => [['id' => 'w1', 'role' => '']],
            'a v1 permission instead of a role' => [['id' => 'w1', 'permission' => 'write']],
            'an edit flag, which is the application\'s to say' => [['id' => 'w1', 'role' => 'sender', 'editable' => true]],
            'the same workspace twice' => [['id' => 'w1', 'role' => 'sender'], ['id' => 'w1', 'role' => 'auditor']],
        ] as $label => $workspaces) {
            $this->refused(
                fn () => $contract->request(self::APP, $this->update(['access' => ['application_admin' => false, 'workspaces' => $workspaces]]), 2),
                422,
                $label,
            );
        }

        $this->refused(fn () => $contract->request(self::APP, $this->update(['access' => [...$access, 'workspaces' => [...$access['workspaces'], ['id' => '101', 'role' => 'sender']]]]), 2), 422);
    }

    public function test_provisioning_is_an_update_with_a_null_revision_and_an_optional_display_name(): void
    {
        $contract = new DelegatedContract;

        $provision = $this->update(['expected_revision' => null, 'display_name' => str_repeat('n', 255)]);
        $this->assertNull($contract->request(self::APP, $provision, 2)['expected_revision']);
        $this->assertNull($contract->request(self::APP, $this->update(['expected_revision' => null]), 2)['expected_revision']);

        $this->refused(fn () => $contract->request(self::APP, $this->update(['display_name' => 'Example Person']), 2), 422, 'a display name on an ordinary update');
        $this->refused(fn () => $contract->request(self::APP, $this->update(['expected_revision' => null, 'display_name' => str_repeat('n', 256)]), 2), 422);
        $this->refused(fn () => $contract->request(self::APP, $this->update(['expected_revision' => null, 'display_name' => '']), 2), 422);
        $this->refused(fn () => $contract->request(self::APP, $this->update(['expected_revision' => '']), 2), 422);

        $withoutRevision = $this->update();
        unset($withoutRevision['expected_revision']);
        $this->refused(fn () => $contract->request(self::APP, $withoutRevision, 2), 422, 'a missing revision is not a null one');
    }

    public function test_capabilities_advertise_roles_and_provisioning(): void
    {
        $contract = new DelegatedContract;

        $this->assertSame($this->capabilities(), $contract->response($this->capabilities(), self::APP, 'capabilities', null, 2));
        $this->assertSame(['owner', 'admin', 'sender', 'auditor'], $contract->advertisedRoleIds($this->capabilities()));

        $roles = $this->capabilities()['controls']['workspace_roles'];
        foreach ([
            'no roles' => ['workspace_roles' => []],
            'seventeen roles' => ['workspace_roles' => array_map(static fn (int $i): array => ['id' => 'r'.$i, 'label' => 'Role '.$i], range(1, 17))],
            'a duplicated role' => ['workspace_roles' => [$roles[0], $roles[0]]],
            'a role label longer than 255 bytes' => ['workspace_roles' => [['id' => 'owner', 'label' => str_repeat('l', 256)]]],
            'a missing provisioning flag' => ['provisioning' => null],
            'v1 permissions alongside' => ['workspace_permissions' => ['read']],
        ] as $label => $change) {
            $controls = array_filter([...$this->capabilities()['controls'], ...$change], static fn (mixed $value): bool => $value !== null);
            $this->refused(fn () => $contract->response([...$this->capabilities(), 'controls' => $controls], self::APP, 'capabilities', null, 2), 503, $label);
        }
    }

    public function test_a_provisioned_state_carries_roles_and_edit_flags(): void
    {
        $contract = new DelegatedContract;
        $state = $this->state();

        $this->assertSame($state, $contract->response($state, self::APP, 'read', 'subject-example', 2));

        foreach ([
            'a membership without an edit flag' => ['access' => ['application_admin' => false, 'workspaces' => [['id' => 'w1', 'role' => 'sender']]]],
            'an edit flag that is not a boolean' => ['access' => ['application_admin' => false, 'workspaces' => [['id' => 'w1', 'role' => 'sender', 'editable' => 'yes']]]],
            'a v1 permission' => ['access' => ['application_admin' => false, 'workspaces' => [['id' => 'w1', 'permission' => 'write', 'editable' => true]]]],
            'an offer to provision an account that exists' => ['allowed_edits' => ['application_admin' => false, 'workspaces' => true, 'provision' => true]],
            'no revision' => ['revision' => null],
            'allowed edits without the provision flag' => ['allowed_edits' => ['application_admin' => false, 'workspaces' => true]],
        ] as $label => $change) {
            $this->refused(fn () => $contract->response([...$state, ...$change], self::APP, 'read', 'subject-example', 2), 503, $label);
        }
    }

    public function test_an_unprovisioned_state_may_offer_only_provisioning(): void
    {
        $contract = new DelegatedContract;
        $unprovisioned = [...$this->state(), 'provisioned' => false, 'revision' => null, 'access' => null,
            'allowed_edits' => ['application_admin' => false, 'workspaces' => false, 'provision' => true]];

        $this->assertSame($unprovisioned, $contract->response($unprovisioned, self::APP, 'read', 'subject-example', 2));
        $closed = [...$unprovisioned, 'allowed_edits' => [...$unprovisioned['allowed_edits'], 'provision' => false]];
        $this->assertSame($closed, $contract->response($closed, self::APP, 'read', 'subject-example', 2));

        foreach ([
            'workspace edits on an account that does not exist' => ['allowed_edits' => ['application_admin' => false, 'workspaces' => true, 'provision' => true]],
            'a revision for an account that does not exist' => ['revision' => 'rev-1'],
            'access for an account that does not exist' => ['access' => ['application_admin' => false, 'workspaces' => []]],
        ] as $label => $change) {
            $this->refused(fn () => $contract->response([...$unprovisioned, ...$change], self::APP, 'read', 'subject-example', 2), 503, $label);
        }
    }

    public function test_roles_in_an_access_value_must_be_advertised(): void
    {
        $contract = new DelegatedContract;
        $capabilities = $this->capabilities();

        $this->assertTrue($contract->rolesAreAdvertised($capabilities, ['application_admin' => false, 'workspaces' => [['id' => 'w1', 'role' => 'auditor']]]));
        $this->assertTrue($contract->rolesAreAdvertised($capabilities, $this->state()['access']));
        $this->assertFalse($contract->rolesAreAdvertised($capabilities, ['application_admin' => false, 'workspaces' => [['id' => 'w1', 'role' => 'emperor']]]));
        $this->assertFalse($contract->rolesAreAdvertised(['controls' => []], ['application_admin' => false, 'workspaces' => [['id' => 'w1', 'role' => 'auditor']]]));
    }

    public function test_pages_are_the_same_in_both_versions(): void
    {
        $contract = new DelegatedContract;
        $page = ['contract_version' => 2, 'application' => self::APP, 'operation' => 'workspaces', 'workspaces' => [['id' => 'w1', 'label' => 'Example Workspace']], 'next_cursor' => null];

        $this->assertSame($page, $contract->response($page, self::APP, 'workspaces', null, 2));
        $this->refused(fn () => $contract->response([...$page, 'contract_version' => 1], self::APP, 'workspaces', null, 2), 503);
    }

    /**
     * @param  array<string, mixed>  $changes
     * @return array<string, mixed>
     */
    private function update(array $changes = []): array
    {
        return [
            'operation' => 'update',
            'subject' => 'subject-example',
            'expected_revision' => 'rev-1',
            'access' => ['application_admin' => false, 'workspaces' => [['id' => 'w1', 'role' => 'sender']]],
            ...$changes,
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private function capabilities(): array
    {
        return [
            'contract_version' => 2,
            'application' => self::APP,
            'operation' => 'capabilities',
            'controls' => [
                'application_admin' => false,
                'workspace_roles' => [
                    ['id' => 'owner', 'label' => 'Owner'],
                    ['id' => 'admin', 'label' => 'Administrator'],
                    ['id' => 'sender', 'label' => 'Sender'],
                    ['id' => 'auditor', 'label' => 'Auditor'],
                ],
                'provisioning' => true,
            ],
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private function state(): array
    {
        return [
            'contract_version' => 2,
            'application' => self::APP,
            'operation' => 'read',
            'subject' => 'subject-example',
            'provisioned' => true,
            'revision' => 'rev-1',
            'access' => ['application_admin' => false, 'workspaces' => [
                ['id' => 'w1', 'role' => 'owner', 'editable' => false],
                ['id' => 'w2', 'role' => 'sender', 'editable' => true],
            ]],
            'allowed_edits' => ['application_admin' => false, 'workspaces' => true, 'provision' => false],
        ];
    }

    private function refused(callable $action, int $status, string $label = ''): void
    {
        try {
            $action();
            $this->fail('Expected contract refusal'.($label === '' ? '.' : ': '.$label.'.'));
        } catch (DelegatedAccessException $exception) {
            $this->assertSame($status, $exception->status, $label);
        }
    }
}
