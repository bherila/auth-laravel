<?php

namespace BWH\Auth\Tests;

use BWH\Auth\OAuth\DelegatedAccess\DelegatedAccessException;
use BWH\Auth\OAuth\DelegatedAccess\DelegatedContract;
use PHPUnit\Framework\TestCase;

/**
 * Application-defined workspace roles, per-membership edit flags, provisioning of unprovisioned
 * subjects (bherila/auth-laravel#42), account-only applications, and the request and page bounds.
 * Search, removal, receipts and metadata are in {@see DelegatedContractV3Test}.
 */
class DelegatedContractRolesTest extends TestCase
{
    private const APP = 'example-app';

    public function test_request_bounds_preserve_exact_subjects_and_opaque_cursors(): void
    {
        $contract = new DelegatedContract;
        $this->assertSame(3, $contract->request(self::APP, ['operation' => 'capabilities'])['contract_version'], 'version 3 is the default');
        $this->assertSame(str_repeat('s', 191), $contract->request(self::APP, ['operation' => 'read', 'subject' => str_repeat('s', 191)])['subject']);
        $this->assertSame(str_repeat('c', 512), $contract->request(self::APP, ['operation' => 'subjects', 'cursor' => str_repeat('c', 512), 'limit' => 50])['cursor']);
        foreach ([
            ['operation' => 'read', 'subject' => str_repeat('s', 192)],
            ['operation' => 'read', 'subject' => ''],
            ['operation' => 'subjects', 'cursor' => str_repeat('c', 513)],
            ['operation' => 'subjects', 'limit' => 51],
            ['operation' => 'subjects', 'limit' => '1'],
            ['operation' => 'capabilities', 'actor' => 'spoofed-subject'],
        ] as $input) {
            $this->refused(fn () => $contract->request(self::APP, $input), 422, (string) json_encode($input));
        }
        $this->assertSame(str_repeat('r', 128), $contract->request(self::APP, $this->update(['expected_revision' => str_repeat('r', 128)]))['expected_revision']);
        $this->refused(fn () => $contract->request(self::APP, $this->update(['expected_revision' => str_repeat('r', 129)])), 422, 'a revision longer than 128 bytes');
    }

    public function test_a_page_is_bounded_and_a_state_must_echo_its_subject_exactly(): void
    {
        $contract = new DelegatedContract;
        $base = ['contract_version' => 3, 'application' => self::APP, 'operation' => 'subjects', 'subjects' => [['subject' => str_repeat('s', 191), 'label' => 'Example']], 'next_cursor' => str_repeat('c', 512)];
        $this->assertSame($base, $contract->response($base, self::APP, 'subjects'));
        foreach ([['next_cursor' => str_repeat('c', 513)], ['subjects' => [['subject' => str_repeat('s', 192), 'label' => 'Example']]], ['subjects' => array_fill(0, 51, $base['subjects'][0])]] as $changes) {
            $this->refused(fn () => $contract->response([...$base, ...$changes], self::APP, 'subjects'), 503);
        }

        $state = [...$this->state(), 'subject' => 'Subject-Example'];
        $this->assertSame($state, $contract->response($state, self::APP, 'read', 'Subject-Example'));
        $this->refused(fn () => $contract->response($state, self::APP, 'read', 'subject-example'), 503, 'subjects are compared exactly');
        $this->refused(fn () => $contract->response($state, self::APP, 'read'), 503, 'no subject to echo');
    }

    public function test_an_update_names_roles_within_their_bounds(): void
    {
        $contract = new DelegatedContract;
        $access = ['application_admin' => false, 'workspaces' => array_map(
            static fn (int $id): array => ['id' => (string) $id, 'role' => str_repeat('r', 64)],
            range(1, 100),
        )];

        $this->assertSame($access, $contract->request(self::APP, $this->update(['access' => $access]), 3)['access']);

        foreach ([
            'a role id longer than 64 bytes' => [['id' => 'w1', 'role' => str_repeat('r', 65)]],
            'an empty role id' => [['id' => 'w1', 'role' => '']],
            'a permission instead of a role' => [['id' => 'w1', 'permission' => 'write']],
            'an edit flag, which is the application\'s to say' => [['id' => 'w1', 'role' => 'sender', 'editable' => true]],
            'the same workspace twice' => [['id' => 'w1', 'role' => 'sender'], ['id' => 'w1', 'role' => 'auditor']],
        ] as $label => $workspaces) {
            $this->refused(
                fn () => $contract->request(self::APP, $this->update(['access' => ['application_admin' => false, 'workspaces' => $workspaces]]), 3),
                422,
                $label,
            );
        }

        $this->refused(fn () => $contract->request(self::APP, $this->update(['access' => [...$access, 'workspaces' => [...$access['workspaces'], ['id' => '101', 'role' => 'sender']]]]), 3), 422);
    }

    public function test_provisioning_is_an_update_with_a_null_revision_and_an_optional_display_name(): void
    {
        $contract = new DelegatedContract;

        $provision = $this->update(['expected_revision' => null, 'display_name' => str_repeat('n', 255)]);
        $this->assertNull($contract->request(self::APP, $provision, 3)['expected_revision']);
        $this->assertNull($contract->request(self::APP, $this->update(['expected_revision' => null]), 3)['expected_revision']);

        $this->refused(fn () => $contract->request(self::APP, $this->update(['display_name' => 'Example Person']), 3), 422, 'a display name on an ordinary update');
        $this->refused(fn () => $contract->request(self::APP, $this->update(['expected_revision' => null, 'display_name' => str_repeat('n', 256)]), 3), 422);
        $this->refused(fn () => $contract->request(self::APP, $this->update(['expected_revision' => null, 'display_name' => '']), 3), 422);
        $this->refused(fn () => $contract->request(self::APP, $this->update(['expected_revision' => '']), 3), 422);

        $withoutRevision = $this->update();
        unset($withoutRevision['expected_revision']);
        $this->refused(fn () => $contract->request(self::APP, $withoutRevision, 3), 422, 'a missing revision is not a null one');
    }

    public function test_capabilities_advertise_roles_and_provisioning(): void
    {
        $contract = new DelegatedContract;

        $this->assertSame($this->capabilities(), $contract->response($this->capabilities(), self::APP, 'capabilities', null, 3));
        $this->assertSame(['owner', 'admin', 'sender', 'auditor'], $contract->advertisedRoleIds($this->capabilities()));

        $roles = $this->capabilities()['controls']['workspace_roles'];
        foreach ([
            'roles that are not a list' => ['workspace_roles' => ['owner' => ['id' => 'owner', 'label' => 'Owner']]],
            'no roles list' => ['workspace_roles' => null],
            'seventeen roles' => ['workspace_roles' => array_map(static fn (int $i): array => ['id' => 'r'.$i, 'label' => 'Role '.$i], range(1, 17))],
            'a duplicated role' => ['workspace_roles' => [$roles[0], $roles[0]]],
            'a role label longer than 255 bytes' => ['workspace_roles' => [['id' => 'owner', 'label' => str_repeat('l', 256)]]],
            'a missing provisioning flag' => ['provisioning' => null],
            'permissions alongside' => ['workspace_permissions' => ['read']],
        ] as $label => $change) {
            $controls = array_filter([...$this->capabilities()['controls'], ...$change], static fn (mixed $value): bool => $value !== null);
            $this->refused(fn () => $contract->response([...$this->capabilities(), 'controls' => $controls], self::APP, 'capabilities', null, 3), 503, $label);
        }
    }

    public function test_a_provisioned_state_carries_roles_and_edit_flags(): void
    {
        $contract = new DelegatedContract;
        $state = $this->state();

        $this->assertSame($state, $contract->response($state, self::APP, 'read', 'subject-example', 3));

        foreach ([
            'a membership without an edit flag' => ['access' => ['application_admin' => false, 'workspaces' => [['id' => 'w1', 'role' => 'sender']]]],
            'an edit flag that is not a boolean' => ['access' => ['application_admin' => false, 'workspaces' => [['id' => 'w1', 'role' => 'sender', 'editable' => 'yes']]]],
            'a permission instead of a role' => ['access' => ['application_admin' => false, 'workspaces' => [['id' => 'w1', 'permission' => 'write', 'editable' => true]]]],
            'an offer to provision an account that exists' => ['allowed_edits' => ['application_admin' => false, 'workspaces' => true, 'provision' => true, 'remove' => false]],
            'no revision' => ['revision' => null],
            'allowed edits without the provision flag' => ['allowed_edits' => ['application_admin' => false, 'workspaces' => true, 'remove' => false]],
        ] as $label => $change) {
            $this->refused(fn () => $contract->response([...$state, ...$change], self::APP, 'read', 'subject-example', 3), 503, $label);
        }
    }

    public function test_an_unprovisioned_state_may_offer_only_provisioning(): void
    {
        $contract = new DelegatedContract;
        $unprovisioned = [...$this->state(), 'provisioned' => false, 'revision' => null, 'access' => null,
            'allowed_edits' => ['application_admin' => false, 'workspaces' => false, 'provision' => true, 'remove' => false]];

        $this->assertSame($unprovisioned, $contract->response($unprovisioned, self::APP, 'read', 'subject-example', 3));
        $closed = [...$unprovisioned, 'allowed_edits' => [...$unprovisioned['allowed_edits'], 'provision' => false]];
        $this->assertSame($closed, $contract->response($closed, self::APP, 'read', 'subject-example', 3));

        foreach ([
            'workspace edits on an account that does not exist' => ['allowed_edits' => ['application_admin' => false, 'workspaces' => true, 'provision' => true, 'remove' => false]],
            'a revision for an account that does not exist' => ['revision' => 'rev-1'],
            'access for an account that does not exist' => ['access' => ['application_admin' => false, 'workspaces' => []]],
        ] as $label => $change) {
            $this->refused(fn () => $contract->response([...$unprovisioned, ...$change], self::APP, 'read', 'subject-example', 3), 503, $label);
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

    public function test_capabilities_without_roles_describe_an_account_only_application(): void
    {
        $contract = new DelegatedContract;
        $accountOnly = $this->accountOnlyCapabilities();

        $this->assertSame($accountOnly, $contract->response($accountOnly, self::APP, 'capabilities', null, 3));
        $this->assertTrue($contract->accountOnly($accountOnly));
        $this->assertSame([], $contract->advertisedRoleIds($accountOnly));
        $this->assertFalse($contract->accountOnly($this->capabilities()));
        $this->assertFalse($contract->accountOnly(['controls' => []]), 'a missing roles list is not an empty one');

    }

    public function test_an_account_only_application_takes_and_reports_no_memberships(): void
    {
        $contract = new DelegatedContract;
        $accountOnly = $this->accountOnlyCapabilities();
        $none = ['application_admin' => true, 'workspaces' => []];

        // Requests: an update and a provisioning update carry no memberships.
        $this->assertSame($none, $contract->request(self::APP, $this->update(['access' => $none]), 3)['access']);
        $this->assertSame($none, $contract->request(self::APP, $this->update(['expected_revision' => null, 'access' => $none]), 3)['access']);
        $this->assertTrue($contract->rolesAreAdvertised($accountOnly, $none));
        $this->assertFalse($contract->rolesAreAdvertised($accountOnly, $this->update()['access']), 'any membership names a role it does not advertise');
        $this->assertFalse($contract->rolesAreAdvertised(['controls' => []], $none), 'capabilities without a roles list pass nothing');
        $this->assertTrue($contract->rolesAreAdvertised($this->capabilities(), $none), 'unchanged for a workspace application');

        // Answers: no memberships and no workspace edits in a state, no workspaces in a page.
        $state = [...$this->state(), 'access' => $none, 'allowed_edits' => ['application_admin' => true, 'workspaces' => false, 'provision' => false, 'remove' => true]];
        $unprovisioned = [...$state, 'provisioned' => false, 'revision' => null, 'access' => null,
            'allowed_edits' => ['application_admin' => false, 'workspaces' => false, 'provision' => true, 'remove' => false]];
        $page = ['contract_version' => 3, 'application' => self::APP, 'operation' => 'workspaces', 'workspaces' => [], 'next_cursor' => null];
        foreach ([$state, [...$state, 'operation' => 'update'], $unprovisioned, $page, $accountOnly] as $answer) {
            $this->assertTrue($contract->fitsCapabilities($accountOnly, $answer), (string) $answer['operation']);
        }

        foreach ([
            'a reported membership' => [...$state, 'access' => [...$none, 'workspaces' => [['id' => 'w1', 'role' => 'owner', 'editable' => false]]]],
            'an offer of workspace edits' => [...$state, 'allowed_edits' => [...$state['allowed_edits'], 'workspaces' => true]],
            'a listed workspace' => [...$page, 'workspaces' => [['id' => 'w1', 'label' => 'Example Workspace']]],
            'another page of workspaces' => [...$page, 'next_cursor' => 'more'],
        ] as $label => $answer) {
            $this->assertFalse($contract->fitsCapabilities($accountOnly, $answer), $label);
            $this->assertTrue($contract->fitsCapabilities($this->capabilities(), $answer), $label.' is only shape-checked for a workspace application');
        }
    }

    public function test_a_page_must_carry_this_contract_version(): void
    {
        $contract = new DelegatedContract;
        $page = ['contract_version' => 3, 'application' => self::APP, 'operation' => 'workspaces', 'workspaces' => [['id' => 'w1', 'label' => 'Example Workspace']], 'next_cursor' => null];

        $this->assertSame($page, $contract->response($page, self::APP, 'workspaces', null, 3));
        $this->refused(fn () => $contract->response([...$page, 'contract_version' => 2], self::APP, 'workspaces', null, 3), 503);
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
            'operation_id' => str_repeat('o', 32),
            ...$changes,
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private function capabilities(): array
    {
        return [
            'contract_version' => 3,
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
    private function accountOnlyCapabilities(): array
    {
        $capabilities = $this->capabilities();
        $capabilities['controls']['workspace_roles'] = [];
        $capabilities['controls']['application_admin'] = true;

        return $capabilities;
    }

    /**
     * @return array<string, mixed>
     */
    private function state(): array
    {
        return [
            'contract_version' => 3,
            'application' => self::APP,
            'operation' => 'read',
            'subject' => 'subject-example',
            'provisioned' => true,
            'revision' => 'rev-1',
            'access' => ['application_admin' => false, 'workspaces' => [
                ['id' => 'w1', 'role' => 'owner', 'editable' => false],
                ['id' => 'w2', 'role' => 'sender', 'editable' => true],
            ]],
            // w1 is protected, so a removal would be refused.
            'allowed_edits' => ['application_admin' => false, 'workspaces' => true, 'provision' => false, 'remove' => false],
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
