<?php

namespace BWH\Auth\Tests;

use BWH\Auth\OAuth\DelegatedAccess\DelegatedAccessException;
use BWH\Auth\OAuth\DelegatedAccess\DelegatedContract;
use PHPUnit\Framework\TestCase;

class DelegatedContractTest extends TestCase
{
    public function test_request_limits_preserve_exact_subjects_and_opaque_cursors(): void
    {
        $contract = new DelegatedContract;
        $this->assertSame(str_repeat('s', 191), $contract->request('example-app', ['operation' => 'read', 'subject' => str_repeat('s', 191)])['subject']);
        $this->assertSame(str_repeat('c', 512), $contract->request('example-app', ['operation' => 'subjects', 'cursor' => str_repeat('c', 512), 'limit' => 50])['cursor']);
        foreach ([
            ['operation' => 'read', 'subject' => str_repeat('s', 192)],
            ['operation' => 'read', 'subject' => ''],
            ['operation' => 'subjects', 'cursor' => str_repeat('c', 513)],
            ['operation' => 'subjects', 'limit' => 51],
            ['operation' => 'subjects', 'limit' => '1'],
            ['operation' => 'capabilities', 'actor' => 'spoofed-subject'],
        ] as $input) {
            $this->refused(fn () => $contract->request('example-app', $input), 422);
        }
    }

    public function test_update_limits_revision_and_unique_workspace_access(): void
    {
        $contract = new DelegatedContract;
        $access = ['application_admin' => false, 'workspaces' => array_map(fn ($id) => ['id' => (string) $id, 'permission' => 'read'], range(1, 100))];
        $input = ['operation' => 'update', 'subject' => 'subject-example', 'expected_revision' => str_repeat('r', 128), 'access' => $access];
        $this->assertSame($access, $contract->request('example-app', $input)['access']);
        $this->refused(fn () => $contract->request('example-app', [...$input, 'expected_revision' => str_repeat('r', 129)]), 422);
        $this->refused(fn () => $contract->request('example-app', [...$input, 'access' => [...$access, 'workspaces' => [...$access['workspaces'], ['id' => '101', 'permission' => 'read']]]]), 422);
        foreach ([['id' => '1', 'permission' => 'read'], ['id' => 'other', 'permission' => 'admin']] as $bad) {
            $this->refused(fn () => $contract->request('example-app', [...$input, 'access' => [...$access, 'workspaces' => [$access['workspaces'][0], $bad]]]), 422);
        }
    }

    public function test_response_requires_exact_subject_echo_and_unprovisioned_no_edit_state(): void
    {
        $contract = new DelegatedContract;
        $response = ['contract_version' => 1, 'application' => 'example-app', 'operation' => 'read', 'subject' => 'Subject-Example', 'provisioned' => false, 'revision' => null, 'access' => null, 'allowed_edits' => ['application_admin' => false, 'workspaces' => false]];
        $this->assertSame($response, $contract->response($response, 'example-app', 'read', 'Subject-Example'));
        $this->refused(fn () => $contract->response($response, 'example-app', 'read', 'subject-example'), 503);
        $this->refused(fn () => $contract->response($response, 'example-app', 'read'), 503);
        $this->refused(fn () => $contract->response([...$response, 'allowed_edits' => ['application_admin' => true, 'workspaces' => false]], 'example-app', 'read', 'Subject-Example'), 503);
    }

    public function test_response_page_and_capability_boundaries(): void
    {
        $contract = new DelegatedContract;
        $base = ['contract_version' => 1, 'application' => 'example-app', 'operation' => 'subjects', 'subjects' => [['subject' => str_repeat('s', 191), 'label' => 'Example']], 'next_cursor' => str_repeat('c', 512)];
        $this->assertSame($base, $contract->response($base, 'example-app', 'subjects'));
        foreach ([['next_cursor' => str_repeat('c', 513)], ['subjects' => [['subject' => str_repeat('s', 192), 'label' => 'Example']]], ['subjects' => array_fill(0, 51, $base['subjects'][0])]] as $changes) {
            $this->refused(fn () => $contract->response([...$base, ...$changes], 'example-app', 'subjects'), 503);
        }
        foreach ([[], ['read'], ['read', 'write']] as $permissions) {
            $response = ['contract_version' => 1, 'application' => 'example-app', 'operation' => 'capabilities', 'controls' => ['application_admin' => true, 'workspace_permissions' => $permissions]];
            $this->assertSame($response, $contract->response($response, 'example-app', 'capabilities'));
        }
    }

    private function refused(callable $action, int $status): void
    {
        try {
            $action();
            $this->fail('Expected contract refusal.');
        } catch (DelegatedAccessException $exception) {
            $this->assertSame($status, $exception->status);
        }
    }
}
