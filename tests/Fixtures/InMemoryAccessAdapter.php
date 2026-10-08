<?php

namespace BWH\Auth\Tests\Fixtures;

use BWH\Auth\OAuth\DelegatedAccess\ApplicationAccessAdapter;
use BWH\Auth\OAuth\DelegatedAccess\DelegatedRefusal;

/**
 * A small adapter that follows the normative update semantics, with one switch per way to break them.
 *
 * Managers manage workspaces; an owner membership is visible to its workspace's managers but only
 * its owner can change it; nobody is an application administrator through delegation.
 */
final class InMemoryAccessAdapter implements ApplicationAccessAdapter
{
    public const ROLES = ['owner', 'member'];

    /** @var array<string, list<string>> actor => workspaces it manages */
    public array $managers = ['manager' => ['w1', 'w2']];

    /** @var array<string, array<string, string>> subject => workspace => role */
    public array $memberships = [];

    /** @var array<string, bool> */
    public array $admins = [];

    /**
     * Workspaces that must keep at least one member, checked before the revision as an application
     * may check its own rules first. Following the semantics, not breaking them.
     *
     * @var list<string>
     */
    public array $keepsAMember = [];

    /** @var array<string, bool> */
    public array $broken = [
        'refuse_only_writes' => false,
        'replace_wholesale' => false,
        'trust_editable' => false,
        'grant_application_admin' => false,
        'ignore_revision' => false,
        'accept_any_role' => false,
    ];

    public function handle(string $actorSubject, array $payload): array
    {
        $managed = $this->managers[$actorSubject] ?? [];
        if ($managed === [] && ($payload['operation'] === 'update' || ! $this->broken['refuse_only_writes'])) {
            throw DelegatedRefusal::of(DelegatedRefusal::NOT_AUTHORIZED);
        }

        return match ($payload['operation']) {
            'capabilities' => ['controls' => [
                'application_admin' => false,
                'workspace_roles' => array_map(static fn (string $role): array => ['id' => $role, 'label' => ucfirst($role)], self::ROLES),
                'provisioning' => false,
            ]],
            'subjects' => ['subjects' => [], 'next_cursor' => null],
            'workspaces' => ['workspaces' => array_map(static fn (string $id): array => ['id' => $id, 'label' => $id], $managed), 'next_cursor' => null],
            'read' => $this->state($managed, $payload['subject']),
            'update' => $this->update($managed, $payload),
        };
    }

    public function revision(string $subject): string
    {
        $memberships = $this->memberships[$subject] ?? [];
        ksort($memberships);

        return hash('sha256', json_encode([$memberships, $this->admins[$subject] ?? false]));
    }

    /**
     * @param  list<string>  $managed
     * @return array<string, mixed>
     */
    private function state(array $managed, string $subject): array
    {
        if (! isset($this->memberships[$subject])) {
            throw DelegatedRefusal::of(DelegatedRefusal::NOT_PROVISIONED);
        }

        $visible = [];
        foreach ($this->memberships[$subject] as $workspace => $role) {
            if (in_array($workspace, $managed, true)) {
                $visible[] = ['id' => $workspace, 'role' => $role, 'editable' => $role !== 'owner'];
            }
        }

        return [
            'subject' => $subject,
            'provisioned' => true,
            'revision' => $this->revision($subject),
            'access' => ['application_admin' => $this->admins[$subject] ?? false, 'workspaces' => $visible],
            'allowed_edits' => ['application_admin' => false, 'workspaces' => true, 'provision' => false],
        ];
    }

    /**
     * @param  list<string>  $managed
     * @return array<string, mixed>
     */
    private function update(array $managed, array $payload): array
    {
        $subject = $payload['subject'];
        $current = $this->memberships[$subject] ?? throw DelegatedRefusal::of(DelegatedRefusal::INVALID_REQUEST);

        if ($payload['access']['application_admin'] !== ($this->admins[$subject] ?? false) && ! $this->broken['grant_application_admin']) {
            throw DelegatedRefusal::of(DelegatedRefusal::NOT_AUTHORIZED);
        }
        $kept = array_column($payload['access']['workspaces'], 'role', 'id');
        foreach ($this->keepsAMember as $workspace) {
            if (($current[$workspace] ?? null) === 'member' && ($kept[$workspace] ?? null) !== 'member') {
                throw DelegatedRefusal::of(DelegatedRefusal::INVALID_REQUEST);
            }
        }
        if ($payload['expected_revision'] !== $this->revision($subject) && ! $this->broken['ignore_revision']) {
            throw DelegatedRefusal::of(DelegatedRefusal::REVISION_CONFLICT);
        }

        $requested = [];
        foreach ($payload['access']['workspaces'] as $membership) {
            if (! in_array($membership['id'], $managed, true)) {
                throw DelegatedRefusal::of(DelegatedRefusal::NOT_AUTHORIZED);
            }
            $unchanged = ($current[$membership['id']] ?? null) === $membership['role'];
            if (! $unchanged && ! $this->broken['accept_any_role'] && ! in_array($membership['role'], ['member'], true)) {
                throw DelegatedRefusal::of(DelegatedRefusal::ROLE_NOT_GRANTABLE);
            }
            $requested[$membership['id']] = $membership['role'];
        }

        if (! $this->broken['trust_editable']) {
            foreach ($current as $workspace => $role) {
                if ($role === 'owner' && in_array($workspace, $managed, true) && ($requested[$workspace] ?? null) !== 'owner') {
                    throw DelegatedRefusal::of(DelegatedRefusal::PROTECTED_MEMBERSHIP);
                }
            }
        }

        $unseen = $this->broken['replace_wholesale'] ? [] : array_diff_key($current, array_flip($managed));
        $this->memberships[$subject] = $unseen + $requested;
        $this->admins[$subject] = $payload['access']['application_admin'];

        return $this->state($managed, $subject);
    }
}
