<?php

namespace BWH\Auth\Tests\Fixtures;

use BWH\Auth\OAuth\DelegatedAccess\ApplicationAccessAdapter;
use BWH\Auth\OAuth\DelegatedAccess\DelegatedRefusal;

/**
 * An account-only adapter: accounts, an application administrator flag and provisioning, and no
 * workspaces. It follows the normative update semantics, with one switch per way to break them.
 *
 * Application administrators manage access. None may change their own flag, and the last
 * administrator may not be demoted.
 */
final class AccountOnlyAccessAdapter implements ApplicationAccessAdapter
{
    /** @var array<string, bool> subject => application administrator */
    public array $accounts = [];

    /** @var array<string, bool> */
    public array $broken = [
        'refuse_only_writes' => false,
        'accept_workspaces' => false,
        'allow_self_demotion' => false,
        'report_workspaces' => false,
        'ignore_revision' => false,
    ];

    public function handle(string $actorSubject, array $payload): array
    {
        if (($this->accounts[$actorSubject] ?? false) !== true && ($payload['operation'] === 'update' || ! $this->broken['refuse_only_writes'])) {
            throw DelegatedRefusal::of(DelegatedRefusal::NOT_AUTHORIZED);
        }

        return match ($payload['operation']) {
            'capabilities' => ['controls' => ['application_admin' => true, 'workspace_roles' => [], 'provisioning' => true]],
            'subjects' => ['subjects' => array_map(static fn (string $subject): array => ['subject' => $subject, 'label' => $subject], array_keys($this->accounts)), 'next_cursor' => null],
            'workspaces' => ['workspaces' => [], 'next_cursor' => null],
            'read' => $this->state($actorSubject, $payload['subject']),
            'update' => $this->update($actorSubject, $payload),
        };
    }

    public function revision(string $subject): string
    {
        return hash('sha256', json_encode([$subject, $this->accounts[$subject] ?? null]));
    }

    /**
     * @return array<string, mixed>
     */
    private function state(string $actor, string $subject): array
    {
        if (! isset($this->accounts[$subject])) {
            return ['subject' => $subject, 'provisioned' => false, 'revision' => null, 'access' => null,
                'allowed_edits' => ['application_admin' => false, 'workspaces' => false, 'provision' => true]];
        }

        return [
            'subject' => $subject,
            'provisioned' => true,
            'revision' => $this->revision($subject),
            'access' => ['application_admin' => $this->accounts[$subject],
                'workspaces' => $this->broken['report_workspaces'] ? [['id' => 'w1', 'role' => 'member', 'editable' => false]] : []],
            'allowed_edits' => ['application_admin' => $this->adminEditable($actor, $subject), 'workspaces' => false, 'provision' => false],
        ];
    }

    private function adminEditable(string $actor, string $subject): bool
    {
        $lastAdmin = ($this->accounts[$subject] ?? false) && count(array_filter($this->accounts)) === 1;

        return $actor !== $subject && ! $lastAdmin;
    }

    /**
     * @return array<string, mixed>
     */
    private function update(string $actor, array $payload): array
    {
        $subject = $payload['subject'];
        if ($payload['access']['workspaces'] !== [] && ! $this->broken['accept_workspaces']) {
            throw DelegatedRefusal::of(DelegatedRefusal::INVALID_REQUEST);
        }

        if ($payload['expected_revision'] === null) {
            if (isset($this->accounts[$subject])) {
                throw DelegatedRefusal::of(DelegatedRefusal::REVISION_CONFLICT);
            }
            $this->accounts[$subject] = $payload['access']['application_admin'];

            return $this->state($actor, $subject);
        }

        $current = $this->accounts[$subject] ?? throw DelegatedRefusal::of(DelegatedRefusal::NOT_AUTHORIZED);
        if ($payload['access']['application_admin'] !== $current && ! $this->adminEditable($actor, $subject) && ! $this->broken['allow_self_demotion']) {
            throw DelegatedRefusal::of(DelegatedRefusal::NOT_AUTHORIZED);
        }
        if ($payload['expected_revision'] !== $this->revision($subject) && ! $this->broken['ignore_revision']) {
            throw DelegatedRefusal::of(DelegatedRefusal::REVISION_CONFLICT);
        }

        $this->accounts[$subject] = $payload['access']['application_admin'];

        return $this->state($actor, $subject);
    }
}
