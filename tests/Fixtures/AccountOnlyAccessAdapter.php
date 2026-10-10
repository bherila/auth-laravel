<?php

namespace BWH\Auth\Tests\Fixtures;

use BWH\Auth\OAuth\DelegatedAccess\ApplicationAccessAdapter;
use BWH\Auth\OAuth\DelegatedAccess\DelegatedCursor;
use BWH\Auth\OAuth\DelegatedAccess\DelegatedRefusal;

/**
 * An account-only adapter: accounts, an application administrator flag and provisioning, and no
 * workspaces. It follows the normative semantics, with one switch per way to break them.
 *
 * Application administrators manage access. None may change their own flag, and the last
 * administrator may not be demoted. Service accounts (`service-…`) exist but are never shown.
 */
final class AccountOnlyAccessAdapter implements ApplicationAccessAdapter
{
    /** @var array<string, bool> subject => application administrator */
    public array $accounts = [];

    /** @var array<string, array<string, string|null>> subject => metadata field => timestamp */
    public array $metadata = [];

    /** @var array<string, bool> */
    public array $broken = [
        'refuse_only_writes' => false,
        'accept_workspaces' => false,
        'allow_self_demotion' => false,
        'report_workspaces' => false,
        'ignore_revision' => false,
        'search_service_accounts' => false,
        'allow_self_removal' => false,
        'offer_a_removal_it_refuses' => false,
        'remove_the_account' => false,
    ];

    public function handle(string $actorSubject, array $payload): array
    {
        if (($this->accounts[$actorSubject] ?? false) !== true && (in_array($payload['operation'], ['update', 'remove'], true) || ! $this->broken['refuse_only_writes'])) {
            throw DelegatedRefusal::of(DelegatedRefusal::NOT_AUTHORIZED);
        }

        return match ($payload['operation']) {
            'capabilities' => ['controls' => ['application_admin' => true, 'workspace_roles' => [], 'provisioning' => true]],
            'subjects' => $this->subjects($actorSubject, $payload),
            'workspaces' => ['workspaces' => [], 'next_cursor' => null],
            'read' => $this->state($actorSubject, $payload['subject']),
            'update' => $this->update($actorSubject, $payload),
            'remove' => $this->remove($actorSubject, $payload),
            default => throw DelegatedRefusal::of(DelegatedRefusal::INVALID_REQUEST),
        };
    }

    public function revision(string $subject): string
    {
        return hash('sha256', json_encode([$subject, $this->accounts[$subject] ?? null]));
    }

    /**
     * @param  array<string, mixed>  $payload
     * @return array<string, mixed>
     */
    private function subjects(string $actor, array $payload): array
    {
        $cursors = app(DelegatedCursor::class);
        $after = $cursors->after($actor, 'subjects', $payload);
        $query = $payload['query'] ?? null;
        $entries = [];
        foreach (array_keys($this->accounts) as $key => $subject) {
            $hidden = str_starts_with($subject, 'service-') && ! ($this->broken['search_service_accounts'] && $query !== null);
            if ($key + 1 > $after && ! $hidden && ($query === null || mb_stripos($subject, $query) !== false)) {
                $entries[$key + 1] = ['subject' => $subject, 'label' => $subject];
            }
        }
        $page = array_slice($entries, 0, (int) ($payload['limit'] ?? 50), true);

        return [
            'subjects' => array_values($page),
            'next_cursor' => count($entries) > count($page) ? $cursors->encode($actor, 'subjects', (int) array_key_last($page), $query) : null,
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private function state(string $actor, string $subject): array
    {
        if (! isset($this->accounts[$subject])) {
            return ['subject' => $subject, 'provisioned' => false, 'revision' => null, 'access' => null,
                'allowed_edits' => ['application_admin' => false, 'workspaces' => false, 'provision' => true, 'remove' => false]];
        }

        return [
            'subject' => $subject,
            'provisioned' => true,
            'revision' => $this->revision($subject),
            'access' => ['application_admin' => $this->accounts[$subject],
                'workspaces' => $this->broken['report_workspaces'] ? [['id' => 'w1', 'role' => 'member', 'editable' => false]] : []],
            'allowed_edits' => [
                // Broken, it offers both, so the contract cannot see that the removal will be refused.
                'application_admin' => $this->adminEditable($actor, $subject) || $this->broken['offer_a_removal_it_refuses'],
                'workspaces' => false, 'provision' => false,
                // Refused for the actor themselves and for the last administrator.
                'remove' => ! $this->accounts[$subject] || $this->adminEditable($actor, $subject) || $this->broken['offer_a_removal_it_refuses'],
            ],
        ] + ($this->metadata[$subject] ?? []);
    }

    private function adminEditable(string $actor, string $subject): bool
    {
        return $actor !== $subject && ! $this->lastAdministrator($subject);
    }

    private function lastAdministrator(string $subject): bool
    {
        return ($this->accounts[$subject] ?? false) && count(array_filter($this->accounts)) === 1;
    }

    /**
     * @param  array<string, mixed>  $payload
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

    /**
     * Removal clears the administrator flag and keeps the account; there is nothing else to remove.
     *
     * @param  array<string, mixed>  $payload
     * @return array<string, mixed>
     */
    private function remove(string $actor, array $payload): array
    {
        $subject = $payload['subject'];
        $current = $this->accounts[$subject] ?? throw DelegatedRefusal::of(DelegatedRefusal::NOT_PROVISIONED);
        if ($payload['expected_revision'] !== $this->revision($subject) && ! $this->broken['ignore_revision']) {
            throw DelegatedRefusal::of(DelegatedRefusal::REVISION_CONFLICT);
        }
        if ($current && $this->lastAdministrator($subject)) {
            throw DelegatedRefusal::of(DelegatedRefusal::INVALID_REQUEST);
        }
        if ($current && $actor === $subject && ! $this->broken['allow_self_removal']) {
            throw DelegatedRefusal::of(DelegatedRefusal::NOT_AUTHORIZED);
        }

        $this->accounts[$subject] = false;
        $state = $this->state($actor, $subject);
        if ($this->broken['remove_the_account']) {
            unset($this->accounts[$subject]);
        }

        return $state;
    }
}
