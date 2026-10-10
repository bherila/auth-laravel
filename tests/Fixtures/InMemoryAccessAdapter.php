<?php

namespace BWH\Auth\Tests\Fixtures;

use BWH\Auth\OAuth\DelegatedAccess\ApplicationAccessAdapter;
use BWH\Auth\OAuth\DelegatedAccess\DelegatedAccessException;
use BWH\Auth\OAuth\DelegatedAccess\DelegatedCursor;
use BWH\Auth\OAuth\DelegatedAccess\DelegatedRefusal;

/**
 * A small adapter that follows the normative semantics, with one switch per way to break them.
 *
 * Managers manage workspaces; an owner membership is visible to its workspace's managers but only
 * its owner can change it; nobody is an application administrator through delegation. A manager
 * sees the subjects with a membership in a workspace it manages, and searches them by label and
 * email.
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

    /** @var array<string, string> subject => label, the subject itself otherwise */
    public array $labels = [];

    /** @var array<string, string> subject => email */
    public array $emails = [];

    /** @var array<string, array<string, string|null>> subject => metadata field => timestamp */
    public array $metadata = [];

    /** @var array<string, int> subject => removals that changed nothing; only counted when broken */
    private array $generations = [];

    /**
     * Workspaces that must keep at least one member, checked before the revision as an application
     * may check its own rules first. Following the semantics, not breaking them.
     *
     * @var list<string>
     */
    public array $keepsAMember = [];

    /** Whether managers may make a target an application administrator. */
    public bool $adminEditable = false;

    /** @var array<string, bool> */
    public array $broken = [
        'refuse_only_writes' => false,
        'replace_wholesale' => false,
        'trust_editable' => false,
        'grant_application_admin' => false,
        'ignore_revision' => false,
        'accept_any_role' => false,
        'refuse_removal_with_a_server_error' => false,
        'answer_an_extra_field' => false,
        'search_beyond_scope' => false,
        'cursor_counts_beyond_scope' => false,
        'ignore_query' => false,
        'remove_unseen_memberships' => false,
        'remove_partially' => false,
        'remove_the_account' => false,
        'keep_application_admin_on_removal' => false,
        'bump_revision_on_an_empty_removal' => false,
        'metadata_from_the_future' => false,
        'listing_metadata_from_the_future' => false,
    ];

    public function handle(string $actorSubject, array $payload): array
    {
        $managed = $this->managers[$actorSubject] ?? [];
        if ($managed === [] && (in_array($payload['operation'], ['update', 'remove'], true) || ! $this->broken['refuse_only_writes'])) {
            throw DelegatedRefusal::of(DelegatedRefusal::NOT_AUTHORIZED);
        }

        return match ($payload['operation']) {
            'capabilities' => ['controls' => [
                'application_admin' => $this->adminEditable,
                'workspace_roles' => array_map(static fn (string $role): array => ['id' => $role, 'label' => ucfirst($role), 'description' => 'May act as '.$role.'.'], self::ROLES),
                'provisioning' => false,
            ]],
            'subjects' => $this->subjects($actorSubject, $managed, $payload),
            'workspaces' => $this->workspaces($actorSubject, $managed, $payload),
            'read' => $this->state($managed, $payload['subject']),
            'update' => $this->update($managed, $payload),
            'remove' => $this->remove($managed, $payload),
            default => throw DelegatedRefusal::of(DelegatedRefusal::INVALID_REQUEST),
        };
    }

    public function revision(string $subject): string
    {
        $memberships = $this->memberships[$subject] ?? [];
        ksort($memberships);

        return hash('sha256', json_encode([$memberships, $this->admins[$subject] ?? false, $this->generations[$subject] ?? 0]));
    }

    /**
     * @param  list<string>  $managed
     * @param  array<string, mixed>  $payload
     * @return array<string, mixed>
     */
    private function subjects(string $actor, array $managed, array $payload): array
    {
        $entries = [];
        foreach (array_keys($this->memberships) as $key => $subject) {
            $visible = array_intersect(array_keys($this->memberships[$subject]), $managed) !== [];
            $label = $this->labels[$subject] ?? $subject;
            $metadata = $this->metadata[$subject] ?? [];
            if ($this->broken['listing_metadata_from_the_future']) {
                $metadata['last_seen_at'] = gmdate('Y-m-d\TH:i:s\Z', time() + 86400);
            }
            $entries[$key + 1] = ['subject' => $subject, 'label' => $label, ...$metadata, 'visible' => $visible, 'matches' => [$label, $this->emails[$subject] ?? '']];
        }

        return $this->page($actor, 'subjects', $entries, $payload);
    }

    /**
     * @param  list<string>  $managed
     * @param  array<string, mixed>  $payload
     * @return array<string, mixed>
     */
    private function workspaces(string $actor, array $managed, array $payload): array
    {
        $all = $managed;
        foreach ($this->memberships as $workspaces) {
            $all = [...$all, ...array_map('strval', array_keys($workspaces))];
        }
        $all = array_values(array_unique($all));
        sort($all);
        $entries = [];
        foreach ($all as $key => $id) {
            $entries[$key + 1] = ['id' => $id, 'label' => 'Workspace '.$id, 'visible' => in_array($id, $managed, true), 'matches' => ['Workspace '.$id]];
        }

        return $this->page($actor, 'workspaces', $entries, $payload);
    }

    /**
     * A keyset page of the entries the actor may see that match the query.
     *
     * @param  array<int, array<string, mixed>>  $entries  key => entry with `visible` and `matches`
     * @param  array<string, mixed>  $payload
     * @return array<string, mixed>
     */
    private function page(string $actor, string $operation, array $entries, array $payload): array
    {
        $cursors = app(DelegatedCursor::class);
        $query = is_string($payload['query'] ?? null) && ! $this->broken['ignore_query'] ? $payload['query'] : null;
        $after = $cursors->after($actor, $operation, $payload);
        $limit = (int) ($payload['limit'] ?? 50);

        $matching = array_filter($entries, static fn (array $entry, int $key): bool => $key > $after
            && ($query === null || array_filter($entry['matches'], static fn (string $text): bool => mb_stripos($text, $query) !== false) !== []), ARRAY_FILTER_USE_BOTH);
        $inScope = $this->broken['search_beyond_scope'] && $query !== null ? $matching : array_filter($matching, static fn (array $entry): bool => $entry['visible']);
        $page = array_slice($inScope, 0, $limit, true);
        $more = count($this->broken['cursor_counts_beyond_scope'] ? $matching : $inScope) > count($page);
        $last = array_key_last($page) ?? $after;

        return [
            $operation => array_values(array_map(static fn (array $entry): array => array_diff_key($entry, ['visible' => true, 'matches' => true]), $page)),
            'next_cursor' => $more ? $cursors->encode($actor, $operation, $last, $payload['query'] ?? null) : null,
        ];
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
        $metadata = $this->metadata[$subject] ?? [];
        if ($this->broken['metadata_from_the_future']) {
            $metadata['last_seen_at'] = gmdate('Y-m-d\TH:i:s\Z', time() + 86400);
        }

        return ($this->broken['answer_an_extra_field'] ? ['internal_id' => 42] : []) + [
            'subject' => $subject,
            'provisioned' => true,
            'revision' => $this->revision($subject),
            'access' => ['application_admin' => $this->admins[$subject] ?? false, 'workspaces' => $visible],
            'allowed_edits' => ['application_admin' => $this->adminEditable, 'workspaces' => true, 'provision' => false],
        ] + $metadata;
    }

    /**
     * @param  list<string>  $managed
     * @param  array<string, mixed>  $payload
     * @return array<string, mixed>
     */
    private function update(array $managed, array $payload): array
    {
        $subject = $payload['subject'];
        $current = $this->memberships[$subject] ?? throw DelegatedRefusal::of(DelegatedRefusal::INVALID_REQUEST);

        if ($payload['access']['application_admin'] !== ($this->admins[$subject] ?? false) && ! $this->adminEditable && ! $this->broken['grant_application_admin']) {
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

        if ($this->broken['refuse_removal_with_a_server_error'] && count($requested) < count(array_intersect_key($current, array_flip($managed)))) {
            throw new DelegatedAccessException('unavailable', 503);
        }

        $unseen = $this->broken['replace_wholesale'] ? [] : array_diff_key($current, array_flip($managed));
        $this->memberships[$subject] = $unseen + $requested;
        $this->admins[$subject] = $payload['access']['application_admin'];

        return $this->state($managed, $subject);
    }

    /**
     * Remove every membership the actor manages and the administrator flag, or nothing at all.
     *
     * @param  list<string>  $managed
     * @param  array<string, mixed>  $payload
     * @return array<string, mixed>
     */
    private function remove(array $managed, array $payload): array
    {
        $subject = $payload['subject'];
        $current = $this->memberships[$subject] ?? throw DelegatedRefusal::of(DelegatedRefusal::NOT_PROVISIONED);
        if ($payload['expected_revision'] !== $this->revision($subject) && ! $this->broken['ignore_revision']) {
            throw DelegatedRefusal::of(DelegatedRefusal::REVISION_CONFLICT);
        }

        $mine = array_intersect_key($current, array_flip($managed));
        $admin = $this->admins[$subject] ?? false;
        if ($this->broken['remove_partially']) {
            // Takes what it may before discovering what it may not, and does not undo it.
            $this->memberships[$subject] = array_filter($current, static fn (string $role, string $workspace): bool => $role === 'owner' || ! in_array($workspace, $managed, true), ARRAY_FILTER_USE_BOTH);
        }
        if (in_array('owner', $mine, true)) {
            throw DelegatedRefusal::of(DelegatedRefusal::PROTECTED_MEMBERSHIP);
        }
        if ($admin && ! $this->adminEditable) {
            throw DelegatedRefusal::of(DelegatedRefusal::NOT_AUTHORIZED);
        }

        if ($mine === [] && ! $admin) {
            if ($this->broken['bump_revision_on_an_empty_removal']) {
                $this->generations[$subject] = ($this->generations[$subject] ?? 0) + 1;
            }

            return $this->state($managed, $subject);
        }

        $answer = null;
        $this->memberships[$subject] = $this->broken['remove_unseen_memberships'] ? [] : array_diff_key($current, $mine);
        $this->admins[$subject] = $this->broken['keep_application_admin_on_removal'] && $admin;
        if ($this->broken['remove_the_account']) {
            $answer = ['subject' => $subject, 'provisioned' => true, 'revision' => 'gone', 'access' => ['application_admin' => false, 'workspaces' => []],
                'allowed_edits' => ['application_admin' => false, 'workspaces' => true, 'provision' => false]];
            unset($this->memberships[$subject], $this->admins[$subject]);
        }
        $state = $answer ?? $this->state($managed, $subject);

        // The answer reports the projection the contract requires, whatever was actually kept.
        return ['access' => ['application_admin' => false, 'workspaces' => []]] + $state;
    }
}
