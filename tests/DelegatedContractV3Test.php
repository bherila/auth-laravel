<?php

namespace BWH\Auth\Tests;

use BWH\Auth\OAuth\DelegatedAccess\DelegatedAccessException;
use BWH\Auth\OAuth\DelegatedAccess\DelegatedContract;
use BWH\Auth\OAuth\DelegatedAccess\DelegatedCursor;
use Illuminate\Encryption\Encrypter;
use PHPUnit\Framework\TestCase;

/**
 * Contract version 3: search on the listings, `remove`, `receipt`, an `operation_id` on every write,
 * and read-only metadata. Versions 1 and 2 keep their own tests and are unchanged.
 */
class DelegatedContractV3Test extends TestCase
{
    private const APP = 'example-app';

    private const OPERATION = 'op_0123456789abcdefghijklmnopqrstuv';

    public function test_version_three_is_spoken_and_its_operations_exist_only_in_it(): void
    {
        $contract = new DelegatedContract;

        $this->assertSame(3, $contract->request(self::APP, ['operation' => 'capabilities'], 3)['contract_version']);

        foreach ([1, 2] as $version) {
            $this->refused(fn () => $contract->request(self::APP, $this->remove(), $version), 422, "remove in version {$version}");
            $this->refused(fn () => $contract->request(self::APP, ['operation' => 'receipt', 'operation_id' => self::OPERATION], $version), 422, "receipt in version {$version}");
            $this->refused(fn () => $contract->request(self::APP, ['operation' => 'subjects', 'query' => 'ex'], $version), 422, "search in version {$version}");
        }
        $this->refused(fn () => $contract->request(self::APP, ['operation' => 'capabilities'], 4), 500);
        $this->refused(fn () => $contract->response($this->state(), self::APP, 'read', 'subject-example', 2), 503, 'a version 3 answer is not a version 2 one');
    }

    public function test_a_search_query_is_two_to_one_hundred_characters_of_text(): void
    {
        $contract = new DelegatedContract;

        foreach (['subjects', 'workspaces'] as $operation) {
            foreach (['ex', str_repeat('é', 100), 'Example Person', 'person@example.test', '  x'] as $query) {
                $this->assertSame($query, $contract->request(self::APP, ['operation' => $operation, 'query' => $query, 'limit' => 10], 3)['query']);
            }

            foreach ([
                'one character' => 'e',
                'one multi-byte character' => 'é',
                'an empty query' => '',
                'more than 100 characters' => str_repeat('é', 101),
                'a control character' => "ex\nample",
                'invalid UTF-8' => "ex\xC3",
                'a number' => 42,
                'null, which is not an absent query' => null,
                'a list' => ['ex'],
            ] as $label => $query) {
                $this->refused(fn () => $contract->request(self::APP, ['operation' => $operation, 'query' => $query], 3), 422, "{$operation}: {$label}");
            }
        }

        $this->refused(fn () => $contract->request(self::APP, ['operation' => 'read', 'subject' => 'subject-example', 'query' => 'ex'], 3), 422, 'a query on a read');
    }

    public function test_every_write_and_receipt_carries_an_operation_id(): void
    {
        $contract = new DelegatedContract;

        foreach ([$this->update(), $this->remove(), ['operation' => 'receipt', 'operation_id' => self::OPERATION]] as $input) {
            $this->assertSame(self::OPERATION, $contract->request(self::APP, $input, 3)['operation_id']);
            foreach ([str_repeat('a', 32), str_repeat('Z', 64), DelegatedContract::operationId()] as $id) {
                $this->assertSame($id, $contract->request(self::APP, [...$input, 'operation_id' => $id], 3)['operation_id']);
            }

            $without = $input;
            unset($without['operation_id']);
            $this->refused(fn () => $contract->request(self::APP, $without, 3), 422, $input['operation'].' without an operation id');
            foreach ([str_repeat('a', 31), str_repeat('a', 65), str_repeat('a', 31).'.', str_repeat('a', 32)."\n", null, 12345678901234567890123456789012] as $bad) {
                $this->refused(fn () => $contract->request(self::APP, [...$input, 'operation_id' => $bad], 3), 422, $input['operation'].' with operation id '.var_export($bad, true));
            }
        }

        $this->refused(fn () => $contract->request(self::APP, ['operation' => 'read', 'subject' => 'subject-example', 'operation_id' => self::OPERATION], 3), 422, 'an operation id on a read');
        $this->assertNotSame(DelegatedContract::operationId(), DelegatedContract::operationId());
        $this->assertTrue(DelegatedContract::validOperationId(DelegatedContract::operationId()));
    }

    public function test_an_update_keeps_the_version_two_rules(): void
    {
        $contract = new DelegatedContract;

        $this->assertNull($contract->request(self::APP, $this->update(['expected_revision' => null, 'display_name' => 'Example Person']), 3)['expected_revision']);
        $this->refused(fn () => $contract->request(self::APP, $this->update(['display_name' => 'Example Person']), 3), 422, 'a display name on an ordinary update');
        $this->refused(fn () => $contract->request(self::APP, $this->update(['access' => ['application_admin' => false, 'workspaces' => [['id' => 'w1', 'permission' => 'write']]]]), 3), 422, 'a version 1 permission');
    }

    public function test_a_removal_names_a_subject_and_a_revision_and_nothing_else(): void
    {
        $contract = new DelegatedContract;

        $this->assertSame($this->remove(), array_diff_key($contract->request(self::APP, $this->remove(), 3), ['contract_version' => true, 'application' => true]));

        foreach ([
            'a null revision: there is nothing to provision' => ['expected_revision' => null],
            'an empty revision' => ['expected_revision' => ''],
            'a revision longer than 128 bytes' => ['expected_revision' => str_repeat('r', 129)],
            'a subject longer than 191 bytes' => ['subject' => str_repeat('s', 192)],
            'an access value' => ['access' => ['application_admin' => false, 'workspaces' => []]],
            'a display name' => ['display_name' => 'Example Person'],
        ] as $label => $change) {
            $this->refused(fn () => $contract->request(self::APP, [...$this->remove(), ...$change], 3), 422, $label);
        }

        $withoutRevision = $this->remove();
        unset($withoutRevision['expected_revision']);
        $this->refused(fn () => $contract->request(self::APP, $withoutRevision, 3), 422, 'no revision');
    }

    public function test_a_state_may_carry_metadata_timestamps(): void
    {
        $contract = new DelegatedContract;

        foreach ([
            [],
            ['provisioned_at' => '2026-10-10T12:00:00Z'],
            ['provisioned_at' => '2026-10-10T12:00:00.123456+02:00', 'first_sign_in_at' => null, 'last_seen_at' => '2026-10-10T23:59:59-07:00'],
            ['provisioned_at' => null, 'first_sign_in_at' => null, 'last_seen_at' => null],
        ] as $metadata) {
            $state = [...$this->state(), ...$metadata];
            $this->assertSame($state, $contract->response($state, self::APP, 'read', 'subject-example', 3));
        }

        foreach ([
            'a date without a time' => '2026-10-10',
            'a time without an offset' => '2026-10-10T12:00:00',
            'a month that does not exist' => '2026-13-10T12:00:00Z',
            'February 30th' => '2026-02-30T12:00:00Z',
            'hour 24' => '2026-10-10T24:00:00Z',
            'an offset of 24 hours' => '2026-10-10T12:00:00+24:00',
            'a Unix timestamp' => 1760097600,
            'an empty string' => '',
            'a date in words' => 'yesterday',
        ] as $label => $value) {
            $this->refused(fn () => $contract->response([...$this->state(), 'last_seen_at' => $value], self::APP, 'read', 'subject-example', 3), 503, $label);
        }

        $unprovisioned = $this->unprovisioned();
        $this->assertSame($unprovisioned, $contract->response([...$unprovisioned], self::APP, 'read', 'subject-example', 3));
        $this->assertSame([...$unprovisioned, 'provisioned_at' => null], $contract->response([...$unprovisioned, 'provisioned_at' => null], self::APP, 'read', 'subject-example', 3));
        $this->refused(fn () => $contract->response([...$unprovisioned, 'provisioned_at' => '2026-10-10T12:00:00Z'], self::APP, 'read', 'subject-example', 3), 503, 'metadata for an account that does not exist');
    }

    public function test_a_state_says_whether_a_removal_would_succeed(): void
    {
        $contract = new DelegatedContract;
        $edits = ['application_admin' => true, 'workspaces' => true, 'provision' => false, 'remove' => true];
        $removable = [...$this->state(), 'access' => ['application_admin' => true, 'workspaces' => [['id' => 'w2', 'role' => 'sender', 'editable' => true]]], 'allowed_edits' => $edits];

        $this->assertSame($removable, $contract->response($removable, self::APP, 'read', 'subject-example', 3));
        $this->assertSame(false, $contract->response($this->state(), self::APP, 'read', 'subject-example', 3)['allowed_edits']['remove']);
        $closed = [...$removable, 'allowed_edits' => [...$edits, 'remove' => false]];
        $this->assertSame($closed, $contract->response($closed, self::APP, 'read', 'subject-example', 3), 'refusing for its own reasons, such as permission');

        $withoutFlag = $edits;
        unset($withoutFlag['remove']);
        foreach ([
            'no remove flag' => ['allowed_edits' => $withoutFlag],
            'a remove flag that is not a boolean' => ['allowed_edits' => [...$edits, 'remove' => 'yes']],
            'removal offered over a protected membership' => ['access' => ['application_admin' => false, 'workspaces' => [['id' => 'w1', 'role' => 'owner', 'editable' => false]]]],
            'removal offered over an administrator flag the actor may not change' => ['allowed_edits' => [...$edits, 'application_admin' => false]],
        ] as $label => $change) {
            $this->refused(fn () => $contract->response([...$removable, ...$change], self::APP, 'read', 'subject-example', 3), 503, $label);
        }

        $unprovisioned = $this->unprovisioned();
        $this->refused(fn () => $contract->response([...$unprovisioned, 'allowed_edits' => [...$unprovisioned['allowed_edits'], 'remove' => true]], self::APP, 'read', 'subject-example', 3), 503, 'removal offered for an account that does not exist');
        $this->refused(fn () => $contract->response([...$removable, 'contract_version' => 2], self::APP, 'read', 'subject-example', 2), 503, 'the flag is new in version 3');
    }

    public function test_a_role_may_carry_a_description(): void
    {
        $contract = new DelegatedContract;
        $capabilities = $this->capabilities();
        $capabilities['controls']['workspace_roles'][0]['description'] = str_repeat('d', DelegatedContract::MAX_ROLE_DESCRIPTION_BYTES);

        $this->assertSame($capabilities, $contract->response($capabilities, self::APP, 'capabilities', null, 3));
        $this->assertSame(['owner', 'sender'], $contract->advertisedRoleIds($capabilities));

        foreach ([
            'a description longer than the bound' => str_repeat('d', DelegatedContract::MAX_ROLE_DESCRIPTION_BYTES + 1),
            'an empty description' => '',
            'a null description: omit it instead' => null,
            'a description that is not text' => ['d'],
        ] as $label => $description) {
            $changed = $this->capabilities();
            $changed['controls']['workspace_roles'][0]['description'] = $description;
            $this->refused(fn () => $contract->response($changed, self::APP, 'capabilities', null, 3), 503, $label);
        }

        $v2 = [...$capabilities, 'contract_version' => 2];
        $this->refused(fn () => $contract->response($v2, self::APP, 'capabilities', null, 2), 503, 'descriptions are new in version 3');
    }

    public function test_a_removal_answers_with_the_account_kept_and_nothing_left_in_the_projection(): void
    {
        $contract = new DelegatedContract;
        $removed = [...$this->state(), 'operation' => 'remove', 'access' => ['application_admin' => false, 'workspaces' => []], 'last_seen_at' => '2026-10-09T08:00:00Z',
            'allowed_edits' => ['application_admin' => false, 'workspaces' => true, 'provision' => false, 'remove' => true]];

        $this->assertSame($removed, $contract->response($removed, self::APP, 'remove', 'subject-example', 3));

        foreach ([
            'an administrator flag left' => ['access' => ['application_admin' => true, 'workspaces' => []]],
            'a membership left in the projection' => ['access' => ['application_admin' => false, 'workspaces' => [['id' => 'w1', 'role' => 'owner', 'editable' => false]]]],
            'the account gone' => ['provisioned' => false, 'revision' => null, 'access' => null, 'last_seen_at' => null,
                'allowed_edits' => ['application_admin' => false, 'workspaces' => false, 'provision' => true, 'remove' => false]],
            'another subject' => ['subject' => 'someone-else'],
            'a further removal not offered, though it is a no-op' => ['allowed_edits' => [...$removed['allowed_edits'], 'remove' => false]],
        ] as $label => $change) {
            $this->refused(fn () => $contract->response([...$removed, ...$change], self::APP, 'remove', 'subject-example', 3), 503, $label);
        }
        $this->refused(fn () => $contract->response($removed, self::APP, 'remove', null, 3), 503, 'no subject to echo');
    }

    public function test_an_adapter_answer_may_add_only_metadata_to_a_state(): void
    {
        $contract = new DelegatedContract;
        $fields = array_diff_key($this->state(), ['contract_version' => true, 'application' => true, 'operation' => true]);

        $answer = $contract->adapterAnswer([...$fields, 'first_sign_in_at' => '2026-10-01T09:30:00Z'], self::APP, 'read', 'subject-example');
        $this->assertSame(['contract_version' => 3, 'application' => self::APP, 'operation' => 'read'], array_slice($answer, 0, 3, true));

        $removed = [...$fields, 'access' => ['application_admin' => false, 'workspaces' => []], 'allowed_edits' => [...$fields['allowed_edits'], 'remove' => true]];
        $this->assertSame('remove', $contract->adapterAnswer($removed, self::APP, 'remove', 'subject-example')['operation']);

        foreach ([
            'an undefined field' => [[...$fields, 'email' => 'person@example.test'], 'read'],
            'metadata on a page' => [['subjects' => [], 'next_cursor' => null, 'last_seen_at' => null], 'subjects'],
            'metadata on capabilities' => [['controls' => $this->capabilities()['controls'], 'provisioned_at' => null], 'capabilities'],
            'metadata in a workspace entry' => [['workspaces' => [['id' => 'w1', 'label' => 'W', 'last_seen_at' => null]], 'next_cursor' => null], 'workspaces'],
            'an undefined field in a subject entry' => [['subjects' => [['subject' => 's', 'label' => 'S', 'email' => 'person@example.test']], 'next_cursor' => null], 'subjects'],
            'a receipt, which is the endpoint\'s own' => [['operation_id' => self::OPERATION, 'status' => 'unknown'], 'receipt'],
        ] as $label => [$answerFields, $operation]) {
            $this->refused(fn () => $contract->adapterAnswer($answerFields, self::APP, $operation, $operation === 'read' ? 'subject-example' : null), 503, $label);
        }
    }

    public function test_a_subject_entry_may_carry_the_same_metadata_held_to_the_same_shape(): void
    {
        $contract = new DelegatedContract;
        $entry = ['subject' => 's1', 'label' => 'Example Person', 'provisioned_at' => '2026-09-01T10:00:00Z', 'first_sign_in_at' => null, 'last_seen_at' => '2026-10-09T17:45:00+02:00'];

        $page = $contract->adapterAnswer(['subjects' => [$entry, ['subject' => 's2', 'label' => 'Other']], 'next_cursor' => null], self::APP, 'subjects', null);
        $this->assertSame($entry, $page['subjects'][0]);

        foreach (['2026-10-10', '2026-02-30T12:00:00Z', 1760097600, ''] as $value) {
            $bad = ['contract_version' => 3, 'application' => self::APP, 'operation' => 'subjects', 'subjects' => [[...$entry, 'last_seen_at' => $value]], 'next_cursor' => null];
            $this->refused(fn () => $contract->response($bad, self::APP, 'subjects', null, 3), 503, 'entry metadata '.var_export($value, true));
            $this->refused(fn () => $contract->adapterAnswer(array_slice($bad, 3, null, true), self::APP, 'subjects', null), 503, 'adapter entry metadata '.var_export($value, true));
        }
    }

    public function test_a_receipt_holds_the_stored_answer_or_says_it_is_unknown(): void
    {
        $contract = new DelegatedContract;
        $envelope = ['contract_version' => 3, 'application' => self::APP, 'operation' => 'receipt', 'operation_id' => self::OPERATION];
        $stored = [...$this->state(), 'operation' => 'update'];

        foreach ([
            [...$envelope, 'status' => 'unknown'],
            [...$envelope, 'status' => 'known', 'response_status' => 200, 'response' => $stored],
            [...$envelope, 'status' => 'known', 'response_status' => 409, 'response' => ['error' => 'revision_conflict']],
            [...$envelope, 'status' => 'known', 'response_status' => 403, 'response' => ['error' => 'protected_membership']],
        ] as $receipt) {
            $this->assertSame($receipt, $contract->response($receipt, self::APP, 'receipt', null, 3));
        }

        foreach ([
            'an unknown receipt with a stored answer' => [...$envelope, 'status' => 'unknown', 'response' => ['error' => 'x']],
            'another status' => [...$envelope, 'status' => 'pending'],
            'no operation id' => array_diff_key([...$envelope, 'status' => 'unknown'], ['operation_id' => true]),
            'a malformed operation id' => [...$envelope, 'operation_id' => 'short', 'status' => 'unknown'],
            'a known receipt without its answer' => [...$envelope, 'status' => 'known', 'response_status' => 200],
            'a stored server error' => [...$envelope, 'status' => 'known', 'response_status' => 500, 'response' => ['error' => 'internal_error']],
            'a status that is not a number' => [...$envelope, 'status' => 'known', 'response_status' => '200', 'response' => $stored],
            'a stored read' => [...$envelope, 'status' => 'known', 'response_status' => 200, 'response' => [...$stored, 'operation' => 'read']],
            'a stored answer for another application' => [...$envelope, 'status' => 'known', 'response_status' => 200, 'response' => [...$stored, 'application' => 'another-app']],
            'a stored answer outside the contract' => [...$envelope, 'status' => 'known', 'response_status' => 200, 'response' => [...$stored, 'revision' => null]],
            'a stored version 2 answer' => [...$envelope, 'status' => 'known', 'response_status' => 200, 'response' => [...$stored, 'contract_version' => 2]],
            'a refusal with more than its outcome' => [...$envelope, 'status' => 'known', 'response_status' => 409, 'response' => ['error' => 'revision_conflict', 'detail' => 'x']],
            'a refusal without an outcome' => [...$envelope, 'status' => 'known', 'response_status' => 409, 'response' => []],
            'an extra field' => [...$envelope, 'status' => 'unknown', 'note' => 'x'],
        ] as $label => $receipt) {
            $this->refused(fn () => $contract->response($receipt, self::APP, 'receipt', null, 3), 503, $label);
        }
    }

    public function test_a_receipt_must_be_about_the_write_it_was_asked_for(): void
    {
        $contract = new DelegatedContract;
        $write = $contract->request(self::APP, $this->update(), 3);
        $envelope = ['contract_version' => 3, 'application' => self::APP, 'operation' => 'receipt', 'operation_id' => self::OPERATION];
        $known = [...$envelope, 'status' => 'known', 'response_status' => 200, 'response' => [...$this->state(), 'operation' => 'update']];

        $this->assertSame($known, $contract->receipt($known, self::APP, $write));
        $this->assertSame('unknown', $contract->receipt([...$envelope, 'status' => 'unknown'], self::APP, $write)['status']);
        $refusal = [...$envelope, 'status' => 'known', 'response_status' => 422, 'response' => ['error' => 'invalid_request']];
        $this->assertSame($refusal, $contract->receipt($refusal, self::APP, $write));

        foreach ([
            'another operation id' => [[...$known, 'operation_id' => str_repeat('b', 40)], $write],
            'an unknown receipt for another operation id' => [[...$envelope, 'operation_id' => str_repeat('b', 40), 'status' => 'unknown'], $write],
            'an answer about another subject' => [[...$known, 'response' => [...$known['response'], 'subject' => 'someone-else']], $write],
            'an answer to another operation' => [$known, $contract->request(self::APP, $this->remove(), 3)],
            'a write that is not one' => [$known, ['operation' => 'read', 'subject' => 'subject-example', 'operation_id' => self::OPERATION]],
        ] as $label => [$receipt, $asked]) {
            $this->refused(fn () => $contract->receipt($receipt, self::APP, $asked), 503, $label);
        }
    }

    public function test_an_account_only_removal_reports_no_workspaces(): void
    {
        $contract = new DelegatedContract;
        $accountOnly = $this->capabilities();
        $accountOnly['controls']['workspace_roles'] = [];
        $removed = [...$this->state(), 'operation' => 'remove', 'access' => ['application_admin' => false, 'workspaces' => []],
            'allowed_edits' => ['application_admin' => true, 'workspaces' => false, 'provision' => false, 'remove' => true]];

        $this->assertTrue($contract->fitsCapabilities($accountOnly, $removed));
        $this->assertFalse($contract->fitsCapabilities($accountOnly, [...$removed, 'allowed_edits' => [...$removed['allowed_edits'], 'workspaces' => true]]));
    }

    public function test_a_cursor_is_bound_to_its_search(): void
    {
        $cursors = new DelegatedCursor(new Encrypter(random_bytes(32), 'AES-256-CBC'));
        $searched = $cursors->encode('actor', 'subjects', 7, 'example');
        $listed = $cursors->encode('actor', 'subjects', 7);

        $this->assertSame(7, $cursors->after('actor', 'subjects', ['cursor' => $searched, 'query' => 'example']));
        $this->assertSame(7, $cursors->after('actor', 'subjects', ['cursor' => $listed]));
        $this->assertLessThanOrEqual(512, strlen($cursors->encode(str_repeat('a', 191), 'subjects', PHP_INT_MAX, str_repeat('é', 100))));

        foreach ([[$searched, []], [$searched, ['query' => 'Example']], [$listed, ['query' => 'example']]] as [$cursor, $search]) {
            try {
                $cursors->after('actor', 'subjects', ['cursor' => $cursor, ...$search]);
                $this->fail('A cursor was accepted for another search.');
            } catch (DelegatedAccessException $refused) {
                $this->assertSame(['invalid_cursor', 422], [$refused->outcome, $refused->status]);
            }
        }
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
            'operation_id' => self::OPERATION,
            ...$changes,
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private function remove(): array
    {
        return ['operation' => 'remove', 'subject' => 'subject-example', 'expected_revision' => 'rev-1', 'operation_id' => self::OPERATION];
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
                    ['id' => 'sender', 'label' => 'Sender', 'description' => 'Sends documents for signature.'],
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
            'allowed_edits' => ['application_admin' => false, 'workspaces' => true, 'provision' => false, 'remove' => false],
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private function unprovisioned(): array
    {
        return [...$this->state(), 'provisioned' => false, 'revision' => null, 'access' => null,
            'allowed_edits' => ['application_admin' => false, 'workspaces' => false, 'provision' => true, 'remove' => false]];
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
