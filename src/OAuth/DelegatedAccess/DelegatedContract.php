<?php

namespace BWH\Auth\OAuth\DelegatedAccess;

/**
 * Validates delegated application access envelopes: contract version 3, the only version.
 *
 * An application advertises its own workspace roles, marks individual memberships editable or not,
 * and may accept provisioning of a subject it has not seen. Listings take a search query; writes
 * (`update`, `remove`) carry an `operation_id` the endpoint keeps receipts by; states may carry
 * read-only metadata.
 *
 * An application that advertises no workspace roles is account-only: it has accounts, an
 * application administrator flag and provisioning, and no workspaces. Every access value it sends
 * or accepts carries `workspaces: []`. The shape validators see one message at a time, so that rule
 * is checked against the capabilities response with {@see rolesAreAdvertised()} for access a
 * provider sends and {@see fitsCapabilities()} for what an application answers.
 *
 * This checks shapes and bounds only. Which roles an actor may grant, whether a subject may be
 * provisioned and every tenant rule remain the application's decisions.
 */
final class DelegatedContract
{
    public const MAX_REQUEST_BYTES = 65536;

    public const MAX_RESPONSE_BYTES = 262144;

    /** The contract version, and the only one: any other is `unsupported_contract_version`. */
    public const VERSION_3 = 3;

    public const MAX_WORKSPACE_ROLES = 16;

    public const MAX_ROLE_DESCRIPTION_BYTES = 1024;

    /** A search `query` on `subjects` and `workspaces`, in characters. */
    public const QUERY_MIN_CHARACTERS = 2;

    public const QUERY_MAX_CHARACTERS = 100;

    /** A write's `operation_id`: chosen by the provider once per user action and kept across retries. */
    public const OPERATION_ID_PATTERN = '/^[A-Za-z0-9_-]{32,64}$/D';

    /** Read-only observations a state and a `subjects` entry may carry: ISO-8601 timestamps or null. */
    public const STATE_METADATA = ['provisioned_at', 'first_sign_in_at', 'last_seen_at'];

    /** The operations that change something, each carrying an `operation_id`. */
    public const WRITE_OPERATIONS = ['update', 'remove'];

    /** The top-level fields each operation's answer carries besides the envelope, exactly. */
    public const ADAPTER_FIELDS = [
        'capabilities' => ['controls'],
        'subjects' => ['subjects', 'next_cursor'],
        'workspaces' => ['workspaces', 'next_cursor'],
        'read' => ['subject', 'provisioned', 'revision', 'access', 'allowed_edits'],
        'update' => ['subject', 'provisioned', 'revision', 'access', 'allowed_edits'],
        'remove' => ['subject', 'provisioned', 'revision', 'access', 'allowed_edits'],
    ];

    /** The top-level fields an answer may add to {@see ADAPTER_FIELDS}. */
    public const ADAPTER_OPTIONAL_FIELDS = [
        'read' => self::STATE_METADATA,
        'update' => self::STATE_METADATA,
        'remove' => self::STATE_METADATA,
    ];

    /**
     * Validate an operation's input and wrap it in the envelope.
     *
     * @param  array<string, mixed>  $input  `operation` plus that operation's fields
     * @return array<string, mixed>
     *
     * @throws DelegatedAccessException `invalid_request` (422), or `unsupported_contract_version` (500)
     */
    public function request(string $application, array $input, int $version = self::VERSION_3): array
    {
        $this->assertSupported($version);

        $operation = $input['operation'] ?? null;
        $fields = match ($operation) {
            'capabilities' => ['operation'],
            'subjects', 'workspaces' => ['operation', 'cursor', 'limit', 'query'],
            'read' => ['operation', 'subject'],
            'update' => ['operation', 'subject', 'expected_revision', 'access', 'display_name', 'operation_id'],
            'remove' => ['operation', 'subject', 'expected_revision', 'operation_id'],
            'receipt' => ['operation', 'operation_id'],
            default => [],
        };
        if ($fields === [] || array_diff(array_keys($input), $fields) !== []) {
            throw new DelegatedAccessException('invalid_request', 422);
        }
        if (in_array($operation, ['subjects', 'workspaces'], true)
            && ((! is_int($input['limit'] ?? 50) || ($input['limit'] ?? 50) < 1 || ($input['limit'] ?? 50) > 50)
                || (isset($input['cursor']) && ! $this->boundedString($input['cursor'], 512))
                || (array_key_exists('query', $input) && ! self::validQuery($input['query'])))) {
            throw new DelegatedAccessException('invalid_request', 422);
        }
        if (in_array($operation, ['read', 'update', 'remove'], true) && ! $this->boundedString($input['subject'] ?? null, 191)) {
            throw new DelegatedAccessException('invalid_request', 422);
        }
        // Every write and receipt names its operation, which is required, never defaulted.
        if (in_array($operation, ['update', 'remove', 'receipt'], true) && ! self::validOperationId($input['operation_id'] ?? null)) {
            throw new DelegatedAccessException('invalid_request', 422);
        }
        if ($operation === 'update' && ! $this->update($input)) {
            throw new DelegatedAccessException('invalid_request', 422);
        }
        // Removal always compares against a revision: there is no account to provision away.
        if ($operation === 'remove' && ! $this->boundedString($input['expected_revision'] ?? null, 128)) {
            throw new DelegatedAccessException('invalid_request', 422);
        }

        return ['contract_version' => $version, 'application' => $application, ...$input];
    }

    /**
     * Validate a response envelope: the version, application and operation echoed, then the
     * operation's own fields. Pass the target subject for `read`, `update` and `remove`, whose answer
     * must echo it exactly.
     *
     * A `receipt` answer is checked for its shape here; {@see receipt()} also checks that it
     * is about the write it was asked for.
     *
     * @return array<string, mixed>
     *
     * @throws DelegatedAccessException `invalid_response`, or `unsupported_contract_version` (500)
     */
    public function response(mixed $response, string $application, string $operation, ?string $subject = null, int $version = self::VERSION_3): array
    {
        $this->assertSupported($version);

        $valid = is_array($response) && ($response['contract_version'] ?? null) === $version
            && ($response['application'] ?? null) === $application && ($response['operation'] ?? null) === $operation;
        if ($valid) {
            $valid = match ($operation) {
                'capabilities' => $this->controls($response['controls'] ?? null),
                'subjects', 'workspaces' => $this->page($response, $operation),
                'read', 'update' => $subject !== null && ($response['subject'] ?? null) === $subject && $this->state($response),
                'remove' => $subject !== null && ($response['subject'] ?? null) === $subject
                    && $this->state($response) && $this->removed($response),
                'receipt' => $this->receiptShape($response, $application),
                default => false,
            };
        }
        if (! $valid) {
            throw new DelegatedAccessException('invalid_response');
        }

        return $response;
    }

    /**
     * Validate a `receipt` answer for the write it was asked about.
     *
     * A provider asks for a receipt after a write whose outcome it does not know: a 5xx, a timeout or
     * a transport error. `$write` is that write as {@see request()} built it. The answer must have the
     * receipt's shape, name the same `operation_id`, and, when it holds a successful answer, hold one
     * for the same operation on the same subject. A known receipt's `response` is what the
     * application answered then: a state on `response_status` 200, `{error}` on a refusal.
     *
     * @param  array<string, mixed>  $write
     * @return array<string, mixed>
     *
     * @throws DelegatedAccessException `invalid_response`
     */
    public function receipt(mixed $response, string $application, array $write): array
    {
        $receipt = $this->response($response, $application, 'receipt', null, self::VERSION_3);

        $valid = in_array($write['operation'] ?? null, self::WRITE_OPERATIONS, true)
            && is_string($write['operation_id'] ?? null) && $receipt['operation_id'] === $write['operation_id'];
        if ($valid && $receipt['status'] === 'known' && $receipt['response_status'] === 200) {
            $valid = $receipt['response']['operation'] === $write['operation'] && $receipt['response']['subject'] === ($write['subject'] ?? null);
        }
        if (! $valid) {
            throw new DelegatedAccessException('invalid_response');
        }

        return $receipt;
    }

    /**
     * A fresh `operation_id` for one user action: 43 URL-safe characters from 256 random bits.
     *
     * Generate it once when the person acts and send the same one on every attempt of that action.
     * It is never the assertion's `jti`, which must be new for every HTTP request.
     */
    public static function operationId(): string
    {
        return rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
    }

    public static function validOperationId(mixed $value): bool
    {
        return is_string($value) && preg_match(self::OPERATION_ID_PATTERN, $value) === 1;
    }

    /**
     * A search query: 2 to 100 characters of valid UTF-8 without control characters. An application
     * matches it as a case-insensitive substring, within what the actor may see.
     */
    public static function validQuery(mixed $value): bool
    {
        if (! is_string($value) || preg_match('/^[^\p{Cc}]*$/uD', $value) !== 1) {
            return false;
        }
        $length = mb_strlen($value, 'UTF-8');

        return $length >= self::QUERY_MIN_CHARACTERS && $length <= self::QUERY_MAX_CHARACTERS;
    }

    /**
     * Wrap an application adapter's answer in the envelope and validate all of it.
     *
     * Stricter than {@see response()} on its own: the answer carries exactly the operation's fields
     * (and, for a state, only the optional metadata besides), and page entries exactly an identifier
     * and a label, so no adapter data leaves by an extra key.
     *
     * @param  array<string, mixed>  $fields  the adapter's answer, without the envelope
     * @return array<string, mixed> the whole response
     *
     * @throws DelegatedAccessException `invalid_response`
     */
    public function adapterAnswer(array $fields, string $application, string $operation, ?string $subject): array
    {
        $required = self::ADAPTER_FIELDS[$operation] ?? [];
        $present = array_intersect(array_map('strval', array_keys($fields)), self::ADAPTER_OPTIONAL_FIELDS[$operation] ?? []);
        if ($required === [] || ! $this->hasExactKeys($fields, [...$required, ...$present])) {
            throw new DelegatedAccessException('invalid_response');
        }

        // response() allows extra keys in page entries; an adapter's may carry exactly an identifier
        // and a label, and a subject entry the state metadata besides.
        if ($operation === 'subjects' || $operation === 'workspaces') {
            $entryKeys = [$operation === 'subjects' ? 'subject' : 'id', 'label'];
            foreach (is_array($fields[$operation]) ? $fields[$operation] : [] as $entry) {
                $optional = $operation === 'subjects' && is_array($entry)
                    ? array_intersect(array_map('strval', array_keys($entry)), self::STATE_METADATA) : [];
                if (! is_array($entry) || ! $this->hasExactKeys($entry, [...$entryKeys, ...$optional])) {
                    throw new DelegatedAccessException('invalid_response');
                }
            }
        }

        $response = ['contract_version' => self::VERSION_3, 'application' => $application, 'operation' => $operation] + $fields;

        return $this->response($response, $application, $operation, $subject, self::VERSION_3);
    }

    /**
     * The role ids a `capabilities` response advertised, in its order.
     *
     * @return list<string>
     */
    public function advertisedRoleIds(array $capabilities): array
    {
        $roles = $capabilities['controls']['workspace_roles'] ?? null;
        if (! is_array($roles)) {
            return [];
        }

        $ids = [];
        foreach ($roles as $role) {
            if (is_array($role) && is_string($role['id'] ?? null)) {
                $ids[] = $role['id'];
            }
        }

        return $ids;
    }

    /**
     * Whether a `capabilities` response describes an account-only application: one that
     * advertises no workspace roles, so no membership can name a role and every access value it
     * sends or accepts has `workspaces: []`.
     *
     * False for anything that is not a `controls.workspace_roles` list, so a capabilities value that
     * was never validated is not mistaken for one.
     */
    public function accountOnly(array $capabilities): bool
    {
        return ($capabilities['controls']['workspace_roles'] ?? null) === [];
    }

    /**
     * Whether every membership in an access value names a role the application advertised.
     *
     * The shape validators cannot know the advertised roles, so a provider checks an access value
     * it is about to send, or has received, against the capabilities response it holds. An
     * account-only application advertises none, so only an access value without memberships passes.
     * A capabilities value without a `workspace_roles` list passes nothing.
     */
    public function rolesAreAdvertised(array $capabilities, array $access): bool
    {
        $workspaces = $access['workspaces'] ?? null;
        if (! is_array($capabilities['controls']['workspace_roles'] ?? null) || ! is_array($workspaces)) {
            return false;
        }

        $ids = $this->advertisedRoleIds($capabilities);
        foreach ($workspaces as $workspace) {
            if (! is_array($workspace) || ! in_array($workspace['role'] ?? null, $ids, true)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Whether a validated answer is consistent with the application's capabilities.
     *
     * For a workspace application this is always true: its answers are checked by shape alone, and a
     * read may report a role the application has since retired. For an account-only application a
     * `workspaces` page is empty, and a `read`, `update` or `remove` state reports no memberships and
     * does not offer workspace edits. Any other answer is accepted as it is.
     *
     * @param  array<string, mixed>  $capabilities  a validated capabilities response
     * @param  array<string, mixed>  $response  a validated response from the same application
     */
    public function fitsCapabilities(array $capabilities, array $response): bool
    {
        if (! $this->accountOnly($capabilities)) {
            return true;
        }

        return match ($response['operation'] ?? null) {
            'workspaces' => ($response['workspaces'] ?? null) === [] && ($response['next_cursor'] ?? null) === null,
            'read', 'update', 'remove' => ($response['allowed_edits']['workspaces'] ?? null) === false
                && (($response['access'] ?? null) === null || ($response['access']['workspaces'] ?? null) === []),
            default => true,
        };
    }

    private function assertSupported(int $version): void
    {
        if ($version !== self::VERSION_3) {
            // A deployment configured for a version this package does not implement. Not a refusal
            // of any request: nothing should be sent or accepted until the configuration is fixed.
            throw new DelegatedAccessException('unsupported_contract_version', 500);
        }
    }

    /**
     * A page of entries, each an identifier and a label. A `subjects` entry may also carry the state
     * metadata, held to the same shape as in a state.
     *
     * @param  array<string, mixed>  $response
     */
    private function page(array $response, string $operation): bool
    {
        $items = $response[$operation] ?? null;
        if (! is_array($items) || ! array_is_list($items) || count($items) > 50
            || ! array_key_exists('next_cursor', $response)
            || ($response['next_cursor'] !== null && ! $this->boundedString($response['next_cursor'], 512))) {
            return false;
        }
        foreach ($items as $item) {
            if (! is_array($item) || ! $this->boundedString($item[$operation === 'subjects' ? 'subject' : 'id'] ?? null, 191)
                || ! $this->boundedString($item['label'] ?? null, 255)
                || ($operation === 'subjects' && ! $this->metadata($item, true))) {
                return false;
            }
        }

        return true;
    }

    /**
     * An update: a revision to compare against, or null to provision; a display name only when
     * provisioning; and memberships that name roles.
     *
     * @param  array<string, mixed>  $input
     */
    private function update(array $input): bool
    {
        // A missing revision is not a null one. Provisioning has to be asked for.
        if (! array_key_exists('expected_revision', $input)) {
            return false;
        }

        $provisioning = $input['expected_revision'] === null;
        if (! $provisioning && ! $this->boundedString($input['expected_revision'], 128)) {
            return false;
        }
        if (array_key_exists('display_name', $input) && (! $provisioning || ! $this->boundedString($input['display_name'], 255))) {
            return false;
        }

        return $this->access($input['access'] ?? null, false);
    }

    /**
     * `{application_admin, workspace_roles, provisioning}`; each role `{id, label}` and optionally a
     * `description`.
     */
    private function controls(mixed $controls): bool
    {
        if (! is_array($controls) || ! $this->hasExactKeys($controls, ['application_admin', 'workspace_roles', 'provisioning'])
            || ! is_bool($controls['application_admin']) || ! is_bool($controls['provisioning'])) {
            return false;
        }

        // No roles at all is an account-only application ({@see accountOnly()}), not a missing list.
        $roles = $controls['workspace_roles'];
        if (! is_array($roles) || ! array_is_list($roles) || count($roles) > self::MAX_WORKSPACE_ROLES) {
            return false;
        }

        $ids = [];
        foreach ($roles as $role) {
            $keys = is_array($role) && array_key_exists('description', $role) ? ['id', 'label', 'description'] : ['id', 'label'];
            if (! is_array($role) || ! $this->hasExactKeys($role, $keys)
                || ! $this->boundedString($role['id'], 64) || ! $this->boundedString($role['label'], 255)
                || (isset($keys[2]) && ! $this->boundedString($role['description'], self::MAX_ROLE_DESCRIPTION_BYTES))
                || in_array($role['id'], $ids, true)) {
                return false;
            }
            $ids[] = $role['id'];
        }

        return true;
    }

    /**
     * A state: whether the subject is provisioned, its revision and access, what this actor may edit,
     * and optionally read-only metadata. `allowed_edits.remove` says whether a `remove` by this actor
     * would succeed now, including as a no-op. Nothing exists to edit or remove for an unprovisioned
     * subject, which may only be offered provisioning, and has no observations.
     *
     * @param  array<string, mixed>  $response
     */
    private function state(array $response): bool
    {
        $edits = $response['allowed_edits'] ?? null;
        if (! is_bool($response['provisioned'] ?? null)
            || ! is_array($edits) || ! $this->hasExactKeys($edits, ['application_admin', 'workspaces', 'provision', 'remove'])
            || ! is_bool($edits['application_admin']) || ! is_bool($edits['workspaces']) || ! is_bool($edits['provision'])
            || ! is_bool($edits['remove'])
            || ! array_key_exists('revision', $response) || ! array_key_exists('access', $response)) {
            return false;
        }
        if (! $response['provisioned']) {
            return $response['revision'] === null && $response['access'] === null
                && $edits['application_admin'] === false && $edits['workspaces'] === false && $edits['remove'] === false
                && $this->metadata($response, false);
        }
        if ($edits['provision'] !== false || ! $this->boundedString($response['revision'], 128) || ! $this->access($response['access'], true)) {
            return false;
        }
        // A removal is refused whole when anything in the projection is protected, so a state reporting
        // such a thing cannot offer one. Other refusals (permission, last administrator) are the
        // application's to report as false.
        if ($edits['remove']
            && (($response['access']['application_admin'] && ! $response['allowed_edits']['application_admin'])
                || array_filter($response['access']['workspaces'], static fn (array $m): bool => $m['editable'] === false) !== [])) {
            return false;
        }

        return $this->metadata($response, true);
    }

    /**
     * Each metadata field present is null or an ISO-8601 timestamp; an account that does not exist
     * has no observations at all.
     *
     * @param  array<array-key, mixed>  $value  a state or a `subjects` entry
     */
    private function metadata(array $value, bool $exists): bool
    {
        foreach (self::STATE_METADATA as $field) {
            if (! array_key_exists($field, $value) || $value[$field] === null) {
                continue;
            }
            if (! $exists || ! self::timestamp($value[$field])) {
                return false;
            }
        }

        return true;
    }

    /**
     * A removal leaves the account and nothing the actor manages: no administrator flag, no membership
     * in the actor's projection, and a further removal offered as the no-op it would be. Memberships
     * outside the projection are not reported, and survive.
     *
     * @param  array<string, mixed>  $response  a valid state
     */
    private function removed(array $response): bool
    {
        // Removing again would be a no-op, which succeeds.
        return $response['provisioned'] === true && $response['allowed_edits']['remove'] === true
            && $response['access']['application_admin'] === false && $response['access']['workspaces'] === [];
    }

    /**
     * `{operation_id, status: "known", response_status, response}` or `{operation_id, status: "unknown"}`.
     *
     * A known receipt holds the application's answer to an `update` or `remove`: a whole response on
     * 200, or the `{error}` body of a 4xx refusal.
     *
     * @param  array<string, mixed>  $response
     */
    private function receiptShape(array $response, string $application): bool
    {
        $fields = array_diff_key($response, array_flip(['contract_version', 'application', 'operation']));
        if (! self::validOperationId($fields['operation_id'] ?? null)) {
            return false;
        }
        if (($fields['status'] ?? null) === 'unknown') {
            return $this->hasExactKeys($fields, ['operation_id', 'status']);
        }
        if (($fields['status'] ?? null) !== 'known' || ! $this->hasExactKeys($fields, ['operation_id', 'status', 'response_status', 'response'])
            || ! is_int($fields['response_status']) || ! is_array($fields['response'])) {
            return false;
        }

        $status = $fields['response_status'];
        $stored = $fields['response'];
        if ($status === 200) {
            $operation = $stored['operation'] ?? null;
            $subject = $stored['subject'] ?? null;
            if (! in_array($operation, self::WRITE_OPERATIONS, true) || ! is_string($subject)) {
                return false;
            }
            try {
                $this->response($stored, $application, $operation, $subject, self::VERSION_3);
            } catch (DelegatedAccessException) {
                return false;
            }

            return true;
        }

        return $status >= 400 && $status <= 499 && $this->hasExactKeys($stored, ['error']) && $this->boundedString($stored['error'], 64);
    }

    /** An ISO-8601 date and time with seconds and an explicit offset, such as `2026-10-10T12:00:00Z`. */
    private static function timestamp(mixed $value): bool
    {
        if (! is_string($value) || preg_match('/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d{1,6})?(Z|[+-](\d{2}):(\d{2}))$/D', $value, $parts) !== 1) {
            return false;
        }

        return checkdate((int) $parts[2], (int) $parts[3], (int) $parts[1])
            && (int) $parts[4] < 24 && (int) $parts[5] < 60 && (int) $parts[6] < 60
            && (($parts[9] ?? '') === '' || ((int) $parts[9] < 24 && (int) $parts[10] < 60));
    }

    /**
     * Access: memberships name a role, and a response also says whether each is editable. Role ids
     * are bounded here; whether they were advertised is {@see rolesAreAdvertised()}.
     */
    private function access(mixed $access, bool $reported): bool
    {
        if (! is_array($access) || ! $this->hasExactKeys($access, ['application_admin', 'workspaces'])
            || ! is_bool($access['application_admin']) || ! is_array($access['workspaces'])
            || ! array_is_list($access['workspaces']) || count($access['workspaces']) > 100) {
            return false;
        }

        $keys = $reported ? ['id', 'role', 'editable'] : ['id', 'role'];
        $ids = [];
        foreach ($access['workspaces'] as $workspace) {
            if (! is_array($workspace) || ! $this->hasExactKeys($workspace, $keys)
                || ! $this->boundedString($workspace['id'], 191)
                || ! $this->boundedString($workspace['role'], 64)
                || ($reported && ! is_bool($workspace['editable']))
                || in_array($workspace['id'], $ids, true)) {
                return false;
            }
            $ids[] = $workspace['id'];
        }

        return true;
    }

    /**
     * @param  list<string>  $expected
     */
    private function hasExactKeys(array $value, array $expected): bool
    {
        $keys = array_map('strval', array_keys($value));
        sort($keys);
        sort($expected);

        return $keys === $expected;
    }

    private function boundedString(mixed $value, int $max): bool
    {
        return is_string($value) && $value !== '' && strlen($value) <= $max;
    }
}
