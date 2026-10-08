<?php

namespace BWH\Auth\OAuth\DelegatedAccess;

/**
 * Validates delegated application access envelopes in both contract versions.
 *
 * Version 1 describes access as `application_admin` plus per-workspace `read`/`write`. Version 2
 * lets an application advertise its own workspace roles, mark individual memberships editable or
 * not, and accept provisioning of a subject it has not seen (bherila/auth-laravel#42). Version 1
 * is the default for every method, so an existing caller validates exactly what it did before.
 *
 * This checks shapes and bounds only. Which roles an actor may grant, whether a subject may be
 * provisioned and every tenant rule remain the application's decisions.
 */
final class DelegatedContract
{
    public const MAX_REQUEST_BYTES = 65536;

    public const MAX_RESPONSE_BYTES = 262144;

    public const VERSION_1 = 1;

    public const VERSION_2 = 2;

    public const MAX_WORKSPACE_ROLES = 16;

    /** The top-level fields each version 2 operation's answer carries besides the envelope, exactly. */
    public const ADAPTER_FIELDS = [
        'capabilities' => ['controls'],
        'subjects' => ['subjects', 'next_cursor'],
        'workspaces' => ['workspaces', 'next_cursor'],
        'read' => ['subject', 'provisioned', 'revision', 'access', 'allowed_edits'],
        'update' => ['subject', 'provisioned', 'revision', 'access', 'allowed_edits'],
    ];

    public function request(string $application, array $input, int $version = self::VERSION_1): array
    {
        $this->assertSupported($version);

        $operation = $input['operation'] ?? null;
        $fields = match ($operation) {
            'capabilities' => ['operation'],
            'subjects', 'workspaces' => ['operation', 'cursor', 'limit'],
            'read' => ['operation', 'subject'],
            'update' => $version === self::VERSION_2
                ? ['operation', 'subject', 'expected_revision', 'access', 'display_name']
                : ['operation', 'subject', 'expected_revision', 'access'],
            default => [],
        };
        if ($fields === [] || array_diff(array_keys($input), $fields) !== []) {
            throw new DelegatedAccessException('invalid_request', 422);
        }
        if (in_array($operation, ['subjects', 'workspaces'], true)
            && ((! is_int($input['limit'] ?? 50) || ($input['limit'] ?? 50) < 1 || ($input['limit'] ?? 50) > 50)
                || (isset($input['cursor']) && ! $this->boundedString($input['cursor'], 512)))) {
            throw new DelegatedAccessException('invalid_request', 422);
        }
        if (in_array($operation, ['read', 'update'], true) && ! $this->boundedString($input['subject'] ?? null, 191)) {
            throw new DelegatedAccessException('invalid_request', 422);
        }
        if ($operation === 'update') {
            $valid = $version === self::VERSION_2
                ? $this->updateV2($input)
                : $this->boundedString($input['expected_revision'] ?? null, 128) && $this->access($input['access'] ?? null);

            if (! $valid) {
                throw new DelegatedAccessException('invalid_request', 422);
            }
        }

        return ['contract_version' => $version, 'application' => $application, ...$input];
    }

    public function response(mixed $response, string $application, string $operation, ?string $subject = null, int $version = self::VERSION_1): array
    {
        $this->assertSupported($version);

        $valid = is_array($response) && ($response['contract_version'] ?? null) === $version
            && ($response['application'] ?? null) === $application && ($response['operation'] ?? null) === $operation;
        if ($valid) {
            $valid = match ($operation) {
                'capabilities' => $version === self::VERSION_2
                    ? $this->controlsV2($response['controls'] ?? null)
                    : is_array($response['controls'] ?? null)
                        && is_bool($response['controls']['application_admin'] ?? null)
                        && $this->permissions($response['controls']['workspace_permissions'] ?? null),
                'subjects', 'workspaces' => $this->page($response, $operation),
                'read', 'update' => $subject !== null && ($response['subject'] ?? null) === $subject
                    && ($version === self::VERSION_2 ? $this->stateV2($response) : $this->state($response)),
                default => false,
            };
        }
        if (! $valid) {
            throw new DelegatedAccessException('invalid_response');
        }

        return $response;
    }

    /**
     * Wrap an application adapter's answer in the version 2 envelope and validate all of it.
     *
     * Stricter than {@see response()} on its own: the answer carries exactly the operation's fields,
     * and page entries exactly an identifier and a label, so no adapter data leaves by an extra key.
     *
     * @param  array<string, mixed>  $fields  the adapter's answer, without the envelope
     * @return array<string, mixed> the whole response
     *
     * @throws DelegatedAccessException `invalid_response`
     */
    public function adapterAnswer(array $fields, string $application, string $operation, ?string $subject): array
    {
        if (! $this->hasExactKeys($fields, self::ADAPTER_FIELDS[$operation] ?? [])) {
            throw new DelegatedAccessException('invalid_response');
        }

        // Page entries share version 1's validator, which allows extra keys.
        if ($operation === 'subjects' || $operation === 'workspaces') {
            $entryKeys = [$operation === 'subjects' ? 'subject' : 'id', 'label'];
            foreach (is_array($fields[$operation]) ? $fields[$operation] : [] as $entry) {
                if (! is_array($entry) || ! $this->hasExactKeys($entry, $entryKeys)) {
                    throw new DelegatedAccessException('invalid_response');
                }
            }
        }

        $response = ['contract_version' => self::VERSION_2, 'application' => $application, 'operation' => $operation] + $fields;

        return $this->response($response, $application, $operation, $subject, self::VERSION_2);
    }

    /**
     * The role ids a version 2 `capabilities` response advertised, in its order.
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
     * Whether every membership in a version 2 access value names a role the application advertised.
     *
     * The shape validators cannot know the advertised roles, so a provider checks an access value
     * it is about to send, or has received, against the capabilities response it holds.
     */
    public function rolesAreAdvertised(array $capabilities, array $access): bool
    {
        $ids = $this->advertisedRoleIds($capabilities);
        $workspaces = $access['workspaces'] ?? null;
        if ($ids === [] || ! is_array($workspaces)) {
            return false;
        }

        foreach ($workspaces as $workspace) {
            if (! is_array($workspace) || ! in_array($workspace['role'] ?? null, $ids, true)) {
                return false;
            }
        }

        return true;
    }

    private function assertSupported(int $version): void
    {
        if (! in_array($version, [self::VERSION_1, self::VERSION_2], true)) {
            // A deployment configured for a version this package does not implement. Not a refusal
            // of any request: nothing should be sent or accepted until the configuration is fixed.
            throw new DelegatedAccessException('unsupported_contract_version', 500);
        }
    }

    private function permissions(mixed $permissions): bool
    {
        return is_array($permissions) && array_is_list($permissions) && count($permissions) <= 2
            && count(array_unique($permissions, SORT_REGULAR)) === count($permissions)
            && array_all($permissions, fn ($permission): bool => in_array($permission, ['read', 'write'], true));
    }

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
                || ! $this->boundedString($item['label'] ?? null, 255)) {
                return false;
            }
        }

        return true;
    }

    private function state(array $response): bool
    {
        if (! is_bool($response['provisioned'] ?? null)
            || ! is_array($response['allowed_edits'] ?? null)
            || ! is_bool($response['allowed_edits']['application_admin'] ?? null)
            || ! is_bool($response['allowed_edits']['workspaces'] ?? null)) {
            return false;
        }
        if (! $response['provisioned']) {
            return array_key_exists('revision', $response) && $response['revision'] === null
                && array_key_exists('access', $response) && $response['access'] === null
                && $response['allowed_edits']['application_admin'] === false && $response['allowed_edits']['workspaces'] === false;
        }

        return $this->boundedString($response['revision'] ?? null, 128) && $this->access($response['access'] ?? null);
    }

    private function access(mixed $access): bool
    {
        if (! is_array($access) || array_diff(array_keys($access), ['application_admin', 'workspaces']) !== []
            || ! is_bool($access['application_admin'] ?? null) || ! is_array($access['workspaces'] ?? null)
            || ! array_is_list($access['workspaces']) || count($access['workspaces']) > 100) {
            return false;
        }
        $ids = [];
        foreach ($access['workspaces'] as $workspace) {
            if (! is_array($workspace) || array_diff(array_keys($workspace), ['id', 'permission']) !== []
                || ! $this->boundedString($workspace['id'] ?? null, 191)
                || ! in_array($workspace['permission'] ?? null, ['read', 'write'], true)
                || in_array($workspace['id'], $ids, true)) {
                return false;
            }
            $ids[] = $workspace['id'];
        }

        return true;
    }

    /**
     * A version 2 update: a revision to compare against, or null to provision; a display name only
     * when provisioning; and memberships that name roles.
     */
    private function updateV2(array $input): bool
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

        return $this->accessV2($input['access'] ?? null, false);
    }

    private function controlsV2(mixed $controls): bool
    {
        if (! is_array($controls) || ! $this->hasExactKeys($controls, ['application_admin', 'workspace_roles', 'provisioning'])
            || ! is_bool($controls['application_admin']) || ! is_bool($controls['provisioning'])) {
            return false;
        }

        $roles = $controls['workspace_roles'];
        if (! is_array($roles) || ! array_is_list($roles) || $roles === [] || count($roles) > self::MAX_WORKSPACE_ROLES) {
            return false;
        }

        $ids = [];
        foreach ($roles as $role) {
            if (! is_array($role) || ! $this->hasExactKeys($role, ['id', 'label'])
                || ! $this->boundedString($role['id'], 64) || ! $this->boundedString($role['label'], 255)
                || in_array($role['id'], $ids, true)) {
                return false;
            }
            $ids[] = $role['id'];
        }

        return true;
    }

    private function stateV2(array $response): bool
    {
        $edits = $response['allowed_edits'] ?? null;
        if (! is_bool($response['provisioned'] ?? null)
            || ! is_array($edits) || ! $this->hasExactKeys($edits, ['application_admin', 'workspaces', 'provision'])
            || ! is_bool($edits['application_admin']) || ! is_bool($edits['workspaces']) || ! is_bool($edits['provision'])
            || ! array_key_exists('revision', $response) || ! array_key_exists('access', $response)) {
            return false;
        }
        if (! $response['provisioned']) {
            // Nothing exists to edit; the only thing that can be offered is creating it.
            return $response['revision'] === null && $response['access'] === null
                && $edits['application_admin'] === false && $edits['workspaces'] === false;
        }

        return $edits['provision'] === false
            && $this->boundedString($response['revision'], 128)
            && $this->accessV2($response['access'], true);
    }

    /**
     * Version 2 access: memberships name a role, and a response also says whether each is editable.
     * Role ids are bounded here; whether they were advertised is {@see rolesAreAdvertised()}.
     */
    private function accessV2(mixed $access, bool $reported): bool
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
