<?php

namespace BWH\Auth\OAuth\DelegatedAccess;

final class DelegatedContract
{
    public const MAX_REQUEST_BYTES = 65536;

    public const MAX_RESPONSE_BYTES = 262144;

    public function request(string $application, array $input): array
    {
        $operation = $input['operation'] ?? null;
        $fields = match ($operation) {
            'capabilities' => ['operation'],
            'subjects', 'workspaces' => ['operation', 'cursor', 'limit'],
            'read' => ['operation', 'subject'],
            'update' => ['operation', 'subject', 'expected_revision', 'access'],
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
        if ($operation === 'update' && (! $this->boundedString($input['expected_revision'] ?? null, 128) || ! $this->access($input['access'] ?? null))) {
            throw new DelegatedAccessException('invalid_request', 422);
        }

        return ['contract_version' => 1, 'application' => $application, ...$input];
    }

    public function response(mixed $response, string $application, string $operation, ?string $subject = null): array
    {
        $valid = is_array($response) && ($response['contract_version'] ?? null) === 1
            && ($response['application'] ?? null) === $application && ($response['operation'] ?? null) === $operation;
        if ($valid) {
            $valid = match ($operation) {
                'capabilities' => is_array($response['controls'] ?? null)
                    && is_bool($response['controls']['application_admin'] ?? null)
                    && $this->permissions($response['controls']['workspace_permissions'] ?? null),
                'subjects', 'workspaces' => $this->page($response, $operation),
                'read', 'update' => $subject !== null && ($response['subject'] ?? null) === $subject && $this->state($response),
                default => false,
            };
        }
        if (! $valid) {
            throw new DelegatedAccessException('invalid_response');
        }

        return $response;
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

    private function boundedString(mixed $value, int $max): bool
    {
        return is_string($value) && $value !== '' && strlen($value) <= $max;
    }
}
