<?php

namespace BWH\Auth\OAuth\Credentials;

use LogicException;

/** Fails fast and loudly on a presentation that would misdescribe a grant. */
final class ScopePresentationValidator
{
    private const ID = '/^[a-z0-9_]+$/';

    /** @throws LogicException naming the offending id and scope */
    public static function assertValid(ScopePresentation $presentation): void
    {
        $catalog = ConfiguredGrantableScopes::catalog();
        $groupIds = [];
        $owner = [];
        $sensitive = [];

        foreach ($presentation->groups() as $group) {
            self::assertId('group', $group->id);
            if ($group->id === ScopePresentationResolver::UNGROUPED_ID) {
                throw new LogicException('Scope group id "'.ScopePresentationResolver::UNGROUPED_ID.'" is reserved for the generated group of ungrouped scopes.');
            }
            if (isset($groupIds[$group->id])) {
                throw new LogicException("Scope group id \"{$group->id}\" is used by more than one group.");
            }
            $groupIds[$group->id] = true;
            foreach ($group->scopes as $scope) {
                if (! array_key_exists($scope, $catalog)) {
                    throw new LogicException("Scope group \"{$group->id}\" names scope \"{$scope}\", which is not in the scope catalog.");
                }
                if (isset($owner[$scope])) {
                    throw new LogicException("Scope \"{$scope}\" is in more than one group (\"{$owner[$scope]}\" and \"{$group->id}\").");
                }
                $owner[$scope] = $group->id;
                if ($group->sensitive) {
                    $sensitive[$scope] = $group->id;
                }
            }
        }

        $closure = self::assertImplications($presentation, $catalog, $sensitive);

        $presetIds = [];
        foreach ($presentation->presets() as $preset) {
            self::assertId('preset', $preset->id);
            if (isset($presetIds[$preset->id])) {
                throw new LogicException("Scope preset id \"{$preset->id}\" is used by more than one preset.");
            }
            $presetIds[$preset->id] = true;
            if ($preset->scopes === []) {
                throw new LogicException("Scope preset \"{$preset->id}\" is empty.");
            }
            foreach ($preset->scopes as $scope) {
                if (! array_key_exists($scope, $catalog)) {
                    throw new LogicException("Scope preset \"{$preset->id}\" names scope \"{$scope}\", which is not in the scope catalog.");
                }
                if (isset($sensitive[$scope])) {
                    throw new LogicException("Scope preset \"{$preset->id}\" contains scope \"{$scope}\" from the sensitive group \"{$sensitive[$scope]}\"; sensitive scopes must be chosen deliberately.");
                }
            }
            $contained = array_map('strval', $preset->scopes);
            foreach ($contained as $scope) {
                foreach ($closure[$scope] ?? [] as $required) {
                    if (! in_array($required, $contained, true)) {
                        throw new LogicException("Scope preset \"{$preset->id}\" contains scope \"{$scope}\" but not \"{$required}\", which it requires; presets must be closed under scope implications.");
                    }
                }
            }
        }
    }

    /**
     * Validates declared implications and returns each scope's transitive requirements.
     *
     * @param  array<string, string>  $catalog
     * @param  array<string, string>  $sensitive  scope => sensitive group id
     * @return array<string, list<string>>
     */
    private static function assertImplications(ScopePresentation $presentation, array $catalog, array $sensitive): array
    {
        if (! $presentation instanceof DeclaresScopeImplications) {
            return [];
        }

        $direct = [];
        foreach ($presentation->implications() as $scope => $required) {
            $scope = (string) $scope;
            if (! array_key_exists($scope, $catalog)) {
                throw new LogicException("Scope implication names scope \"{$scope}\", which is not in the scope catalog.");
            }
            foreach ($required as $need) {
                $need = (string) $need;
                if (! array_key_exists($need, $catalog)) {
                    throw new LogicException("Scope \"{$scope}\" requires scope \"{$need}\", which is not in the scope catalog.");
                }
                if ($need === $scope) {
                    throw new LogicException("Scope \"{$scope}\" requires itself.");
                }
                if (! isset($sensitive[$scope]) && isset($sensitive[$need])) {
                    throw new LogicException("Scope \"{$scope}\" requires scope \"{$need}\" from the sensitive group \"{$sensitive[$need]}\"; a routine scope must not pull in a sensitive one.");
                }
                $direct[$scope][$need] = true;
            }
        }
        $direct = array_map(static fn (array $needs): array => array_map('strval', array_keys($needs)), $direct);

        // Depth-first walk: 1 = on the current path, 2 = done.
        $state = [];
        $closure = [];
        $visit = static function (string $scope, array $path) use (&$visit, &$state, &$closure, $direct): array {
            if (($state[$scope] ?? 0) === 1) {
                $cycle = [...array_slice($path, (int) array_search($scope, $path, true)), $scope];
                throw new LogicException("Scope \"{$scope}\" is part of an implication cycle (".implode(' -> ', $cycle).').');
            }
            if (($state[$scope] ?? 0) === 2) {
                return $closure[$scope];
            }
            $state[$scope] = 1;
            $all = [];
            foreach ($direct[$scope] ?? [] as $need) {
                $all[$need] = true;
                foreach ($visit($need, [...$path, $scope]) as $deeper) {
                    $all[$deeper] = true;
                }
            }
            $state[$scope] = 2;

            return $closure[$scope] = array_map('strval', array_keys($all));
        };
        foreach (array_keys($direct) as $scope) {
            $visit((string) $scope, []);
        }

        return $closure;
    }

    private static function assertId(string $kind, string $id): void
    {
        if (preg_match(self::ID, $id) !== 1) {
            throw new LogicException("Scope {$kind} id \"{$id}\" must match [a-z0-9_]+.");
        }
    }
}
