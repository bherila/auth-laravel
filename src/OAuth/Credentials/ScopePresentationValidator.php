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
        }
    }

    private static function assertId(string $kind, string $id): void
    {
        if (preg_match(self::ID, $id) !== 1) {
            throw new LogicException("Scope {$kind} id \"{$id}\" must match [a-z0-9_]+.");
        }
    }
}
