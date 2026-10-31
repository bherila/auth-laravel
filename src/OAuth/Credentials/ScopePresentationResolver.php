<?php

namespace BWH\Auth\OAuth\Credentials;

/** Resolves a bound ScopePresentation against the scopes one surface offers. */
final class ScopePresentationResolver
{
    /** The id of the generated group holding offered scopes no declared group names. Reserved. */
    public const UNGROUPED_ID = 'other';

    private bool $validated = false;

    public function __construct(private readonly ScopePresentation $presentation) {}

    /** Whether the bound presentation declares any group or preset. */
    public function active(): bool
    {
        return $this->presentation->groups() !== [] || $this->presentation->presets() !== [];
    }

    /**
     * @param  array<string, string>  $offered  scope id => description
     * @return list<array{id: string, label: string, description: ?string, sensitive: bool, scopes: list<string>}>
     */
    public function groups(array $offered): array
    {
        $this->validate();
        $declared = $this->presentation->groups();
        if ($declared === []) {
            return [];
        }

        $placed = [];
        $groups = [];
        foreach ($declared as $group) {
            $scopes = array_values(array_filter($group->scopes, static fn (string $scope): bool => array_key_exists($scope, $offered)));
            $placed = [...$placed, ...$scopes];
            if ($scopes !== []) {
                $groups[] = [
                    'id' => $group->id,
                    'label' => $group->label,
                    'description' => $group->description,
                    'sensitive' => $group->sensitive,
                    'scopes' => $scopes,
                ];
            }
        }

        // Catalog order first, then anything a custom binding offers beyond the catalog.
        // Array keys turn numeric scope ids into integers; the payload's ids are strings.
        $ordered = array_values(array_unique(array_map('strval', [...array_keys(ConfiguredGrantableScopes::catalog()), ...array_keys($offered)])));
        $other = array_values(array_filter(
            $ordered,
            static fn (string $scope): bool => array_key_exists($scope, $offered) && ! in_array($scope, $placed, true),
        ));
        if ($other !== []) {
            $groups[] = [
                'id' => self::UNGROUPED_ID,
                'label' => (string) config('bherila-auth.oauth_server.consent.ungrouped_label', 'Other permissions'),
                'description' => null,
                'sensitive' => false,
                'scopes' => $other,
            ];
        }

        return $groups;
    }

    /**
     * Only presets whose every scope is offered.
     *
     * @param  array<string, string>  $offered
     * @return list<array{id: string, label: string, description: string, scopes: list<string>}>
     */
    public function presets(array $offered): array
    {
        $this->validate();
        $presets = [];
        foreach ($this->presentation->presets() as $preset) {
            foreach ($preset->scopes as $scope) {
                if (! array_key_exists($scope, $offered)) {
                    continue 2;
                }
            }
            $presets[] = [
                'id' => $preset->id,
                'label' => $preset->label,
                'description' => $preset->description,
                'scopes' => array_values($preset->scopes),
            ];
        }

        return $presets;
    }

    /**
     * Declared implications as a transitive closure, in catalog order, restricted to
     * one surface: a key must be offered, a requirement must be offered, and an entry
     * left with no requirement is dropped. Empty unless the presentation declares any.
     *
     * @param  array<string, string>  $offered
     * @return array<string, list<string>>
     */
    public function implications(array $offered): array
    {
        $this->validate();
        if (! $this->presentation instanceof DeclaresScopeImplications) {
            return [];
        }

        $direct = [];
        foreach ($this->presentation->implications() as $scope => $required) {
            foreach ($required as $need) {
                $direct[(string) $scope][(string) $need] = true;
            }
        }
        // Memoized per scope: the graph is a validated DAG, but shared dependencies would
        // otherwise be walked once per path.
        $memo = [];
        $closure = static function (string $scope) use (&$closure, &$memo, $direct): array {
            if (isset($memo[$scope])) {
                return $memo[$scope];
            }
            $all = [];
            foreach (array_keys($direct[$scope] ?? []) as $need) {
                $need = (string) $need;
                $all[$need] = true;
                foreach ($closure($need) as $deeper) {
                    $all[$deeper] = true;
                }
            }

            return $memo[$scope] = array_map('strval', array_keys($all));
        };

        $ordered = array_values(array_unique(array_map('strval', [...array_keys(ConfiguredGrantableScopes::catalog()), ...array_keys($offered)])));
        $result = [];
        foreach ($ordered as $scope) {
            if (! array_key_exists($scope, $offered) || ! isset($direct[$scope])) {
                continue;
            }
            $needs = $closure($scope);
            $needed = array_flip($needs);
            $kept = array_values(array_filter($ordered, static fn (string $id): bool => isset($needed[$id]) && array_key_exists($id, $offered)));
            if ($kept !== []) {
                $result[$scope] = $kept;
            }
        }

        return $result;
    }

    private function validate(): void
    {
        if (! $this->validated) {
            ScopePresentationValidator::assertValid($this->presentation);
            $this->validated = true;
        }
    }
}
