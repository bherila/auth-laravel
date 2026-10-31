<?php

namespace BWH\Auth\OAuth\Credentials;

/** Resolves a bound ScopePresentation against the scopes one surface offers. */
final class ScopePresentationResolver
{
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
        $ordered = array_values(array_unique([...array_keys(ConfiguredGrantableScopes::catalog()), ...array_keys($offered)]));
        $other = array_values(array_filter(
            $ordered,
            static fn (string $scope): bool => array_key_exists($scope, $offered) && ! in_array($scope, $placed, true),
        ));
        if ($other !== []) {
            $groups[] = [
                'id' => 'other',
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

    private function validate(): void
    {
        if (! $this->validated) {
            ScopePresentationValidator::assertValid($this->presentation);
            $this->validated = true;
        }
    }
}
