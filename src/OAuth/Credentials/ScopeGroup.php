<?php

namespace BWH\Auth\OAuth\Credentials;

/**
 * A named set of scopes shown together in a credential UI and on the consent
 * screen. Presentation only: a grant always stores explicit scopes.
 */
final readonly class ScopeGroup
{
    /** @param list<string> $scopes declared order is display order */
    public function __construct(
        public string $id,
        public string $label,
        public array $scopes,
        public bool $sensitive = false,
        public ?string $description = null,
    ) {}
}
