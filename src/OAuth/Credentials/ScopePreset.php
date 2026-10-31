<?php

namespace BWH\Auth\OAuth\Credentials;

/**
 * A named set of scopes a credential UI can tick in one click. Presentation
 * only: no endpoint accepts a preset id, and it may not contain a scope from a
 * sensitive group.
 */
final readonly class ScopePreset
{
    /** @param list<string> $scopes */
    public function __construct(
        public string $id,
        public string $label,
        public string $description,
        public array $scopes,
    ) {}
}
