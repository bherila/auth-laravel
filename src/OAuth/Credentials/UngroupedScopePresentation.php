<?php

namespace BWH\Auth\OAuth\Credentials;

/** Default: no groups and no presets. */
final class UngroupedScopePresentation implements ScopePresentation
{
    public function groups(): array
    {
        return [];
    }

    public function presets(): array
    {
        return [];
    }
}
