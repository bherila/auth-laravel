<?php

namespace BWH\Auth\OAuth\Credentials;

/**
 * Optional grouping, sensitivity and presets for the scopes a credential UI
 * and the consent screen show. Bind an implementation to opt in; the default
 * (UngroupedScopePresentation) leaves every payload and the consent markup as
 * they were.
 */
interface ScopePresentation
{
    /** @return list<ScopeGroup> */
    public function groups(): array;

    /** @return list<ScopePreset> */
    public function presets(): array;
}
