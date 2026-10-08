<?php

namespace BWH\Auth\OAuth\Credentials;

use BWH\Auth\OAuth\Server\OAuthResourceIndicator;

/**
 * Default: the configured scope catalog, without the scopes that open an MCP
 * connection (`resource_required_scopes`) and without `credentials.excluded_scopes`.
 * A REST credential is never an MCP connection.
 */
final class ConfiguredGrantableScopes implements GrantableScopes
{
    public function scopes(): array
    {
        $catalog = config('bherila-auth.oauth_server.scopes', []);
        if (! is_array($catalog)) {
            return [];
        }
        $excluded = [
            ...OAuthResourceIndicator::requiredScopes(),
            ...array_map('strval', (array) config('bherila-auth.oauth_server.credentials.excluded_scopes', [])),
        ];

        // The catalog is `identifier => description`; a plain list uses the
        // identifier as its own description.
        $scopes = [];
        foreach ($catalog as $key => $value) {
            [$id, $description] = is_int($key) ? [(string) $value, (string) $value] : [(string) $key, (string) $value];
            if (! in_array($id, $excluded, true)) {
                $scopes[$id] = $description;
            }
        }

        return $scopes;
    }
}
