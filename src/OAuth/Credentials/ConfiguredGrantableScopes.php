<?php

namespace BWH\Auth\OAuth\Credentials;

use BWH\Auth\OAuth\Server\OAuthResourceIndicator;

/**
 * Default: the configured scope catalog, without the scopes that open an MCP
 * connection (`resource_required_scopes`) and without `credentials.excluded_scopes`.
 * A REST credential is never an MCP connection - unless the application opts
 * personal API tokens in with `credentials.personal_token_connection_scopes`,
 * which ApiCredentialService adds on top of this set (never to OAuth apps).
 */
final class ConfiguredGrantableScopes implements GrantableScopes
{
    public function scopes(): array
    {
        $excluded = [
            ...OAuthResourceIndicator::requiredScopes(),
            ...self::excludedScopes(),
        ];

        return array_filter(
            self::catalog(),
            static fn (int|string $id): bool => ! in_array((string) $id, $excluded, true),
            ARRAY_FILTER_USE_KEY,
        );
    }

    /**
     * The application's whole scope catalog, `identifier => description`; a
     * plain list uses the identifier as its own description.
     *
     * @return array<string, string>
     */
    public static function catalog(): array
    {
        $catalog = config('bherila-auth.oauth_server.scopes', []);
        if (! is_array($catalog)) {
            return [];
        }

        $scopes = [];
        foreach ($catalog as $key => $value) {
            [$id, $description] = is_int($key) ? [(string) $value, (string) $value] : [(string) $key, (string) $value];
            $scopes[$id] = $description;
        }

        return $scopes;
    }

    /**
     * `credentials.excluded_scopes`: never offered to any credential.
     *
     * @return list<string>
     */
    public static function excludedScopes(): array
    {
        return array_values(array_map('strval', (array) config('bherila-auth.oauth_server.credentials.excluded_scopes', [])));
    }
}
