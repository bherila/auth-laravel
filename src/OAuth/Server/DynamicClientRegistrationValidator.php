<?php

namespace BWH\Auth\OAuth\Server;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use JsonException;

final class DynamicClientRegistrationValidator
{
    private const MAX_BODY_BYTES = 16_384;

    /**
     * @param  list<string>  $allowedScopes
     *
     * @throws InvalidClientMetadata
     */
    public function validate(Request $request, array $allowedScopes): DynamicClientRegistration
    {
        if (! $request->isJson() || strlen((string) $request->getContent()) > self::MAX_BODY_BYTES) {
            throw new InvalidClientMetadata('Client registration requires a bounded JSON request.');
        }

        // RFC 7591 requires unknown client metadata to be ignored. Validate the
        // fields this server acts on without rejecting harmless harness metadata.
        try {
            $metadata = json_decode((string) $request->getContent(), true, 64, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            throw new InvalidClientMetadata('Client registration requires a JSON object.');
        }
        if (! is_array($metadata)) {
            throw new InvalidClientMetadata('Client registration requires a JSON object.');
        }
        $validator = Validator::make($metadata, [
            'client_name' => ['required', 'string', 'min:1', 'max:100'],
            'redirect_uris' => ['required', 'array', 'min:1', 'max:10'],
            'redirect_uris.*' => ['required', 'string', 'max:2048'],
            'grant_types' => ['sometimes', 'array', 'size:2'],
            'grant_types.*' => ['string', 'in:authorization_code,refresh_token'],
            'response_types' => ['sometimes', 'array', 'size:1'],
            'response_types.*' => ['string', 'in:code'],
            // Every method the metadata document may advertise is accepted on
            // request, but a self-registered client is always public: RFC 7591
            // section 3.2.1 lets the server replace requested metadata, and the
            // response states `none`. Clients built on the MCP SDKs ask for
            // `client_secret_post` by default and follow the method returned.
            'token_endpoint_auth_method' => ['sometimes', 'string', 'in:none,client_secret_basic,client_secret_post'],
            // An explicitly empty scope is meaningful: it registers a client with
            // no requested scopes. Omission means the authorization server's
            // configured catalog remains the upper bound.
            'scope' => ['sometimes', 'string', 'max:2048'],
            'application_type' => ['sometimes', 'string', 'in:native,web'],
        ]);
        if ($validator->fails()) {
            throw self::invalid(array_keys($validator->failed()));
        }

        $metadata = $validator->validated();
        $grantTypes = array_values(array_unique($metadata['grant_types'] ?? ['authorization_code', 'refresh_token']));
        sort($grantTypes);
        $responseTypes = array_values(array_unique($metadata['response_types'] ?? ['code']));
        if ($grantTypes !== ['authorization_code', 'refresh_token']) {
            throw self::invalid(['grant_types']);
        }
        if ($responseTypes !== ['code']) {
            throw self::invalid(['response_types']);
        }

        $clientName = trim((string) $metadata['client_name']);
        if ($clientName === '' || preg_match('/[\p{C}]/u', $clientName) !== 0) {
            throw self::invalid(['client_name']);
        }

        $applicationType = isset($metadata['application_type'])
            ? (string) $metadata['application_type']
            : null;
        $redirectUris = [];
        foreach ($metadata['redirect_uris'] as $redirectUri) {
            if (! is_string($redirectUri) || ! $this->validRedirectUri($redirectUri, $applicationType)) {
                throw self::invalid(['redirect_uris']);
            }
            $redirectUris[] = $redirectUri;
        }
        $redirectUris = array_values(array_unique($redirectUris));
        if ($redirectUris === []) {
            throw self::invalid(['redirect_uris']);
        }

        // An omitted scope uses the application catalog as the client's explicit
        // upper bound. This keeps a nullable registration field from becoming an
        // accidental scope-escalation escape hatch.
        $scopes = $allowedScopes;
        if (array_key_exists('scope', $metadata)) {
            $scopes = self::parseScopes((string) $metadata['scope']);
            if (array_diff($scopes, $allowedScopes) !== []) {
                throw self::invalid(['scope']);
            }
        }

        return new DynamicClientRegistration(
            clientName: $clientName,
            redirectUris: $redirectUris,
            scopes: $scopes,
            applicationType: $applicationType,
        );
    }

    /**
     * A refusal that names the metadata fields at fault, never their values, so
     * a client developer (or an operator reading a connector's error) can tell
     * which field to change without the response reflecting caller input.
     *
     * @param  list<int|string>  $fields
     */
    private static function invalid(array $fields): InvalidClientMetadata
    {
        $names = array_values(array_unique(array_map(
            static fn (int|string $field): string => explode('.', (string) $field)[0],
            $fields,
        )));
        sort($names);

        return new InvalidClientMetadata('Client metadata is invalid: '.implode(', ', $names).'.');
    }

    /** @return list<string> */
    public static function parseScopes(string $value): array
    {
        return array_values(array_unique(array_filter(
            preg_split('/\s+/', trim($value)) ?: [],
            static fn (string $scope): bool => $scope !== '',
        )));
    }

    private function validRedirectUri(string $redirectUri, ?string $applicationType): bool
    {
        if (filter_var($redirectUri, FILTER_VALIDATE_URL) === false) {
            return false;
        }

        try {
            $parts = parse_url($redirectUri);
        } catch (\ValueError) {
            return false;
        }
        if (! is_array($parts)
            || ! isset($parts['scheme'], $parts['host'])
            || isset($parts['fragment'])
            || isset($parts['user'])
            || isset($parts['pass'])) {
            return false;
        }
        if (isset($parts['port']) && ((int) $parts['port'] < 1 || (int) $parts['port'] > 65535)) {
            return false;
        }

        $scheme = strtolower((string) $parts['scheme']);
        $host = strtolower((string) $parts['host']);

        return $scheme === 'https'
            || ($applicationType !== 'web'
                && $scheme === 'http'
                && in_array($host, ['localhost', '127.0.0.1', '[::1]'], true));
    }
}
