<?php

namespace BWH\Auth\Http\Controllers;

use BWH\Auth\OAuth\Server\AgentOAuthServer;
use BWH\Auth\OAuth\Server\OAuthProtectedResource;
use BWH\Auth\OAuth\Server\OAuthResourceIndicator;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use RuntimeException;

final class OAuthMetadataController
{
    public function authorizationServer(): JsonResponse
    {
        if (! $this->enabled()) {
            return $this->notFound();
        }

        $metadata = [
            'issuer' => OAuthResourceIndicator::issuer(),
            'authorization_endpoint' => $this->requiredUrl('authorization_endpoint'),
            'token_endpoint' => $this->requiredUrl('token_endpoint'),
            'grant_types_supported' => ['authorization_code', 'refresh_token'],
            'response_types_supported' => ['code'],
            'code_challenge_methods_supported' => ['S256'],
            'scopes_supported' => $this->scopes(),
        ];

        $tokenEndpointAuthMethods = $this->tokenEndpointAuthMethods();
        if ($tokenEndpointAuthMethods !== []) {
            $metadata['token_endpoint_auth_methods_supported'] = $tokenEndpointAuthMethods;
        }

        $registrationEndpoint = $this->optionalUrl('registration_endpoint');
        if ($this->dynamicClientsEnabled($tokenEndpointAuthMethods) && $registrationEndpoint !== '') {
            $metadata['registration_endpoint'] = $registrationEndpoint;
        }

        if (config('bherila-auth.oauth_server.authorization_response_issuer.enabled', false)) {
            $metadata['authorization_response_iss_parameter_supported'] = true;
        }

        return $this->publicJson($metadata);
    }

    public function protectedResource(Request $request): JsonResponse
    {
        if (! $this->enabled()) {
            return $this->notFound();
        }
        // Each resource's document is routed at that resource's own well-known path.
        $resource = $request->route()?->defaults[AgentOAuthServer::RESOURCE_ROUTE_DEFAULT] ?? null;

        return OAuthProtectedResource::metadataResponse(null, is_string($resource) ? $resource : null);
    }

    private function enabled(): bool
    {
        return (bool) config('bherila-auth.oauth_server.enabled', false);
    }

    /** @return list<string> */
    private function scopes(): array
    {
        $scopes = config('bherila-auth.oauth_server.scopes', []);
        if (! is_array($scopes)) {
            return [];
        }

        return OAuthResourceIndicator::scopeIdentifiers(
            array_is_list($scopes) ? $scopes : array_keys($scopes),
        );
    }

    /** @return list<string> */
    private function tokenEndpointAuthMethods(): array
    {
        $methods = config('bherila-auth.oauth_server.token_endpoint_auth_methods', ['none']);
        if (! is_array($methods)) {
            return [];
        }

        $supported = ['none', 'client_secret_basic', 'client_secret_post'];
        $methods = array_values(array_unique(array_filter(
            $methods,
            static fn (mixed $method): bool => is_string($method) && in_array($method, $supported, true),
        )));

        return $methods;
    }

    /** @param list<string> $tokenEndpointAuthMethods */
    private function dynamicClientsEnabled(array $tokenEndpointAuthMethods): bool
    {
        return (bool) config('bherila-auth.oauth_server.dynamic_clients.enabled', true)
            && in_array('none', $tokenEndpointAuthMethods, true);
    }

    private function requiredUrl(string $key): string
    {
        $value = config("bherila-auth.oauth_server.{$key}");
        $url = OAuthResourceIndicator::absoluteHttpUrl($value);
        if ($url === null) {
            throw new RuntimeException("The OAuth {$key} is not configured.");
        }

        return $url;
    }

    private function optionalUrl(string $key): string
    {
        $value = config("bherila-auth.oauth_server.{$key}");

        return OAuthResourceIndicator::absoluteHttpUrl($value) ?? '';
    }

    /** @param array<string, mixed> $payload */
    private function publicJson(array $payload): JsonResponse
    {
        return response()->json($payload)->withHeaders([
            'Cache-Control' => 'public, max-age=300',
            'X-Content-Type-Options' => 'nosniff',
        ]);
    }

    private function notFound(): JsonResponse
    {
        return response()->json(['error' => 'not_found'], 404, [
            'Cache-Control' => 'no-store',
            'Pragma' => 'no-cache',
            'X-Content-Type-Options' => 'nosniff',
        ]);
    }
}
