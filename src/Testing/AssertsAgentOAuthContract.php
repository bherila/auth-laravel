<?php

namespace BWH\Auth\Testing;

use BWH\Auth\OAuth\Server\OAuthResourceIndicator;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Testing\TestResponse;

/**
 * Assert the agent-API OAuth contract against an application's own routes.
 *
 * Use in a feature test of an application configured with the agent preset.
 * It drives the flow a generic connector uses - self-registration, S256 PKCE,
 * no `resource` parameter - and checks the credentials are bound to the
 * configured resource and accepted by a protected route.
 *
 * @mixin \Illuminate\Foundation\Testing\TestCase
 */
trait AssertsAgentOAuthContract
{
    protected function assertAgentOAuthDiscovery(): void
    {
        $issuer = (string) config('bherila-auth.oauth_server.issuer');
        $resource = (string) config('bherila-auth.oauth_server.resource');

        $this->getJson('/.well-known/oauth-authorization-server')->assertOk()
            ->assertJsonPath('issuer', $issuer)
            ->assertJsonPath('code_challenge_methods_supported', ['S256']);
        // The route the preset registers, relative to the (possibly path-mounted) application.
        $this->getJson(\BWH\Auth\OAuth\Server\AgentOAuthServer::protectedResourceMetadataPath())->assertOk()
            ->assertJsonPath('resource', $resource);
    }

    /**
     * Self-register a public client, complete the code flow without `resource`,
     * call a protected route, refresh, and return the final token response.
     *
     * @return array<string, mixed>
     */
    protected function assertAgentOAuthLifecycle(Authenticatable $user, string $scope, string $protectedPath, string $redirectUri = 'http://127.0.0.1:3210/callback'): array
    {
        $resource = (string) config('bherila-auth.oauth_server.resource');
        $clientId = $this->postJson('/oauth/register', [
            'client_name' => 'Contract test client',
            'redirect_uris' => [$redirectUri],
            'grant_types' => ['authorization_code', 'refresh_token'],
            'response_types' => ['code'],
            'token_endpoint_auth_method' => 'none',
            'scope' => $scope,
        ])->assertCreated()->assertJsonMissingPath('client_secret')->json('client_id');

        $tokens = $this->agentOAuthCodeFlow($user, (string) $clientId, $scope, $redirectUri)->assertOk()->json();
        $this->assertSame($resource, OAuthResourceIndicator::tokenClaims((string) $tokens['access_token'])['resource'] ?? null, 'The access token is bound to the configured resource');
        $this->app['auth']->forgetGuards();
        $this->getJson($protectedPath, ['Authorization' => 'Bearer '.$tokens['access_token']])->assertSuccessful();

        $refreshed = $this->post('/oauth/token', [
            'grant_type' => 'refresh_token',
            'client_id' => $clientId,
            'refresh_token' => $tokens['refresh_token'],
        ], ['Accept' => 'application/json'])->assertOk()->json();
        $this->assertSame($resource, OAuthResourceIndicator::tokenClaims((string) $refreshed['access_token'])['resource'] ?? null, 'The refreshed token is bound to the configured resource');

        return $refreshed;
    }

    /**
     * Follow a protected endpoint's own bearer challenge to its metadata, as a strict
     * RFC 9728 client does, and assert the document describes exactly that endpoint's
     * resource. Run it for every endpoint and alias an agent can be pointed at.
     */
    protected function assertProtectedResourceChallenge(string $method, string $path, string $expectedResource): void
    {
        $this->app['auth']->forgetGuards();
        $challenge = $this->json($method, $path)->assertUnauthorized()->headers->get('WWW-Authenticate');
        $this->assertIsString($challenge, "{$path} answers 401 with a bearer challenge");
        $this->assertSame(1, preg_match('/resource_metadata="([^"]+)"/', $challenge, $match), "{$path}'s challenge names its resource metadata");
        $metadataUrl = $match[1];
        $this->assertSame(\BWH\Auth\OAuth\Server\OAuthProtectedResource::wellKnownFor($expectedResource), $metadataUrl,
            "{$path}'s metadata is at the path-inserted well-known URL of its own resource");

        $document = $this->getJson((string) parse_url($metadataUrl, PHP_URL_PATH))->assertOk()->json();
        $this->assertSame($expectedResource, $document['resource'] ?? null,
            "The metadata reached from {$path} names that resource exactly (RFC 9728 section 3.3)");
        $this->assertContains((string) config('bherila-auth.oauth_server.issuer'), $document['authorization_servers'] ?? []);
    }

    /**
     * Authorize (approving consent unless Passport already holds it) and
     * exchange the code with PKCE and no `resource`.
     *
     * @param  array<string, string>  $tokenExtras  e.g. ['client_secret' => ...]
     * @return TestResponse<\Symfony\Component\HttpFoundation\Response>
     */
    protected function agentOAuthCodeFlow(Authenticatable $user, string $clientId, string $scope, string $redirectUri, array $tokenExtras = []): TestResponse
    {
        $verifier = rtrim(strtr(base64_encode(random_bytes(48)), '+/', '-_'), '=');
        $authorize = $this->actingAs($user)->get('/oauth/authorize?'.http_build_query([
            'response_type' => 'code',
            'client_id' => $clientId,
            'redirect_uri' => $redirectUri,
            'scope' => $scope,
            'state' => 'contract-state',
            'code_challenge' => rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '='),
            'code_challenge_method' => 'S256',
        ]));
        $approval = $authorize->isRedirect()
            ? $authorize
            : $this->actingAs($user)->post('/oauth/authorize', ['auth_token' => (string) session('authToken')])->assertRedirect();
        parse_str((string) parse_url((string) $approval->headers->get('Location'), PHP_URL_QUERY), $query);
        $this->assertArrayHasKey('code', $query, 'Authorization returned a code: '.(string) $approval->headers->get('Location'));

        return $this->post('/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => $clientId,
            'redirect_uri' => $redirectUri,
            'code' => $query['code'],
            'code_verifier' => $verifier,
            ...$tokenExtras,
        ], ['Accept' => 'application/json']);
    }
}
