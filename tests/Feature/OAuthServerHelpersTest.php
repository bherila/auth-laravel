<?php

namespace BWH\Auth\Tests\Feature;

use BWH\Auth\Http\Controllers\OAuthMetadataController;
use BWH\Auth\Http\Middleware\EnsureOAuthServerEnabled;
use BWH\Auth\Http\Middleware\EnforceOAuthPkce;
use BWH\Auth\Http\Middleware\EnforceOAuthResourceIndicator;
use BWH\Auth\OAuth\Server\DynamicClientRegistrationValidator;
use BWH\Auth\OAuth\Server\InvalidClientMetadata;
use BWH\Auth\OAuth\Server\OAuthAuthorizationStateStore;
use BWH\Auth\OAuth\Server\OAuthAuthorizationResponseIssuer;
use BWH\Auth\OAuth\Server\OAuthProtectedResource;
use BWH\Auth\OAuth\Server\OAuthResourceIndicator;
use BWH\Auth\Tests\TestCase;
use Illuminate\Http\Request;
use Illuminate\Http\Exceptions\HttpResponseException;
use Illuminate\Routing\Route as RoutingRoute;
use Illuminate\Support\Facades\Route;
use Laravel\Passport\Passport;
use PHPUnit\Framework\Attributes\DataProvider;

class OAuthServerHelpersTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        config([
            'app.name' => 'Synthetic App',
            'bherila-auth.oauth_server' => [
                'enabled' => true,
                'issuer' => 'https://auth.example.test',
                'resource' => 'https://auth.example.test/api/v1',
                'authorization_endpoint' => 'https://auth.example.test/oauth/authorize',
                'token_endpoint' => 'https://auth.example.test/oauth/token',
                'registration_endpoint' => 'https://auth.example.test/oauth/register',
                'scopes' => [
                    'identity:read' => 'Read identity',
                    'mcp:use' => 'Connect through MCP',
                ],
                'token_endpoint_auth_methods' => ['none'],
                'protected_resource_metadata_url' => 'https://auth.example.test/.well-known/oauth-protected-resource/api/v1/mcp',
                'resource_required_scope' => 'mcp:use',
                'dynamic_clients' => [
                    'enabled' => true,
                    'enforce_registered_scopes' => false,
                ],
                'authorization_state' => [
                    'cache_prefix' => 'test-oauth-resource:',
                    'ttl_seconds' => 300,
                ],
                'consent' => [
                    'app_name' => 'Synthetic App',
                    'heading' => 'Connect :client to :app?',
                    'intro' => 'Request access to :app.',
                    'identity' => true,
                    'trust_warning' => 'Trust this client only if you recognize it.',
                    'dynamic_client_warning' => 'This client registered automatically. Return to:',
                    'policy_notice' => 'Existing permissions continue to apply.',
                    'approve_label' => 'Authorize',
                    'deny_label' => 'Cancel',
                ],
            ],
        ]);

        Route::post('/oauth/approve-test', fn () => 'approved')
            ->name('passport.authorizations.approve');
        Route::delete('/oauth/deny-test', fn () => 'denied')
            ->name('passport.authorizations.deny');
        Route::get('/metadata/authorization-test', [OAuthMetadataController::class, 'authorizationServer']);
        Route::get('/metadata/resource-test', [OAuthMetadataController::class, 'protectedResource']);
        Route::get('/oauth/enabled-test', fn () => response()->json(['enabled' => true]))
            ->middleware(EnsureOAuthServerEnabled::class);
    }

    public function test_metadata_is_built_from_the_application_scope_catalog(): void
    {
        $this->getJson('/metadata/authorization-test')
            ->assertOk()
            ->assertExactJson([
                'issuer' => 'https://auth.example.test',
                'authorization_endpoint' => 'https://auth.example.test/oauth/authorize',
                'token_endpoint' => 'https://auth.example.test/oauth/token',
                'registration_endpoint' => 'https://auth.example.test/oauth/register',
                'grant_types_supported' => ['authorization_code', 'refresh_token'],
                'response_types_supported' => ['code'],
                'code_challenge_methods_supported' => ['S256'],
                'token_endpoint_auth_methods_supported' => ['none'],
                'scopes_supported' => ['identity:read', 'mcp:use'],
            ]);
        $this->assertStringContainsString('public', (string) $this->get('/metadata/authorization-test')->headers->get('Cache-Control'));

        config(['bherila-auth.oauth_server.dynamic_clients.enabled' => false]);
        $this->getJson('/metadata/authorization-test')->assertJsonMissingPath('registration_endpoint');
        config(['bherila-auth.oauth_server.dynamic_clients.enabled' => true]);

        config(['bherila-auth.oauth_server.registration_endpoint' => 'not-a-url']);
        $this->getJson('/metadata/authorization-test')->assertJsonMissingPath('registration_endpoint');
        config(['bherila-auth.oauth_server.registration_endpoint' => 'https://auth.example.test/oauth/register']);

        config(['bherila-auth.oauth_server.authorization_response_issuer.enabled' => true]);
        $this->getJson('/metadata/authorization-test')
            ->assertJsonPath('authorization_response_iss_parameter_supported', true);
        config(['bherila-auth.oauth_server.authorization_response_issuer.enabled' => false]);

        $this->getJson('/metadata/resource-test')->assertOk()->assertExactJson([
            'resource' => 'https://auth.example.test/api/v1',
            'authorization_servers' => ['https://auth.example.test'],
            'scopes_supported' => ['identity:read', 'mcp:use'],
            'bearer_methods_supported' => ['header'],
        ]);

        config(['bherila-auth.oauth_server.protected_resource_metadata_url' => null]);
        $this->assertSame(
            'https://auth.example.test/.well-known/oauth-protected-resource/api/v1',
            OAuthProtectedResource::metadataUrl(),
        );
        config(['bherila-auth.oauth_server.protected_resource_metadata_url' => 'https://auth.example.test/.well-known/oauth-protected-resource/api/v1/mcp']);

        config([
            'bherila-auth.oauth_server.issuer' => 'https://auth.example.test/tenant/',
            'bherila-auth.oauth_server.resource' => 'https://auth.example.test/api/v1/',
        ]);
        $this->getJson('/metadata/authorization-test')
            ->assertJsonPath('issuer', 'https://auth.example.test/tenant/');
        $this->getJson('/metadata/resource-test')
            ->assertJsonPath('resource', 'https://auth.example.test/api/v1/');
        $this->assertSame('https://auth.example.test/api/v1/', OAuthResourceIndicator::resource());
        $this->assertTrue(OAuthResourceIndicator::isConfiguredResource('https://auth.example.test/api/v1/'));

        config([
            'bherila-auth.oauth_server.issuer' => 'https://auth.example.test',
            'bherila-auth.oauth_server.resource' => 'https://auth.example.test/api/v1',
        ]);
    }

    public function test_metadata_is_not_advertised_when_the_oauth_server_is_disabled(): void
    {
        config(['bherila-auth.oauth_server.enabled' => false]);

        $authorization = $this->getJson('/metadata/authorization-test')
            ->assertNotFound()
            ->assertExactJson(['error' => 'not_found']);
        $this->assertStringContainsString('no-store', (string) $authorization->headers->get('Cache-Control'));

        $protectedResource = $this->getJson('/metadata/resource-test')
            ->assertNotFound()
            ->assertExactJson(['error' => 'not_found']);
        $this->assertStringContainsString('no-store', (string) $protectedResource->headers->get('Cache-Control'));
    }

    public function test_application_oauth_routes_can_fail_closed_when_the_server_is_disabled(): void
    {
        $this->getJson('/oauth/enabled-test')->assertOk()->assertExactJson(['enabled' => true]);

        config(['bherila-auth.oauth_server.enabled' => false]);

        $disabled = $this->getJson('/oauth/enabled-test')
            ->assertNotFound()
            ->assertExactJson(['error' => 'not_found'])
            ->assertHeader('Pragma', 'no-cache')
            ->assertHeader('X-Content-Type-Options', 'nosniff');
        $this->assertStringContainsString('no-store', (string) $disabled->headers->get('Cache-Control'));
    }

    public function test_dynamic_registration_accepts_codex_native_metadata_and_ignores_unknown_fields(): void
    {
        $request = $this->jsonRequest([
            'client_name' => 'Codex CLI',
            'redirect_uris' => ['http://127.0.0.1:1455/callback'],
            'grant_types' => ['refresh_token', 'authorization_code'],
            'response_types' => ['code'],
            'token_endpoint_auth_method' => 'none',
            'scope' => 'mcp:use identity:read',
            'application_type' => 'native',
            'software_id' => 'ignored-standard-metadata',
        ]);

        $registration = app(DynamicClientRegistrationValidator::class)->validate(
            $request,
            ['identity:read', 'mcp:use'],
        );

        $this->assertSame('Codex CLI', $registration->clientName);
        $this->assertSame(['http://127.0.0.1:1455/callback'], $registration->redirectUris);
        $this->assertSame(['mcp:use', 'identity:read'], $registration->scopes);
        $this->assertSame('native', $registration->applicationType);
        $this->assertSame('mcp:use identity:read', $registration->responseMetadata('client-id', 123)['scope']);
    }

    public function test_dynamic_registration_accepts_a_hosted_public_client_with_an_https_redirect(): void
    {
        $registration = app(DynamicClientRegistrationValidator::class)->validate(
            $this->jsonRequest([
                'client_name' => 'ChatGPT',
                'redirect_uris' => ['https://chatgpt.com/connector_platform_oauth_redirect'],
                'grant_types' => ['authorization_code', 'refresh_token'],
                'response_types' => ['code'],
                'token_endpoint_auth_method' => 'none',
                'application_type' => 'web',
                'scope' => 'mcp:use',
            ]),
            ['identity:read', 'mcp:use'],
        );

        $this->assertSame('ChatGPT', $registration->clientName);
        $this->assertSame('web', $registration->applicationType);
        $this->assertSame(['https://chatgpt.com/connector_platform_oauth_redirect'], $registration->redirectUris);
        $this->assertSame(['mcp:use'], $registration->scopes);
    }

    /**
     * The MCP SDKs register with `client_secret_post` unless told otherwise, and
     * the metadata document advertises it. Registration accepts the request but
     * still creates a public client, and says so in the response.
     */
    #[DataProvider('secretAuthMethodProvider')]
    public function test_dynamic_registration_accepts_a_requested_secret_method_as_a_public_client(string $method): void
    {
        $registration = app(DynamicClientRegistrationValidator::class)->validate(
            $this->jsonRequest([
                'client_name' => 'Claude',
                'redirect_uris' => ['https://claude.ai/api/mcp/auth_callback'],
                'grant_types' => ['authorization_code', 'refresh_token'],
                'response_types' => ['code'],
                'token_endpoint_auth_method' => $method,
                'scope' => 'mcp:use',
            ]),
            ['identity:read', 'mcp:use'],
        );

        $metadata = $registration->responseMetadata('client-id', 123);
        $this->assertSame('none', $metadata['token_endpoint_auth_method']);
        $this->assertArrayNotHasKey('client_secret', $metadata);
        $this->assertSame(['mcp:use'], $registration->scopes);
    }

    /** @return iterable<string, array{string}> */
    public static function secretAuthMethodProvider(): iterable
    {
        yield 'client_secret_post' => ['client_secret_post'];
        yield 'client_secret_basic' => ['client_secret_basic'];
    }

    public function test_a_refusal_names_the_fields_at_fault_without_their_values(): void
    {
        try {
            app(DynamicClientRegistrationValidator::class)->validate(
                $this->jsonRequest([
                    'client_name' => 'Synthetic Client',
                    'redirect_uris' => ['https://client.example.test/callback'],
                    'token_endpoint_auth_method' => 'private_key_jwt',
                    'scope' => 'mcp:use',
                ]),
                ['mcp:use'],
            );
            $this->fail('An unsupported auth method must be refused.');
        } catch (InvalidClientMetadata $exception) {
            $this->assertSame('Client metadata is invalid: token_endpoint_auth_method.', $exception->getMessage());
        }

        try {
            app(DynamicClientRegistrationValidator::class)->validate(
                $this->jsonRequest([
                    'client_name' => 'Synthetic Client',
                    'redirect_uris' => ['https://client.example.test/callback'],
                    'scope' => 'mcp:use records:delete',
                ]),
                ['mcp:use'],
            );
            $this->fail('An unknown scope must be refused.');
        } catch (InvalidClientMetadata $exception) {
            $this->assertSame('Client metadata is invalid: scope.', $exception->getMessage());
            $this->assertStringNotContainsString('records:delete', $exception->getMessage());
        }
    }

    public function test_empty_scope_is_distinct_from_an_omitted_scope(): void
    {
        $empty = app(DynamicClientRegistrationValidator::class)->validate(
            $this->jsonRequest([
                'client_name' => 'No Scope Client',
                'redirect_uris' => ['https://client.example.test/callback'],
                'scope' => '',
            ]),
            ['identity:read', 'mcp:use'],
        );
        $omitted = app(DynamicClientRegistrationValidator::class)->validate(
            $this->jsonRequest([
                'client_name' => 'Catalog Client',
                'redirect_uris' => ['https://client.example.test/callback'],
            ]),
            ['identity:read', 'mcp:use'],
        );

        $this->assertSame([], $empty->scopes);
        $this->assertSame(['identity:read', 'mcp:use'], $omitted->scopes);
        $this->assertSame('', $empty->responseMetadata('client-id', 123)['scope']);
        $this->assertSame(
            'identity:read mcp:use',
            $omitted->responseMetadata('client-id', 123)['scope'],
        );
    }

    public function test_dynamic_registration_body_is_bounded(): void
    {
        $this->expectException(InvalidClientMetadata::class);

        app(DynamicClientRegistrationValidator::class)->validate(
            Request::create(
                '/oauth/register',
                'POST',
                server: ['CONTENT_TYPE' => 'application/json'],
                content: str_repeat('x', 16_385),
            ),
            ['identity:read', 'mcp:use'],
        );
    }

    public function test_dynamic_registration_requires_a_json_object(): void
    {
        $this->expectException(InvalidClientMetadata::class);

        app(DynamicClientRegistrationValidator::class)->validate(
            Request::create(
                '/oauth/register',
                'POST',
                server: ['CONTENT_TYPE' => 'application/json'],
                content: 'null',
            ),
            ['identity:read', 'mcp:use'],
        );
    }

    #[DataProvider('invalidRegistrationProvider')]
    public function test_dynamic_registration_rejects_unsafe_or_unsupported_metadata(array $metadata): void
    {
        $this->expectException(InvalidClientMetadata::class);

        app(DynamicClientRegistrationValidator::class)->validate(
            $this->jsonRequest($metadata),
            ['identity:read', 'mcp:use'],
        );
    }

    /** @return iterable<string, array{array<string, mixed>}> */
    public static function invalidRegistrationProvider(): iterable
    {
        $valid = [
            'client_name' => 'Synthetic Client',
            'redirect_uris' => ['https://client.example.test/callback'],
            'grant_types' => ['authorization_code', 'refresh_token'],
            'response_types' => ['code'],
            'token_endpoint_auth_method' => 'none',
        ];

        yield 'non-loopback HTTP' => [[...$valid, 'redirect_uris' => ['http://client.example.test/callback']]];
        yield 'invalid port' => [[...$valid, 'redirect_uris' => ['http://127.0.0.1:0/callback']]];
        yield 'fragment' => [[...$valid, 'redirect_uris' => ['https://client.example.test/callback#fragment']]];
        yield 'unknown scope' => [[...$valid, 'scope' => 'mcp:use records:delete']];
        yield 'unsupported auth method' => [[...$valid, 'token_endpoint_auth_method' => 'private_key_jwt']];
        yield 'web application type with loopback redirect' => [[
            ...$valid,
            'application_type' => 'web',
            'redirect_uris' => ['http://127.0.0.1:1455/callback'],
        ]];
        yield 'control character in name' => [[...$valid, 'client_name' => "Synthetic\nClient"]];
    }

    public function test_pkce_middleware_fails_locally_without_reflecting_caller_input(): void
    {
        $request = Request::create('/oauth/authorize', 'GET', [
            'code_challenge' => 'synthetic',
            'code_challenge_method' => 'plain',
            'redirect_uri' => 'https://untrusted.example.test/callback',
        ]);
        $request->setRouteResolver(static function (): RoutingRoute {
            return (new RoutingRoute('GET', '/oauth/authorize', fn () => 'next'))
                ->name('passport.authorizations.authorize');
        });

        $response = app(EnforceOAuthPkce::class)->handle($request, fn () => response('next'));

        $this->assertSame(400, $response->getStatusCode());
        $this->assertStringNotContainsString('untrusted.example.test', (string) $response->getContent());
        $this->assertStringContainsString('no-store', (string) $response->headers->get('Cache-Control'));
    }

    public function test_resource_middleware_applies_default_scopes_and_rejects_unconfigured_token_targets(): void
    {
        Passport::defaultScopes(['mcp:use']);

        try {
            $authorization = Request::create('/oauth/authorize', 'GET');
            $authorization->setRouteResolver(static function (): RoutingRoute {
                return (new RoutingRoute('GET', '/oauth/authorize', fn () => 'next'))
                    ->name('passport.authorizations.authorize');
            });
            $authorizationResponse = app(EnforceOAuthResourceIndicator::class)
                ->handle($authorization, fn () => response('next'));
            $this->assertSame(400, $authorizationResponse->getStatusCode());
            $this->assertStringContainsString('invalid_target', (string) $authorizationResponse->getContent());

            $authorization->query->set('scope', '   ');
            $emptyScopeResponse = app(EnforceOAuthResourceIndicator::class)
                ->handle($authorization, fn () => response('next'));
            $this->assertSame(400, $emptyScopeResponse->getStatusCode());
            $this->assertStringContainsString('invalid_scope', (string) $emptyScopeResponse->getContent());

            $token = Request::create('/oauth/token', 'POST', [
                'resource' => 'https://other.example.test/api/v1',
            ]);
            $token->setRouteResolver(static function (): RoutingRoute {
                return (new RoutingRoute('POST', '/oauth/token', fn () => 'next'))
                    ->name('passport.token');
            });
            $tokenResponse = app(EnforceOAuthResourceIndicator::class)
                ->handle($token, fn () => response('next'));
            $this->assertSame(400, $tokenResponse->getStatusCode());

            $token->request->set('resource', 'HTTPS://AUTH.EXAMPLE.TEST:443/api/v1');
            $accepted = app(EnforceOAuthResourceIndicator::class)
                ->handle($token, fn (Request $request) => response(
                    OAuthResourceIndicator::validatedFor($request) ?? 'missing',
                ));
            $this->assertSame('https://auth.example.test/api/v1', $accepted->getContent());
        } finally {
            Passport::defaultScopes([]);
        }
    }

    public function test_resource_indicator_is_canonical_and_authorization_state_falls_back_to_cache(): void
    {
        $this->assertSame(
            'https://auth.example.test/api/v1',
            OAuthResourceIndicator::canonicalize('HTTPS://AUTH.EXAMPLE.TEST:443/api/v1'),
        );
        $this->assertFalse(OAuthResourceIndicator::isConfiguredResource('https://auth.example.test/api/v1/'));
        $this->assertNull(OAuthResourceIndicator::canonicalize('https://user@auth.example.test/api/v1'));

        $state = app(OAuthAuthorizationStateStore::class);
        $state->rememberResource('synthetic-approval-token', OAuthResourceIndicator::resource());
        session()->forget('test-oauth-resource:'.hash('sha256', 'synthetic-approval-token'));

        $this->assertSame(OAuthResourceIndicator::resource(), $state->resourceFor('synthetic-approval-token'));
        $state->forgetResource('synthetic-approval-token');
        $this->assertNull($state->resourceFor('synthetic-approval-token'));
    }

    public function test_expected_resource_is_an_explicit_request_boundary(): void
    {
        $request = Request::create('/mcp', 'GET');

        $this->assertNull(OAuthResourceIndicator::expectedFor($request));
        $this->assertSame(
            'https://auth.example.test/api/v1',
            OAuthResourceIndicator::expectConfiguredFor($request),
        );
        $this->assertSame(
            'https://auth.example.test/api/v1',
            OAuthResourceIndicator::expectedFor($request),
        );
    }

    public function test_protected_resource_helper_builds_metadata_and_bearer_challenges(): void
    {
        $this->assertSame([
            'resource' => 'https://auth.example.test/api/v1',
            'authorization_servers' => ['https://auth.example.test'],
            'scopes_supported' => ['identity:read', 'mcp:use'],
            'bearer_methods_supported' => ['header'],
        ], OAuthProtectedResource::metadata());

        $challenge = OAuthProtectedResource::bearerChallenge(
            'insufficient_scope',
            'Choose a permitted scope',
            ['mcp:use'],
        );
        $this->assertSame(
            'Bearer error="insufficient_scope", error_description="Choose a permitted scope", scope="mcp:use", resource_metadata="https://auth.example.test/.well-known/oauth-protected-resource/api/v1/mcp"',
            $challenge,
        );

        $response = OAuthProtectedResource::unauthorizedResponse();
        $this->assertSame(401, $response->getStatusCode());
        $this->assertSame(
            'Bearer error="invalid_token", resource_metadata="https://auth.example.test/.well-known/oauth-protected-resource/api/v1/mcp"',
            $response->headers->get('WWW-Authenticate'),
        );

        $forbidden = OAuthProtectedResource::insufficientScopeResponse(['mcp:use']);
        $this->assertSame(403, $forbidden->getStatusCode());
        $this->assertStringContainsString('scope="mcp:use"', (string) $forbidden->headers->get('WWW-Authenticate'));
    }

    public function test_rfc9207_issuer_is_exact_and_only_added_when_enabled(): void
    {
        $response = redirect('https://client.example.test/callback?code=synthetic&state=state');
        $this->assertSame($response, OAuthAuthorizationResponseIssuer::decorate($response));
        $this->assertStringNotContainsString('iss=', (string) $response->headers->get('Location'));

        config(['bherila-auth.oauth_server.authorization_response_issuer.enabled' => true]);
        config(['bherila-auth.oauth_server.enabled' => false]);
        OAuthAuthorizationResponseIssuer::decorate($response);
        $this->assertStringNotContainsString('iss=', (string) $response->headers->get('Location'));

        config(['bherila-auth.oauth_server.enabled' => true]);
        OAuthAuthorizationResponseIssuer::decorate($response);
        $this->assertStringContainsString('iss=https%3A%2F%2Fauth.example.test', (string) $response->headers->get('Location'));

        config(['bherila-auth.oauth_server.issuer' => 'https://auth.example.test/tenant/']);
        $response = redirect('https://client.example.test/callback?error=access_denied');
        OAuthAuthorizationResponseIssuer::decorate($response);
        $this->assertStringContainsString('iss=https%3A%2F%2Fauth.example.test%2Ftenant%2F', (string) $response->headers->get('Location'));

        $fragmentResponse = redirect('https://client.example.test/callback#error=access_denied&state=state');
        OAuthAuthorizationResponseIssuer::decorate($fragmentResponse);
        $this->assertStringContainsString(
            '#error=access_denied&state=state&iss=https%3A%2F%2Fauth.example.test%2Ftenant%2F',
            (string) $fragmentResponse->headers->get('Location'),
        );

        $request = Request::create('/oauth/authorize', 'GET', ['scope' => 'identity:read']);
        $request->setRouteResolver(static function (): RoutingRoute {
            return (new RoutingRoute('GET', '/oauth/authorize', fn () => 'next'))
                ->name('passport.authorizations.authorize');
        });
        $decoratedException = app(EnforceOAuthResourceIndicator::class)->handle(
            $request,
            static fn (): never => throw new HttpResponseException(
                redirect('https://client.example.test/callback?error=temporarily_unavailable'),
            ),
        );
        $this->assertStringContainsString(
            'iss=https%3A%2F%2Fauth.example.test%2Ftenant%2F',
            (string) $decoratedException->headers->get('Location'),
        );
        $this->assertStringContainsString(
            'no-store',
            (string) $decoratedException->headers->get('Cache-Control'),
        );
        $this->assertSame('no-cache', $decoratedException->headers->get('Pragma'));
    }

    public function test_a_failed_authorization_request_preserves_an_existing_consent_resource_binding(): void
    {
        $state = app(OAuthAuthorizationStateStore::class);
        session()->put('authToken', 'existing-consent-token');
        $state->rememberResource('existing-consent-token', OAuthResourceIndicator::resource());

        $request = Request::create('/oauth/authorize', 'GET', ['scope' => 'identity:read']);
        $request->setRouteResolver(static function (): RoutingRoute {
            return (new RoutingRoute('GET', '/oauth/authorize', fn () => 'next'))
                ->name('passport.authorizations.authorize');
        });

        app(EnforceOAuthResourceIndicator::class)->handle(
            $request,
            static fn (): never => throw new HttpResponseException(
                response()->json(['error' => 'invalid_request'], 400),
            ),
        );

        self::assertSame(
            OAuthResourceIndicator::resource(),
            $state->resourceFor('existing-consent-token'),
        );
    }

    public function test_shared_consent_view_renders_identity_permissions_and_dynamic_redirect_warning(): void
    {
        $client = new class
        {
            public string $name = 'Synthetic Harness';

            public ?string $dynamically_registered_at = '2026-08-23 12:00:00';

            public ?string $registered_on = null;

            /** @var list<string> */
            public array $redirect_uris = ['http://127.0.0.1:1455/callback'];
        };
        $user = (object) ['name' => 'Synthetic User'];
        $scope = (object) ['description' => 'Connect through MCP'];
        $request = Request::create('/oauth/authorize', 'GET');

        $html = view('bherila-auth::oauth.authorize', [
            'client' => $client,
            'user' => $user,
            'scopes' => [$scope],
            'authToken' => 'synthetic-auth-token',
            'request' => $request,
        ])->render();

        $this->assertStringContainsString('Connect Synthetic Harness to Synthetic App?', $html);
        $this->assertStringContainsString('Signed in as Synthetic User.', $html);
        $this->assertStringContainsString('Connect through MCP', $html);
        $this->assertStringContainsString('http://127.0.0.1:1455/callback', $html);
        $this->assertStringContainsString('name="auth_token" value="synthetic-auth-token"', $html);

        config(['bherila-auth.oauth_server.dynamic_clients.registered_at_column' => 'registered_on']);
        $client->registered_on = '2026-08-23 12:00:00';
        $client->dynamically_registered_at = null;
        $configuredMarkerHtml = view('bherila-auth::oauth.authorize', [
            'client' => $client,
            'user' => $user,
            'scopes' => [$scope],
            'authToken' => 'synthetic-auth-token',
            'request' => $request,
        ])->render();
        $this->assertStringContainsString('registered automatically', $configuredMarkerHtml);
    }

    /** @param array<string, mixed> $metadata */
    private function jsonRequest(array $metadata): Request
    {
        return Request::create(
            '/oauth/register',
            'POST',
            server: ['CONTENT_TYPE' => 'application/json'],
            content: json_encode($metadata, JSON_THROW_ON_ERROR),
        );
    }
}
