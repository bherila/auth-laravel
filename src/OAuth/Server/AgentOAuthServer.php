<?php

namespace BWH\Auth\OAuth\Server;

use BWH\Auth\Http\Controllers\OAuthDynamicClientRegistrationController;
use BWH\Auth\Http\Controllers\OAuthMetadataController;
use BWH\Auth\Http\Middleware\EnforceOAuthPkce;
use BWH\Auth\Http\Middleware\OAuthEndpointCors;
use BWH\Auth\Http\Middleware\EnforceOAuthResourceIndicator;
use BWH\Auth\Http\Middleware\EnsureOAuthServerEnabled;
use Illuminate\Support\Facades\Route;
use Laravel\Passport\Contracts\AuthorizationViewResponse;
use Laravel\Passport\Passport;

/**
 * The agent-API authorization-server profile, applied in one place.
 *
 * An application that lets agents (MCP clients and REST/OpenAPI connectors)
 * act for its users runs its own authorization server through this package;
 * the identity provider only signs people in. Every such application needs the
 * same settings, and small differences between hand-written copies become
 * interoperability bugs, so they live here:
 *
 * - S256 PKCE for every client (EnforceOAuthPkce);
 * - public-only dynamic client registration at `/oauth/register`;
 * - RFC 8707 binding to `APP_URL/api/v1`, with an omitted `resource` taken as
 *   that one resource, since most generic clients never send it - or to several
 *   resources, each its own audience with its own metadata document and scope
 *   ceiling (see `resources` below);
 * - `none`, `client_secret_basic` and `client_secret_post` advertised -
 *   confidential clients are only ever ones a person registers;
 * - discovery metadata for the authorization server and protected resource.
 *
 * Everything derives from the application URL, so a fork or self-hosted
 * deployment needs no host-specific configuration. Use it from the
 * application's published config:
 *
 *     'oauth_server' => AgentOAuthServer::config(AppScopes::descriptions(), [
 *         'resource_required_scopes' => ['mcp:use'],
 *     ]),
 *
 * and in config/passport.php: `'middleware' => AgentOAuthServer::passportMiddleware()`.
 *
 * Several resources (RFC 9728 wants a document per endpoint whose `resource` is that
 * endpoint's own URL, so an MCP endpoint is a resource of its own):
 *
 *     'oauth_server' => AgentOAuthServer::config(AppScopes::descriptions(), [
 *         'resources' => [
 *             'rest' => ['path' => '/api/v1', 'scopes' => AppScopes::rest()],
 *             'mcp' => ['path' => '/api/v1/mcp', 'scopes' => ['mcp:use', ...AppScopes::modules()]],
 *         ],
 *         'assume_omitted_resource' => 'rest',
 *     ]),
 *
 * then `ExpectOAuthResource::class.':mcp'` on the MCP route. A scope may be listed
 * under several resources.
 */
final class AgentOAuthServer
{
    /**
     * @param  array<string, string>  $scopes  the application's scope catalog: identifier => description
     * @param  array<string, mixed>  $overrides  merged recursively; a list replaces the preset's list
     * @return array<string, mixed>
     */
    public static function config(array $scopes, array $overrides = [], ?string $appUrl = null): array
    {
        $base = rtrim($appUrl ?? (string) env('APP_URL', 'http://localhost'), '/');

        $config = self::merge([
            'enabled' => (bool) env('OAUTH_SERVER_ENABLED', true),
            'issuer' => $base,
            'resource' => $base.'/api/v1',
            'authorization_endpoint' => $base.'/oauth/authorize',
            'token_endpoint' => $base.'/oauth/token',
            'registration_endpoint' => $base.'/oauth/register',
            'protected_resource_metadata_url' => self::wellKnown($base.'/api/v1', 'oauth-protected-resource'),
            'scopes' => $scopes,
            'token_endpoint_auth_methods' => ['none', 'client_secret_basic', 'client_secret_post'],
            'assume_omitted_resource' => true,
            // Origins of browser-based agents allowed to call discovery, registration and the
            // token endpoint directly (`*` for any). Empty: no CORS headers at all.
            'cors' => ['allowed_origins' => [], 'max_age' => 600],
            'introspection' => ['enabled' => false, 'clients' => []],
            // Marks the profile so the package's service provider completes the
            // Passport side (scopes, consent view, no device grant).
            'profile' => self::PROFILE,
        ], $overrides);

        // Several resources, each its own audience: `path` is relative to the application
        // URL (or give a full `uri`). The single `resource` key then names the default one,
        // for callers that read it directly.
        if (is_array($config['resources'] ?? null) && $config['resources'] !== []) {
            foreach ($config['resources'] as $name => $definition) {
                if (is_array($definition) && ! isset($definition['uri']) && is_string($definition['path'] ?? null)) {
                    $config['resources'][$name]['uri'] = $base.'/'.ltrim($definition['path'], '/');
                }
            }
            $default = is_string($config['assume_omitted_resource']) ? $config['assume_omitted_resource'] : array_key_first($config['resources']);
            if (is_string($config['resources'][$default]['uri'] ?? null)) {
                $config['resource'] = $config['resources'][$default]['uri'];
            }
        }

        // Derived from the final resource, so overriding the resource cannot
        // leave challenges pointing at a document nothing serves.
        if (! array_key_exists('protected_resource_metadata_url', $overrides)) {
            $config['protected_resource_metadata_url'] = self::wellKnown((string) $config['resource'], 'oauth-protected-resource');
        }

        return $config;
    }

    public const string PROFILE = 'agent';

    /** The route default naming which resource a protected-resource document describes. */
    public const string RESOURCE_ROUTE_DEFAULT = 'bherila_auth_resource';

    public static function active(): bool
    {
        return config('bherila-auth.oauth_server.profile') === self::PROFILE;
    }

    /**
     * Passport settings the profile needs before Passport registers its routes:
     * the device-code grant is off, because PKCE is only enforced on the
     * authorization endpoint and the profile advertises authorization code and
     * refresh only. Called from the package's register phase.
     */
    public static function configurePassportEarly(): void
    {
        if (class_exists(Passport::class)) {
            Passport::$deviceCodeGrantEnabled = false;
        }
    }

    /**
     * Passport settings applied at boot unless the application already set
     * them: the scope catalog and the packaged consent view.
     */
    public static function configurePassport(): void
    {
        if (! class_exists(Passport::class)) {
            return;
        }
        $scopes = config('bherila-auth.oauth_server.scopes', []);
        if (is_array($scopes) && Passport::scopes()->isEmpty()) {
            Passport::tokensCan($scopes);
        }
        if (! app()->bound(AuthorizationViewResponse::class)) {
            Passport::authorizationView('bherila-auth::oauth.authorize');
        }
    }

    /**
     * Passport's route middleware for the profile: kill switch, PKCE, then
     * resource binding and scope ceilings. Append application middleware.
     *
     * @param  list<class-string|string>  $extra
     * @return list<class-string|string>
     */
    public static function passportMiddleware(array $extra = []): array
    {
        return [
            EnsureOAuthServerEnabled::class,
            OAuthEndpointCors::class,
            EnforceOAuthPkce::class,
            EnforceOAuthResourceIndicator::class,
            ...$extra,
        ];
    }

    /**
     * Discovery documents and dynamic client registration, outside the `web`
     * group (no session or CSRF: these are called by machines).
     *
     * @param  list<class-string|string>  $protectedResourceMiddleware  e.g. a CORS policy for browser MCP clients
     */
    public static function routes(array $protectedResourceMiddleware = [], string $registrationThrottle = 'throttle:10,60'): void
    {
        Route::withoutMiddleware(['web'])->middleware([EnsureOAuthServerEnabled::class, OAuthEndpointCors::class])->group(static function () use ($protectedResourceMiddleware, $registrationThrottle): void {
            // RFC 8414: an issuer with a path is discovered under that path too.
            $issuerPath = rtrim((string) (parse_url((string) config('bherila-auth.oauth_server.issuer', ''), PHP_URL_PATH) ?? ''), '/');
            foreach (array_unique(['/.well-known/oauth-authorization-server', '/.well-known/oauth-authorization-server'.$issuerPath]) as $path) {
                Route::match(['GET', 'OPTIONS'], $path, [OAuthMetadataController::class, 'authorizationServer']);
            }
            // One document per protected resource, each only at the path derived from
            // that resource: RFC 9728 requires a document's `resource` to be identical
            // to the identifier it was discovered from, so no other path may serve it.
            foreach (array_keys(OAuthResourceIndicator::resources()) as $resource) {
                Route::match(['GET', 'OPTIONS'], self::protectedResourceMetadataPath($resource), [OAuthMetadataController::class, 'protectedResource'])
                    ->defaults(self::RESOURCE_ROUTE_DEFAULT, $resource)
                    ->middleware($protectedResourceMiddleware);
            }
            Route::post('/oauth/register', OAuthDynamicClientRegistrationController::class)->middleware($registrationThrottle);
            // Preflights for the machine endpoints a browser agent posts to; the middleware
            // answers them before any controller runs.
            Route::options('/oauth/register', static fn () => response('', 204));
            Route::options('/oauth/token', static fn () => response('', 204));
        });
    }

    /**
     * RFC 9728 / RFC 8414 well-known URL: the well-known segment goes between
     * the origin and the identifier's path, so `https://h/tenant/api/v1` gives
     * `https://h/.well-known/oauth-protected-resource/tenant/api/v1`.
     */
    public static function wellKnown(string $identifier, string $suffix): string
    {
        $parts = parse_url($identifier);
        $origin = ($parts['scheme'] ?? 'https').'://'.($parts['host'] ?? 'localhost').(isset($parts['port']) ? ':'.$parts['port'] : '');
        $path = rtrim((string) ($parts['path'] ?? ''), '/');

        return $origin.'/.well-known/'.$suffix.$path;
    }

    /**
     * The route path for the protected-resource document, relative to the
     * application. A deployment mounted under a path must also route the
     * host-root well-known URL (see wellKnown()) to the application.
     */
    public static function protectedResourceMetadataPath(?string $resource = null): string
    {
        $path = rtrim((string) (parse_url(OAuthResourceIndicator::resource($resource), PHP_URL_PATH) ?? ''), '/');
        $appPath = rtrim((string) (parse_url((string) config('app.url', ''), PHP_URL_PATH) ?? ''), '/');
        if ($appPath !== '' && str_starts_with($path, $appPath)) {
            $path = substr($path, strlen($appPath));
        }

        return '/.well-known/oauth-protected-resource'.($path === '' ? '/api/v1' : $path);
    }

    /**
     * Recurse into associative arrays; a list (or scalar) replaces outright, so
     * an override that narrows a list means exactly what it says.
     *
     * @param  array<mixed>  $defaults
     * @param  array<mixed>  $overrides
     * @return array<mixed>
     */
    private static function merge(array $defaults, array $overrides): array
    {
        foreach ($overrides as $key => $value) {
            $default = $defaults[$key] ?? null;
            $defaults[$key] = is_array($value) && is_array($default) && ! array_is_list($value) && ! array_is_list($default)
                ? self::merge($default, $value)
                : $value;
        }

        return $defaults;
    }
}
