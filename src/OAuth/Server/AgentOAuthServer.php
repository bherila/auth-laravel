<?php

namespace BWH\Auth\OAuth\Server;

use BWH\Auth\Http\Controllers\OAuthDynamicClientRegistrationController;
use BWH\Auth\Http\Controllers\OAuthMetadataController;
use BWH\Auth\Http\Middleware\EnforceOAuthPkce;
use BWH\Auth\Http\Middleware\EnforceOAuthResourceIndicator;
use BWH\Auth\Http\Middleware\EnsureOAuthServerEnabled;
use Illuminate\Support\Facades\Route;

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
 *   that one resource, since most generic clients never send it;
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

        return self::merge([
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
            'introspection' => ['enabled' => false, 'clients' => []],
        ], $overrides);
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
        Route::withoutMiddleware(['web'])->middleware([EnsureOAuthServerEnabled::class])->group(static function () use ($protectedResourceMiddleware, $registrationThrottle): void {
            Route::get('/.well-known/oauth-authorization-server', [OAuthMetadataController::class, 'authorizationServer']);
            // Only at the path derived from the one protected resource: RFC 9728
            // requires the document's `resource` to match the URL it was
            // discovered from, so no other suffix may serve it.
            Route::get(self::protectedResourceMetadataPath(), [OAuthMetadataController::class, 'protectedResource'])
                ->middleware($protectedResourceMiddleware);
            Route::post('/oauth/register', OAuthDynamicClientRegistrationController::class)->middleware($registrationThrottle);
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
    public static function protectedResourceMetadataPath(): string
    {
        $resource = (string) config('bherila-auth.oauth_server.resource', '');
        $path = rtrim((string) (parse_url($resource, PHP_URL_PATH) ?? ''), '/');
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
