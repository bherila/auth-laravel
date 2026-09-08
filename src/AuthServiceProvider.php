<?php

namespace BWH\Auth;

use BWH\Auth\Console\PruneAuthAuditLogCommand;
use BWH\Auth\Contracts\AuthAuditLogger;
use BWH\Auth\Contracts\AuthUserPolicy;
use BWH\Auth\Contracts\LoginThrottle;
use BWH\Auth\Services\AuthAuditLogLoginThrottle;
use BWH\Auth\Services\DatabaseAuthAuditLogger;
use BWH\Auth\Services\DefaultAuthUserPolicy;
use BWH\Auth\Services\NullAuthAuditLogger;
use Illuminate\Contracts\Foundation\CachesConfiguration;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\ServiceProvider;
use Laravel\Passport\Passport;
use Laravel\Passport\Client as PassportClient;
use Laravel\Passport\Bridge\AccessTokenRepository as PassportAccessTokenRepository;
use Laravel\Passport\Bridge\AuthCodeRepository as PassportAuthCodeRepository;
use Laravel\Passport\Bridge\RefreshTokenRepository as PassportRefreshTokenRepository;
use BWH\Auth\OAuth\Server\ResourceAccessToken;
use BWH\Auth\OAuth\Server\ResourceAccessTokenRepository;
use BWH\Auth\OAuth\Server\ResourceAuthCodeRepository;
use BWH\Auth\OAuth\Server\ResourceRefreshTokenRepository;
use BWH\Auth\OAuth\Server\ResourceClient;
use BWH\Auth\Http\Middleware\AppendOAuthAuthorizationResponseIssuer;
use BWH\Auth\OAuth\Introspection\OAuthIntrospectionValidationContext;
use BWH\Auth\OAuth\Introspection\OAuthTokenIntrospector;
use BWH\Auth\OAuth\Introspection\RemoteOAuthTokenIntrospector;

class AuthServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigRecursivelyFrom(__DIR__.'/../config/bherila-auth.php', 'bherila-auth');

        $this->app->bind(AuthUserPolicy::class, DefaultAuthUserPolicy::class);
        $this->app->bind(AuthAuditLogger::class, function ($app) {
            return config('bherila-auth.audit.driver') === 'database'
                ? $app->make(DatabaseAuthAuditLogger::class)
                : $app->make(NullAuthAuditLogger::class);
        });
        $this->app->bind(LoginThrottle::class, AuthAuditLogLoginThrottle::class);
        $this->app->scoped(OAuthIntrospectionValidationContext::class);
        $this->app->bind(OAuthTokenIntrospector::class, RemoteOAuthTokenIntrospector::class);

        $this->registerOAuthServerBindings();
    }

    public function boot(): void
    {
        $this->loadViewsFrom(__DIR__.'/../resources/views', 'bherila-auth');

        $this->publishes([
            __DIR__.'/../config/bherila-auth.php' => config_path('bherila-auth.php'),
        ], 'bherila-auth-config');

        $this->publishes([
            __DIR__.'/../database/migrations' => database_path('migrations'),
        ], 'bherila-auth-migrations');

        $this->publishes([
            __DIR__.'/../database/delegated-access-migrations' => database_path('migrations'),
        ], 'bherila-auth-delegated-access-migrations');

        $this->publishes([
            __DIR__.'/../resources/views' => resource_path('views/vendor/bherila-auth'),
        ], 'bherila-auth-views');

        if (config('bherila-auth.routes.enabled', true) && config('bherila-auth.routes.passkeys', true)) {
            Route::prefix(config('bherila-auth.routes.prefix', 'api'))
                ->middleware(config('bherila-auth.routes.middleware', ['web']))
                ->group(__DIR__.'/../routes/passkeys.php');
        }

        if (config('bherila-auth.routes.enabled', true) && $this->shouldLoadAuthRoutes()) {
            Route::prefix(config('bherila-auth.routes.prefix', 'api'))
                ->middleware(config('bherila-auth.routes.middleware', ['web']))
                ->group(__DIR__.'/../routes/auth.php');
        }

        if (config('bherila-auth.audit.routes_enabled', false)) {
            Route::prefix(config('bherila-auth.routes.prefix', 'api'))
                ->middleware(config('bherila-auth.routes.middleware', ['web']))
                ->group(__DIR__.'/../routes/audit.php');
        }

        if ($this->app->runningInConsole()) {
            $this->commands([PruneAuthAuditLogCommand::class]);
        }

        // Testbench and applications with deferred configuration can apply the
        // opt-in setting after provider registration but before provider boot.
        $this->registerOAuthServerBindings(preserveExisting: true);
        if ($this->oauthServerEnabled() && class_exists(Passport::class)) {
            Passport::useAccessTokenEntity(ResourceAccessToken::class);
            if (Passport::clientModel() === PassportClient::class) {
                Passport::useClientModel(ResourceClient::class);
            }
        }

        if ($this->oauthServerEnabled()
            && config('bherila-auth.oauth_server.authorization_response_issuer.enabled', false)) {
            $this->app->booted(function (): void {
                foreach ([
                    'passport.authorizations.authorize',
                    'passport.authorizations.approve',
                    'passport.authorizations.deny',
                ] as $routeName) {
                    Route::getRoutes()->getByName($routeName)?->middleware(
                        AppendOAuthAuthorizationResponseIssuer::class,
                    );
                }
            });
        }
    }

    private function registerOAuthServerBindings(bool $preserveExisting = false): void
    {
        if (! class_exists(PassportAccessTokenRepository::class)) {
            return;
        }

        // Keep bearer audience enforcement active for already-issued bound tokens
        // after issuance is disabled. The repository delegates unbound issuance and
        // persistence to Passport while the opt-in server switch is off.
        $bindings = [
            PassportAccessTokenRepository::class => ResourceAccessTokenRepository::class,
        ];
        if ($this->oauthServerEnabled()) {
            $bindings += [
                PassportAuthCodeRepository::class => ResourceAuthCodeRepository::class,
                PassportRefreshTokenRepository::class => ResourceRefreshTokenRepository::class,
            ];
        }

        // Passport resolves these concrete bridge classes while constructing its
        // authorization/resource servers. Applications may still replace any of
        // the bindings in their own provider when they need additional bookkeeping.
        foreach ($bindings as $abstract => $implementation) {
            if (! $preserveExisting || ! $this->app->bound($abstract)) {
                $this->app->bind($abstract, $implementation);
            }
        }
    }

    private function oauthServerEnabled(): bool
    {
        return (bool) config('bherila-auth.oauth_server.enabled', false);
    }

    /**
     * Merge the package defaults under the application's configuration, one nested key
     * at a time.
     *
     * mergeConfigFrom() is a top-level array_merge: an application that published this
     * file before a release added a key inside `passkeys`, `two_factor`, `oauth_client`
     * or `oauth_server` replaces that whole nested array, and the new key silently
     * disappears — reading as null rather than as its default. Every setting this
     * package added since a consumer last republished its config has that failure mode.
     *
     * Laravel's replaceConfigRecursivelyFrom() fixes the nesting but merges lists by
     * index, so an application that shortens a list (emptying `required_columns`, or
     * narrowing `test_code_environments`) keeps the tail of the package's default.
     * Recursing into associative arrays only, and letting a configured list replace the
     * default outright, is what a published config file actually means.
     */
    private function mergeConfigRecursivelyFrom(string $path, string $key): void
    {
        if ($this->app instanceof CachesConfiguration && $this->app->configurationIsCached()) {
            return;
        }

        $config = $this->app->make('config');

        $config->set($key, $this->mergeConfigArrays(require $path, (array) $config->get($key, [])));
    }

    /**
     * @param  array<mixed>  $defaults
     * @param  array<mixed>  $configured
     * @return array<mixed>
     */
    private function mergeConfigArrays(array $defaults, array $configured): array
    {
        foreach ($configured as $key => $value) {
            $default = $defaults[$key] ?? null;

            $defaults[$key] = is_array($value) && is_array($default) && ! array_is_list($value)
                ? $this->mergeConfigArrays($default, $value)
                : $value;
        }

        return $defaults;
    }

    private function shouldLoadAuthRoutes(): bool
    {
        return config('bherila-auth.routes.password_resets', true)
            || config('bherila-auth.routes.change_password', true)
            || config('bherila-auth.routes.two_factor', true);
    }
}
