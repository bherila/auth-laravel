<?php

namespace BWH\Auth\Tests\Feature;

use BWH\Auth\Mail\TwoFactorLoginMail;
use BWH\Auth\Models\TwoFactorAttempt;
use BWH\Auth\Services\TwoFactorService;
use BWH\Auth\Support\TwoFactorRoutes;
use BWH\Auth\Tests\Fixtures\TwoFactorRouteContext;
use BWH\Auth\Tests\Fixtures\User;
use BWH\Auth\Tests\TestCase;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Filesystem\Filesystem;
use Illuminate\Foundation\Console\RouteCacheCommand;
use Illuminate\Http\Request;
use Illuminate\Routing\CompiledRouteCollection;
use Illuminate\Routing\RouteCollection;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Str;

class TwoFactorRouteNamesTest extends TestCase
{
    private const DEFAULT_PREFIX = 'bherila-auth.two-factor.';

    private const MOUNTED_PREFIX = 'example-provider.two-factor.';

    protected function setUp(): void
    {
        parent::setUp();
        config(['app.url' => 'https://app.example.test']);
        Mail::fake();
    }

    public function test_default_route_names_mail_links_and_form_actions_remain_unchanged(): void
    {
        $this->assertSame(self::DEFAULT_PREFIX, config('bherila-auth.two_factor.route_name_prefix'));
        $this->assertLinksAndActions(self::DEFAULT_PREFIX, '/api');
    }

    public function test_custom_names_select_the_custom_route_set_for_mail_and_forms(): void
    {
        config(['bherila-auth.two_factor.route_name_prefix' => self::MOUNTED_PREFIX]);
        $this->app['router']->setRoutes(new RouteCollection);
        $this->registerMountedRoutes();
        $this->assertNull($this->app['router']->getRoutes()->getByName(self::DEFAULT_PREFIX.'confirm'));
        $this->assertSame(self::MOUNTED_PREFIX.'report.submit', TwoFactorRoutes::name('report.submit'));
        $this->assertLinksAndActions(self::MOUNTED_PREFIX, '/accounts/api');
    }

    public function test_host_and_mounted_routes_coexist_after_real_route_cache_serialization_and_reload(): void
    {
        $this->registerMountedRoutes();
        $files = new Filesystem;
        $bootstrap = sys_get_temp_dir().'/two-factor-route-cache-'.Str::uuid();
        $files->ensureDirectoryExists($bootstrap.'/cache');
        $previousBootstrap = $this->app->bootstrapPath();
        $this->app->useBootstrapPath($bootstrap);

        // Keep Testbench's isolated routes instead of booting a consuming application.
        // The command's real serialization, duplicate-name checks and cache stub run unchanged.
        $command = new class($files) extends RouteCacheCommand
        {
            protected function getFreshApplication(): Application
            {
                return $this->laravel;
            }
        };
        $this->app->make(Kernel::class)->registerCommand($command);

        try {
            $this->artisan('route:cache')->assertSuccessful();
            $cache = $this->app->getCachedRoutesPath();
            $this->assertFileExists($cache);
            $this->assertStringContainsString('setCompiledRoutes', $files->get($cache));

            // Discard the original collection, then load Laravel's generated cache file.
            $this->app['router']->setRoutes(new RouteCollection);
            require $cache;
            $this->assertInstanceOf(CompiledRouteCollection::class, $this->app['router']->getRoutes());
            $this->app['url']->setRoutes($this->app['router']->getRoutes());

            foreach ([self::DEFAULT_PREFIX => '/api', self::MOUNTED_PREFIX => '/accounts/api'] as $prefix => $path) {
                foreach (['confirm', 'confirm.submit', 'report', 'report.submit'] as $action) {
                    $this->assertSame($path.'/auth/two-factor/'.explode('.', $action)[0].'/synthetic-token', route($prefix.$action, ['token' => 'synthetic-token'], false));
                }
                $this->assertLinksAndActions($prefix, $path);
                $this->assertSame(self::DEFAULT_PREFIX, config('bherila-auth.two_factor.route_name_prefix'));
            }
        } finally {
            $this->app->useBootstrapPath($previousBootstrap);
            $files->deleteDirectory($bootstrap);
        }
    }

    private function registerMountedRoutes(): void
    {
        $previous = config('bherila-auth.two_factor.route_name_prefix');
        config(['bherila-auth.two_factor.route_name_prefix' => self::MOUNTED_PREFIX]);
        try {
            Route::prefix('accounts/api')->middleware(['web', TwoFactorRouteContext::class.':'.self::MOUNTED_PREFIX])
                ->group(__DIR__.'/../../routes/auth.php');
        } finally {
            config(['bherila-auth.two_factor.route_name_prefix' => $previous]);
        }
        $this->app['router']->getRoutes()->refreshNameLookups();
        $this->app['url']->setRoutes($this->app['router']->getRoutes());
    }

    private function assertLinksAndActions(string $prefix, string $path): void
    {
        Auth::forgetGuards();
        $this->flushSession();
        $user = User::create(['name' => 'Example Person', 'email' => 'person-'.Str::lower(Str::random(8)).'@example.test', 'password' => bcrypt('synthetic-password')]);
        $request = Request::create('https://untrusted.example.test/login');
        $request->setLaravelSession(app('session.store'));
        $previous = config('bherila-auth.two_factor.route_name_prefix');
        config(['bherila-auth.two_factor.route_name_prefix' => $prefix]);
        try {
            $attempt = app(TwoFactorService::class)->startChallenge($user, $request);
        } finally {
            config(['bherila-auth.two_factor.route_name_prefix' => $previous]);
        }
        $this->assertGuest();
        Mail::assertSent(TwoFactorLoginMail::class, fn (TwoFactorLoginMail $mail): bool => $mail->attempt->is($attempt)
            && $mail->confirmUrl === 'https://app.example.test'.$path.'/auth/two-factor/confirm/'.$attempt->token
            && $mail->reportUrl === 'https://app.example.test'.$path.'/auth/two-factor/report/'.$attempt->token);

        $confirm = $path.'/auth/two-factor/confirm/'.$attempt->token;
        $report = $path.'/auth/two-factor/report/'.$attempt->token;
        $this->get($confirm)->assertOk()->assertSee('action="http://localhost'.$confirm.'"', false);
        $this->get($report)->assertOk()->assertSee('action="http://localhost'.$report.'"', false);
        $this->assertGuest();
        $this->assertFalse($attempt->fresh()->is_used);

        $suspicious = TwoFactorAttempt::createForUser($user);
        $this->postJson($path.'/auth/two-factor/report/'.$suspicious->token)->assertOk()->assertJsonPath('success', true);
        $this->assertTrue($suspicious->fresh()->is_suspicious);
        $this->assertGuest();
        $this->postJson($confirm)->assertOk()->assertJsonPath('success', true);
        $this->assertAuthenticatedAs($user);
        $this->assertTrue($attempt->fresh()->is_used);
    }
}
