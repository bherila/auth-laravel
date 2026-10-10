<?php

namespace BWH\Auth\Tests\Feature;

use BWH\Auth\AuthServiceProvider;
use BWH\Auth\OAuth\Server\AgentOAuthServer;
use BWH\Auth\Tests\TestCase;
use Illuminate\Support\Facades\Route;
use Laravel\Passport\Passport;
use Laravel\Passport\PassportServiceProvider;

/** The agent profile ignores Passport's transient-token cookie even while issuance is switched off. */
final class TransientTokenCookieTest extends TestCase
{
    protected function getPackageProviders($app): array
    {
        return [AuthServiceProvider::class, PassportServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);
        $app['config']->set('bherila-auth.oauth_server', AgentOAuthServer::config(['items:read' => 'Read items'], [
            'enabled' => false,
        ], 'https://app.example.test'));
    }

    protected function tearDown(): void
    {
        Passport::tokensCan([]);
        parent::tearDown();
    }

    public function test_turning_issuance_off_does_not_reopen_the_cookie_path(): void
    {
        Route::get('/cookie-probe', fn () => request()->cookie(Passport::cookie()) === null ? 'ignored' : 'present');

        $this->withUnencryptedCookie(Passport::cookie(), 'example-cookie-value')
            ->get('/cookie-probe')->assertOk()->assertSee('ignored');
    }
}
