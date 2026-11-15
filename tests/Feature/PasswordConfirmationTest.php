<?php

namespace BWH\Auth\Tests\Feature;

use BWH\Auth\Http\Middleware\RequirePasswordConfirmation;
use BWH\Auth\OAuth\Session\AuthenticationContext;
use BWH\Auth\Tests\Fixtures\User;
use BWH\Auth\Tests\TestCase;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use Orchestra\Testbench\Attributes\DefineEnvironment;

/**
 * Passkey enrollment needs a recent password confirmation, so a stolen session alone cannot
 * add the thief's authenticator; the package's confirm endpoint provides it.
 */
class PasswordConfirmationTest extends TestCase
{
    private function user(): User
    {
        return User::create([
            'name' => 'Test',
            'email' => 'user@example.com',
            'password' => bcrypt('secret-password'),
        ]);
    }

    public function test_enrollment_options_need_a_confirmed_password(): void
    {
        $user = $this->user();

        // No Accept header, as the bwh-auth passkey client sends: still JSON, never a redirect.
        $this->actingAs($user)->post('/api/passkeys/register/options')
            ->assertStatus(423)
            ->assertJsonPath('error', RequirePasswordConfirmation::ERROR);
        $this->actingAs($user)->postJson('/api/passkeys/register', ['credential' => ['id' => 'x']])->assertStatus(423);

        $this->actingAs($user)->postJson('/api/auth/confirm-password', ['password' => 'wrong'])
            ->assertStatus(422)->assertJsonValidationErrors('password');
        $this->actingAs($user)->postJson('/api/passkeys/register/options')->assertStatus(423);

        $this->actingAs($user)->postJson('/api/auth/confirm-password', ['password' => 'secret-password'])
            ->assertOk()
            ->assertJsonPath('success', true)
            ->assertJsonPath('expires_in', 10800);
        $this->actingAs($user)->postJson('/api/passkeys/register/options')
            ->assertOk()->assertJsonStructure(['challenge']);
    }

    public function test_a_confirmation_expires_with_the_configured_timeout(): void
    {
        config(['bherila-auth.password_confirmation.timeout' => 60]);
        $user = $this->user();

        $this->actingAs($user)->postJson('/api/auth/confirm-password', ['password' => 'secret-password'])
            ->assertOk()->assertJsonPath('expires_in', 60);
        $this->travel(59)->seconds();
        $this->actingAs($user)->postJson('/api/passkeys/register/options')->assertOk();

        $this->travel(2)->seconds();
        $this->actingAs($user)->postJson('/api/passkeys/register/options')->assertStatus(423);
    }

    public function test_without_a_package_timeout_the_laravel_password_timeout_applies(): void
    {
        config(['auth.password_timeout' => 120]);
        $user = $this->user();

        $this->actingAs($user)->postJson('/api/auth/confirm-password', ['password' => 'secret-password'])->assertJsonPath('expires_in', 120);
        $this->travel(121)->seconds();

        $this->actingAs($user)->postJson('/api/passkeys/register/options')->assertStatus(423);
    }

    public function test_a_recent_provider_authentication_counts_as_a_confirmation(): void
    {
        $user = $this->user();
        $context = ['account' => (string) $user->id, 'auth_time' => now()->getTimestamp() - 30, 'amr' => ['pwd'], 'acr' => null];

        $this->actingAs($user)->withSession([AuthenticationContext::SESSION_KEY => $context])
            ->postJson('/api/passkeys/register/options')->assertOk();

        // Another account's provider authentication proves nothing about this one.
        $this->actingAs($user)->withSession([AuthenticationContext::SESSION_KEY => ['account' => 'other'] + $context])
            ->postJson('/api/passkeys/register/options')->assertStatus(423);

        // Nor does one older than the confirmation window (beyond the provider clock-skew allowance).
        $this->actingAs($user)->withSession([AuthenticationContext::SESSION_KEY => ['auth_time' => now()->getTimestamp() - 10900] + $context])
            ->postJson('/api/passkeys/register/options')->assertStatus(423);
    }

    public function test_the_requirement_can_be_turned_off(): void
    {
        config(['bherila-auth.passkeys.require_password_confirmation' => false]);

        $this->actingAs($this->user())->postJson('/api/passkeys/register/options')->assertOk();
    }

    public function test_confirming_needs_a_signed_in_account(): void
    {
        $this->postJson('/api/auth/confirm-password', ['password' => 'secret-password'])->assertUnauthorized();
    }

    public function test_password_confirmation_is_rate_limited_per_account(): void
    {
        $user = $this->user();

        foreach (range(1, 6) as $ip) {
            $this->actingAs($user)->withServerVariables(['REMOTE_ADDR' => "203.0.113.{$ip}"])
                ->postJson('/api/auth/confirm-password', ['password' => 'wrong'])->assertStatus(422);
        }

        $this->actingAs($user)->withServerVariables(['REMOTE_ADDR' => '203.0.113.99'])
            ->postJson('/api/auth/confirm-password', ['password' => 'secret-password'])->assertStatus(429);
    }

    /** @param  Application  $app */
    protected function withoutConfirmRoute($app): void
    {
        $app['config']->set('bherila-auth.routes.confirm_password', false);
    }

    #[DefineEnvironment('withoutConfirmRoute')]
    public function test_the_confirm_route_can_be_turned_off_for_an_application_that_owns_one(): void
    {
        $this->assertNull(collect(Route::getRoutes()->getRoutes())->first(fn ($route): bool => $route->uri() === 'api/auth/confirm-password'));

        // The application's own endpoint satisfies the same check.
        Route::middleware(['web', 'auth'])->post('/my/confirm', function (Request $request) {
            $request->session()->passwordConfirmed();

            return 'ok';
        });
        $user = $this->user();
        $this->actingAs($user)->post('/my/confirm')->assertOk();
        $this->actingAs($user)->postJson('/api/passkeys/register/options')->assertOk();
    }

    public function test_the_middleware_guards_an_application_route_with_its_own_window(): void
    {
        Route::middleware(['web', 'auth', RequirePasswordConfirmation::class.':300'])->post('/account/danger', fn () => 'done');
        $user = $this->user();

        $this->actingAs($user)->post('/account/danger')->assertStatus(423)->assertHeader('Cache-Control', 'no-store, private');

        $this->actingAs($user)->postJson('/api/auth/confirm-password', ['password' => 'secret-password'])->assertOk();
        $this->actingAs($user)->post('/account/danger')->assertOk()->assertSee('done');

        $this->travel(301)->seconds();
        $this->actingAs($user)->post('/account/danger')->assertStatus(423);
    }
}
