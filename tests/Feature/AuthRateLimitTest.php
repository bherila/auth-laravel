<?php

namespace BWH\Auth\Tests\Feature;

use BWH\Auth\Http\Controllers\TwoFactorController;
use BWH\Auth\Models\TwoFactorAttempt;
use BWH\Auth\Support\RateLimits;
use BWH\Auth\Tests\Fixtures\User;
use BWH\Auth\Tests\TestCase;
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Password;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use InvalidArgumentException;
use Orchestra\Testbench\Attributes\DefineEnvironment;

/**
 * The package's own named limiters on its routes, and the wrong-code cap on emailed
 * sign-in challenges. Each sends mail or checks a credential, so each is bounded per source
 * and per address (or account, or challenge) by default.
 */
class AuthRateLimitTest extends TestCase
{
    private function user(string $email = 'user@example.com'): User
    {
        return User::create([
            'name' => 'Test',
            'email' => $email,
            'password' => bcrypt('secret-password'),
        ]);
    }

    private function challenge(User $user): TwoFactorAttempt
    {
        $attempt = TwoFactorAttempt::createForUser($user);
        $attempt->forceFill(['code' => '123456'])->save();

        return $attempt;
    }

    /** @param  array<string, mixed>  $payload */
    private function postFrom(string $ip, string $uri, array $payload): TestResponse
    {
        return $this->withServerVariables(['REMOTE_ADDR' => $ip])->postJson($uri, $payload);
    }

    public function test_a_challenge_is_spent_after_five_wrong_codes(): void
    {
        $attempt = $this->challenge($this->user());

        foreach (range(1, 4) as $ignored) {
            $this->postJson('/api/auth/two-factor/verify', ['attempt_token' => $attempt->token, 'code' => '000000'])
                ->assertStatus(422)->assertJsonPath('message', 'The verification code is incorrect. Please try again.');
        }
        $this->assertFalse($attempt->fresh()->is_used);

        $this->postJson('/api/auth/two-factor/verify', ['attempt_token' => $attempt->token, 'code' => '000000'])
            ->assertStatus(422)->assertJsonPath('message', 'Too many incorrect codes. Please sign in again for a new code.');
        $this->assertTrue($attempt->fresh()->is_used);

        $this->postJson('/api/auth/two-factor/verify', ['attempt_token' => $attempt->token, 'code' => '123456'])->assertStatus(422);
        $this->assertGuest();
    }

    public function test_the_right_code_still_works_after_a_few_misses(): void
    {
        $user = $this->user();
        $attempt = $this->challenge($user);

        foreach (range(1, 4) as $ignored) {
            $this->postJson('/api/auth/two-factor/verify', ['attempt_token' => $attempt->token, 'code' => '000000'])->assertStatus(422);
        }

        $this->postJson('/api/auth/two-factor/verify', ['attempt_token' => $attempt->token, 'code' => '123456'])->assertOk();
        $this->assertAuthenticatedAs($user);
    }

    public function test_the_cap_holds_on_an_application_route_that_verifies_through_the_package(): void
    {
        // An application's own emergency sign-in, say: none of the package's route middleware.
        Route::middleware('web')->post('/emergency-login/verify', [TwoFactorController::class, 'verify']);
        $attempt = $this->challenge($this->user());

        foreach (range(1, 5) as $ignored) {
            $this->postJson('/emergency-login/verify', ['attempt_token' => $attempt->token, 'code' => '000000'])->assertStatus(422);
        }

        $this->assertTrue($attempt->fresh()->is_used);
        $this->postJson('/emergency-login/verify', ['attempt_token' => $attempt->token, 'code' => '123456'])->assertStatus(422);
        $this->assertGuest();
    }

    public function test_the_cap_is_configurable_and_can_be_turned_off(): void
    {
        config(['bherila-auth.two_factor.max_wrong_codes' => 2]);
        $attempt = $this->challenge($this->user());
        foreach (range(1, 2) as $ignored) {
            $this->postJson('/api/auth/two-factor/verify', ['attempt_token' => $attempt->token, 'code' => '000000']);
        }
        $this->assertTrue($attempt->fresh()->is_used);

        config(['bherila-auth.two_factor.max_wrong_codes' => 0]);
        $other = $this->challenge($this->user('other@example.com'));
        foreach (range(1, 8) as $ignored) {
            $this->postJson('/api/auth/two-factor/verify', ['attempt_token' => $other->token, 'code' => '000000'])->assertStatus(422);
        }
        $this->assertFalse($other->fresh()->is_used);
    }

    public function test_a_challenge_another_request_consumed_cannot_complete_a_sign_in(): void
    {
        $attempt = $this->challenge($this->user());
        // The row is spent between this request's validity check and its consumption.
        TwoFactorAttempt::retrieved(function (TwoFactorAttempt $retrieved) use ($attempt): void {
            if ($retrieved->is($attempt)) {
                TwoFactorAttempt::query()->whereKey($attempt->getKey())->update(['is_used' => true]);
            }
        });

        $this->postJson('/api/auth/two-factor/verify', ['attempt_token' => $attempt->token, 'code' => '123456'])
            ->assertStatus(422)->assertJsonPath('message', 'Invalid or expired verification attempt.');
        $this->assertGuest();
    }

    public function test_verify_is_rate_limited_per_ip(): void
    {
        foreach (range(1, 60) as $attempt) {
            $this->postJson('/api/auth/two-factor/verify', ['attempt_token' => "missing-{$attempt}", 'code' => '123456'])->assertStatus(422);
        }

        $this->postJson('/api/auth/two-factor/verify', ['attempt_token' => 'missing-next', 'code' => '123456'])->assertStatus(429);
        $this->postFrom('203.0.113.7', '/api/auth/two-factor/verify', ['attempt_token' => 'missing-next', 'code' => '123456'])->assertStatus(422);
    }

    public function test_verify_is_rate_limited_per_challenge_token_across_ips(): void
    {
        foreach (range(1, 10) as $ip) {
            $this->postFrom("203.0.113.{$ip}", '/api/auth/two-factor/verify', ['attempt_token' => 'missing', 'code' => '123456'])->assertStatus(422);
        }

        $this->postFrom('203.0.113.99', '/api/auth/two-factor/verify', ['attempt_token' => 'missing', 'code' => '123456'])->assertStatus(429);
        $this->postFrom('203.0.113.99', '/api/auth/two-factor/verify', ['attempt_token' => 'other', 'code' => '123456'])->assertStatus(422);
    }

    public function test_resending_codes_is_limited_per_account_across_ips(): void
    {
        Mail::fake();
        $token = $this->challenge($this->user())->token;

        foreach (range(1, 3) as $ip) {
            $token = $this->postFrom("203.0.113.{$ip}", '/api/auth/two-factor/resend', ['attempt_token' => $token])
                ->assertOk()->json('attempt_token');
        }

        $this->postFrom('203.0.113.9', '/api/auth/two-factor/resend', ['attempt_token' => $token])->assertStatus(429);
    }

    public function test_resending_codes_is_limited_per_ip(): void
    {
        foreach (range(1, 6) as $attempt) {
            $this->postJson('/api/auth/two-factor/resend', ['attempt_token' => "missing-{$attempt}"])->assertStatus(422);
        }

        $this->postJson('/api/auth/two-factor/resend', ['attempt_token' => 'missing-next'])->assertStatus(429);
    }

    public function test_forgot_password_is_limited_per_address_across_ips_and_per_ip(): void
    {
        Mail::fake();
        $user = $this->user();

        foreach (range(1, 5) as $ip) {
            $this->postFrom("203.0.113.{$ip}", '/api/auth/forgot-password', ['email' => $user->email])->assertOk();
        }
        // Case and spacing do not make a new bucket.
        $this->postFrom('203.0.113.9', '/api/auth/forgot-password', ['email' => ' USER@example.com'])->assertStatus(429);

        foreach (range(1, 5) as $n) {
            $this->postFrom('198.51.100.1', '/api/auth/forgot-password', ['email' => "someone-{$n}@example.com"])->assertOk();
        }
        $this->postFrom('198.51.100.1', '/api/auth/forgot-password', ['email' => 'someone-else@example.com'])->assertStatus(429);
    }

    public function test_reset_password_is_limited_per_address(): void
    {
        $user = $this->user();
        $payload = ['email' => $user->email, 'token' => 'wrong', 'password' => 'new-password-1234', 'password_confirmation' => 'new-password-1234'];

        foreach (range(1, 10) as $ip) {
            $this->postFrom("203.0.113.{$ip}", '/api/auth/reset-password', $payload)->assertStatus(422);
        }

        $payload['token'] = Password::broker()->createToken($user);
        $this->postFrom('203.0.113.99', '/api/auth/reset-password', $payload)->assertStatus(429);
    }

    public function test_change_password_is_limited_per_account(): void
    {
        $user = $this->user();

        foreach (range(1, 6) as $ip) {
            $this->actingAs($user)->postFrom("203.0.113.{$ip}", '/api/change-password', [
                'current_password' => 'wrong-password',
                'password' => 'new-password-1234',
                'password_confirmation' => 'new-password-1234',
            ])->assertStatus(422);
        }

        $this->actingAs($user)->postFrom('203.0.113.99', '/api/change-password', [
            'current_password' => 'secret-password',
            'password' => 'new-password-1234',
            'password_confirmation' => 'new-password-1234',
        ])->assertStatus(429);
    }

    public function test_every_mail_or_credential_route_names_its_own_limiter(): void
    {
        $expected = [
            'api/auth/two-factor/verify' => RateLimits::TWO_FACTOR_VERIFY,
            'api/auth/two-factor/resend' => RateLimits::TWO_FACTOR_RESEND,
            'api/auth/forgot-password' => RateLimits::FORGOT_PASSWORD,
            'api/auth/reset-password' => RateLimits::RESET_PASSWORD,
            'api/change-password' => RateLimits::CHANGE_PASSWORD,
            'api/auth/confirm-password' => RateLimits::CONFIRM_PASSWORD,
        ];

        foreach ($expected as $uri => $limiter) {
            $route = collect(Route::getRoutes()->getRoutes())->first(fn ($route): bool => $route->uri() === $uri);
            $this->assertNotNull($route, $uri);
            $this->assertContains('throttle:'.$limiter, $route->gatherMiddleware(), $uri);
        }
    }

    /** @param  Application  $app */
    protected function enableCredentials($app): void
    {
        $app['config']->set('bherila-auth.oauth_server.credentials.enabled', true);
    }

    #[DefineEnvironment('enableCredentials')]
    public function test_issuing_api_credentials_has_its_own_limiter_rather_than_the_shared_unprefixed_one(): void
    {

        foreach (['bherila-auth.credentials.tokens.store', 'bherila-auth.credentials.apps.store'] as $name) {
            $middleware = Route::getRoutes()->getByName($name)?->gatherMiddleware() ?? [];
            $this->assertContains('throttle:'.RateLimits::CREDENTIALS, $middleware, $name);
            $this->assertNotContains('throttle:10,1', $middleware, $name);
        }
    }

    public function test_an_application_limiter_of_the_same_name_is_kept(): void
    {
        RateLimiter::for(RateLimits::FORGOT_PASSWORD, fn (): Limit => Limit::perMinute(1)->by('everyone'));
        RateLimits::register();
        Mail::fake();

        $this->postFrom('203.0.113.1', '/api/auth/forgot-password', ['email' => 'a@example.com'])->assertOk();
        $this->postFrom('203.0.113.2', '/api/auth/forgot-password', ['email' => 'b@example.com'])->assertStatus(429);
    }

    public function test_a_dimension_can_be_removed_or_every_limit_turned_off(): void
    {
        Mail::fake();
        config(['bherila-auth.rate_limits.forgot_password.email' => null]);
        foreach (range(1, 6) as $ip) {
            $this->postFrom("203.0.113.{$ip}", '/api/auth/forgot-password', ['email' => 'user@example.com'])->assertOk();
        }

        config(['bherila-auth.rate_limits.enabled' => false]);
        foreach (range(1, 70) as $attempt) {
            $this->postJson('/api/auth/two-factor/verify', ['attempt_token' => 'missing', 'code' => '123456'])->assertStatus(422);
        }
    }

    public function test_an_unreadable_limit_fails_loudly_rather_than_open(): void
    {
        config(['bherila-auth.rate_limits.forgot_password.ip' => [0, 1]]);

        $limiter = RateLimiter::limiter(RateLimits::FORGOT_PASSWORD);
        $this->assertNotNull($limiter);

        $this->expectException(InvalidArgumentException::class);
        $limiter(request());
    }
}
