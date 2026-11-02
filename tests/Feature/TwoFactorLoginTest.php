<?php

namespace BWH\Auth\Tests\Feature;

use BWH\Auth\Contracts\AuthUserPolicy;
use BWH\Auth\Events\TwoFactorLoginSucceeded;
use BWH\Auth\Models\TwoFactorAttempt;
use BWH\Auth\Services\DefaultAuthUserPolicy;
use BWH\Auth\Tests\Fixtures\User;
use BWH\Auth\Tests\TestCase;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Schema;

class TwoFactorLoginTest extends TestCase
{
    protected function defineDatabaseMigrations(): void
    {
        parent::defineDatabaseMigrations();

        // `is_test` is an application column the package only reads; the fixture app
        // needs one for the fixed-code tests below.
        Schema::table('users', function (Blueprint $table): void {
            $table->boolean('is_test')->default(false);
        });
    }

    private function user(array $attributes = []): User
    {
        return User::create(array_merge([
            'name' => 'Test',
            'email' => 'user@example.com',
            'password' => bcrypt('secret-password'),
        ], $attributes));
    }

    /**
     * A challenge whose real code is deliberately not the fixed test code.
     *
     * TwoFactorAttempt::createForUser() draws a random six-digit code, which is 999999
     * one time in a million — enough to make a "the bypass is refused" test pass by
     * authenticating for real.
     */
    private function attemptWithCodeOtherThanTheTestCode(User $user): TwoFactorAttempt
    {
        $attempt = TwoFactorAttempt::createForUser($user);
        $attempt->forceFill(['code' => '123456'])->save();

        $this->assertNotSame(config('bherila-auth.two_factor.test_code'), $attempt->code);

        return $attempt;
    }

    private function denyLogins(): void
    {
        $this->app->bind(AuthUserPolicy::class, fn () => new class extends DefaultAuthUserPolicy
        {
            public function canLogin(Authenticatable $user, Request $request): bool
            {
                return false;
            }
        });
    }

    public function test_verify_logs_the_user_in_with_the_emailed_code(): void
    {
        $user = $this->user();
        $attempt = TwoFactorAttempt::createForUser($user);

        $this->postJson('/api/auth/two-factor/verify', [
            'attempt_token' => $attempt->token,
            'code' => $attempt->code,
        ])->assertOk()->assertJson(['success' => true]);

        $this->assertAuthenticatedAs($user);
        $this->assertTrue($attempt->fresh()->is_used);
    }

    public function test_verifying_a_code_announces_the_sign_in_and_a_wrong_code_does_not(): void
    {
        Event::fake([TwoFactorLoginSucceeded::class]);
        $user = $this->user();
        $attempt = TwoFactorAttempt::createForUser($user);

        $this->postJson('/api/auth/two-factor/verify', ['attempt_token' => $attempt->token, 'code' => 'wrong!']);
        Event::assertNotDispatched(TwoFactorLoginSucceeded::class);

        $this->postJson('/api/auth/two-factor/verify', ['attempt_token' => $attempt->token, 'code' => $attempt->code])->assertOk();
        Event::assertDispatched(TwoFactorLoginSucceeded::class, fn (TwoFactorLoginSucceeded $event): bool => $event->user->is($user));
    }

    public function test_verify_refuses_an_account_disabled_after_the_challenge_was_created(): void
    {
        $user = $this->user();
        $attempt = TwoFactorAttempt::createForUser($user);

        $this->denyLogins();

        $this->postJson('/api/auth/two-factor/verify', [
            'attempt_token' => $attempt->token,
            'code' => $attempt->code,
        ])->assertStatus(422)->assertJson(['success' => false]);

        $this->assertGuest();
        // The challenge is spent either way, so the same code cannot be replayed.
        $this->assertTrue($attempt->fresh()->is_used);
    }

    public function test_confirm_link_refuses_an_account_that_may_no_longer_log_in(): void
    {
        $user = $this->user();
        $attempt = TwoFactorAttempt::createForUser($user);

        $this->denyLogins();

        $this->postJson('/api/auth/two-factor/confirm/'.$attempt->token)
            ->assertStatus(422)
            ->assertJson(['success' => false]);

        $this->assertGuest();
        $this->assertTrue($attempt->fresh()->is_used);
    }

    public function test_resend_refuses_an_expired_attempt(): void
    {
        Mail::fake();

        $user = $this->user();
        $attempt = TwoFactorAttempt::createForUser($user);
        $attempt->forceFill(['expires_at' => now()->subMinute()])->save();

        $this->postJson('/api/auth/two-factor/resend', ['attempt_token' => $attempt->token])
            ->assertStatus(422)
            ->assertJson(['success' => false]);

        $this->assertSame(1, TwoFactorAttempt::query()->count());
    }

    public function test_resend_issues_a_new_attempt_for_a_live_challenge(): void
    {
        Mail::fake();

        $user = $this->user();
        $attempt = TwoFactorAttempt::createForUser($user);

        $this->postJson('/api/auth/two-factor/resend', ['attempt_token' => $attempt->token])
            ->assertOk()
            ->assertJson(['success' => true]);

        $this->assertTrue($attempt->fresh()->is_used);
        $this->assertSame(2, TwoFactorAttempt::query()->count());
    }

    public function test_test_code_is_rejected_for_a_test_user_when_the_setting_is_off(): void
    {
        config(['bherila-auth.two_factor.allow_test_code' => false]);

        $user = $this->user(['is_test' => true]);
        $attempt = $this->attemptWithCodeOtherThanTheTestCode($user);

        $this->postJson('/api/auth/two-factor/verify', [
            'attempt_token' => $attempt->token,
            'code' => config('bherila-auth.two_factor.test_code'),
        ])->assertStatus(422);

        $this->assertGuest();
    }

    public function test_test_code_is_rejected_for_a_non_test_user_when_the_setting_is_on(): void
    {
        config(['bherila-auth.two_factor.allow_test_code' => true]);

        $user = $this->user(['is_test' => false]);
        $attempt = $this->attemptWithCodeOtherThanTheTestCode($user);

        $this->postJson('/api/auth/two-factor/verify', [
            'attempt_token' => $attempt->token,
            'code' => config('bherila-auth.two_factor.test_code'),
        ])->assertStatus(422);

        $this->assertGuest();
    }

    public function test_test_code_is_rejected_outside_the_allowed_environments(): void
    {
        // The environment allowlist deliberately excludes the one the app is running in,
        // standing in for the staging deploy the old default would have let through.
        config([
            'bherila-auth.two_factor.allow_test_code' => true,
            'bherila-auth.two_factor.test_code_environments' => ['local'],
        ]);

        $user = $this->user(['is_test' => true]);
        $attempt = $this->attemptWithCodeOtherThanTheTestCode($user);

        $this->postJson('/api/auth/two-factor/verify', [
            'attempt_token' => $attempt->token,
            'code' => config('bherila-auth.two_factor.test_code'),
        ])->assertStatus(422);

        $this->assertGuest();
    }

    public function test_test_code_works_when_every_condition_holds(): void
    {
        config(['bherila-auth.two_factor.allow_test_code' => true]);

        $user = $this->user(['is_test' => true]);
        $attempt = $this->attemptWithCodeOtherThanTheTestCode($user);

        $this->postJson('/api/auth/two-factor/verify', [
            'attempt_token' => $attempt->token,
            'code' => config('bherila-auth.two_factor.test_code'),
        ])->assertOk();

        $this->assertAuthenticatedAs($user);
    }
}
