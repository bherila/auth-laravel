<?php

namespace BWH\Auth\Tests\Feature;

use BWH\Auth\Contracts\LocalCredentialPolicy;
use BWH\Auth\Mail\PasswordResetConfirmationMail;
use BWH\Auth\Models\TwoFactorAttempt;
use BWH\Auth\Tests\Fixtures\User;
use BWH\Auth\Tests\TestCase;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Password;
use Illuminate\Support\Facades\Schema;

final class LocalCredentialPolicyTest extends TestCase
{
    private const PROVIDER = 'test-provider';

    protected function defineDatabaseMigrations(): void
    {
        parent::defineDatabaseMigrations();

        Schema::table('users', function (Blueprint $table): void {
            $table->string('oauth_provider', 64)->nullable();
            $table->string('oauth_subject', 191)->nullable();
        });
    }

    protected function setUp(): void
    {
        parent::setUp();

        config()->set('bherila-auth.oauth_client.provider', self::PROVIDER);
    }

    private function user(bool $bound, array $attributes = []): User
    {
        static $n = 0;
        $n++;

        return User::create(array_merge([
            'name' => 'Test '.$n,
            'email' => "user{$n}@example.com",
            'password' => bcrypt('old-password-1'),
            'oauth_provider' => $bound ? self::PROVIDER : null,
            'oauth_subject' => $bound ? 'subject-'.$n : null,
        ], $attributes));
    }

    private function refuse(): void
    {
        config()->set('bherila-auth.local_credentials.provider_bound', 'refuse');
    }

    /** @return array<string, mixed> */
    private function resetPayload(User $user, string $token): array
    {
        return [
            'token' => $token,
            'email' => $user->email,
            'password' => 'new-password-1234',
            'password_confirmation' => 'new-password-1234',
        ];
    }

    // ---- default ('allow'): nothing changes for a bound account ----

    public function test_by_default_a_bound_account_can_request_a_reset(): void
    {
        Mail::fake();
        $user = $this->user(true);

        $this->postJson('/api/auth/forgot-password', ['email' => $user->email])->assertOk();

        Mail::assertSent(PasswordResetConfirmationMail::class);
    }

    public function test_by_default_a_bound_account_can_complete_a_reset(): void
    {
        Mail::fake();
        $user = $this->user(true);
        $token = Password::broker()->createToken($user);

        $this->postJson('/api/auth/reset-password', $this->resetPayload($user, $token))->assertOk();

        $this->assertTrue(Hash::check('new-password-1234', $user->fresh()->password));
    }

    public function test_by_default_a_bound_account_can_change_its_password(): void
    {
        Mail::fake();
        $user = $this->user(true);

        $this->actingAs($user)->postJson('/api/change-password', [
            'current_password' => 'old-password-1',
            'password' => 'new-password-1234',
            'password_confirmation' => 'new-password-1234',
        ])->assertOk();

        $this->assertTrue(Hash::check('new-password-1234', $user->fresh()->password));
    }

    public function test_by_default_a_bound_account_can_complete_a_two_factor_login(): void
    {
        $user = $this->user(true);
        $attempt = TwoFactorAttempt::createForUser($user);

        $this->postJson('/api/auth/two-factor/verify', [
            'attempt_token' => $attempt->token,
            'code' => $attempt->code,
        ])->assertOk()->assertJson(['success' => true]);

        $this->assertAuthenticatedAs($user);
    }

    // ---- 'refuse' ----

    public function test_refuse_sends_no_reset_mail_to_a_bound_account_and_answers_like_an_unknown_address(): void
    {
        $this->refuse();
        Mail::fake();
        $bound = $this->user(true);

        $boundResponse = $this->postJson('/api/auth/forgot-password', ['email' => $bound->email]);
        $unknownResponse = $this->postJson('/api/auth/forgot-password', ['email' => 'nobody@example.com']);

        Mail::assertNothingSent();
        $boundResponse->assertOk();
        $this->assertSame($unknownResponse->getStatusCode(), $boundResponse->getStatusCode());
        $this->assertSame($unknownResponse->json(), $boundResponse->json());
    }

    public function test_refuse_completing_a_reset_for_a_bound_account_returns_422_and_keeps_the_password(): void
    {
        $this->refuse();
        $user = $this->user(true);
        $oldHash = $user->password;
        $token = Password::broker()->createToken($user);

        $this->postJson('/api/auth/reset-password', $this->resetPayload($user, $token))
            ->assertStatus(422)
            ->assertJson(['success' => false]);

        $this->assertSame($oldHash, $user->fresh()->password);
        $this->assertGuest();
    }

    public function test_refuse_blocks_change_password_for_a_bound_account(): void
    {
        $this->refuse();
        $user = $this->user(true);
        $oldHash = $user->password;

        $this->actingAs($user)->postJson('/api/change-password', [
            'current_password' => 'old-password-1',
            'password' => 'new-password-1234',
            'password_confirmation' => 'new-password-1234',
        ])->assertForbidden();

        $this->assertSame($oldHash, $user->fresh()->password);
    }

    public function test_refuse_blocks_passkey_registration_for_a_bound_account(): void
    {
        $this->refuse();
        $user = $this->user(true);

        $this->actingAs($user)->postJson('/api/passkeys/register/options')->assertForbidden();
        $this->actingAs($user)->postJson('/api/passkeys/register', ['credential' => ['id' => 'x']])->assertForbidden();
    }

    public function test_refuse_fails_a_two_factor_login_for_a_bound_account(): void
    {
        $this->refuse();
        $user = $this->user(true);
        $attempt = TwoFactorAttempt::createForUser($user);

        $this->postJson('/api/auth/two-factor/verify', [
            'attempt_token' => $attempt->token,
            'code' => $attempt->code,
        ])->assertStatus(422)->assertJson(['success' => false]);

        $this->assertGuest();
    }

    public function test_refuse_leaves_an_unbound_account_with_every_local_credential_path(): void
    {
        $this->refuse();
        Mail::fake();
        $user = $this->user(false);

        $this->postJson('/api/auth/forgot-password', ['email' => $user->email])->assertOk();
        Mail::assertSent(PasswordResetConfirmationMail::class);

        $token = Password::broker()->createToken($user);
        $this->postJson('/api/auth/reset-password', $this->resetPayload($user, $token))->assertOk();
        $this->assertTrue(Hash::check('new-password-1234', $user->fresh()->password));
        $this->app['auth']->guard()->logout();

        $this->actingAs($user->fresh())->postJson('/api/change-password', [
            'current_password' => 'new-password-1234',
            'password' => 'newer-password-5678',
            'password_confirmation' => 'newer-password-5678',
        ])->assertOk();

        $this->actingAs($user)->postJson('/api/passkeys/register/options')->assertOk();

        $this->app['auth']->guard()->logout();
        $attempt = TwoFactorAttempt::createForUser($user);
        $this->postJson('/api/auth/two-factor/verify', [
            'attempt_token' => $attempt->token,
            'code' => $attempt->code,
        ])->assertOk();
        $this->assertAuthenticatedAs($user);
    }

    public function test_refuse_treats_a_broken_binding_as_refused(): void
    {
        $this->refuse();
        Mail::fake();
        $user = $this->user(true, ['oauth_provider' => 'some-other-provider']);
        $oldHash = $user->password;

        $this->postJson('/api/auth/forgot-password', ['email' => $user->email])->assertOk();
        Mail::assertNothingSent();

        $token = Password::broker()->createToken($user);
        $this->postJson('/api/auth/reset-password', $this->resetPayload($user, $token))->assertStatus(422);
        $this->assertSame($oldHash, $user->fresh()->password);

        $this->actingAs($user)->postJson('/api/change-password', [
            'current_password' => 'old-password-1',
            'password' => 'new-password-1234',
            'password_confirmation' => 'new-password-1234',
        ])->assertForbidden();
    }

    // ---- the policy itself (a full WebAuthn assertion for passkey authenticate is impractical) ----

    public function test_policy_allows_everything_by_default_and_when_set_to_allow(): void
    {
        $policy = $this->app->make(LocalCredentialPolicy::class);
        $request = Request::create('/');

        $this->assertTrue($policy->mayUseLocalCredentials($this->user(true), $request));

        config()->set('bherila-auth.local_credentials.provider_bound', 'allow');
        $this->assertTrue($policy->mayUseLocalCredentials($this->user(true), $request));
    }

    public function test_policy_refuses_bound_and_broken_accounts_but_not_unbound_ones(): void
    {
        $this->refuse();
        $policy = $this->app->make(LocalCredentialPolicy::class);
        $request = Request::create('/');

        $this->assertFalse($policy->mayUseLocalCredentials($this->user(true), $request));
        $this->assertFalse($policy->mayUseLocalCredentials($this->user(true, ['oauth_provider' => 'other']), $request));
        $this->assertTrue($policy->mayUseLocalCredentials($this->user(false), $request));
    }

    public function test_policy_reads_the_stored_binding_when_the_columns_were_not_loaded(): void
    {
        $this->refuse();
        $policy = $this->app->make(LocalCredentialPolicy::class);

        // Selected without the binding columns, as `User::create()` or a narrow select leaves a
        // model: the stored row decides, rather than refusing every such account.
        $unbound = User::query()->select(['id', 'email', 'password'])->findOrFail($this->user(false)->getKey());
        $bound = User::query()->select(['id', 'email', 'password'])->findOrFail($this->user(true)->getKey());

        $this->assertTrue($policy->mayUseLocalCredentials($unbound, Request::create('/')));
        $this->assertFalse($policy->mayUseLocalCredentials($bound, Request::create('/')));
    }

    public function test_policy_refuses_an_unsaved_account_whose_binding_cannot_be_read(): void
    {
        $this->refuse();

        $unsaved = new User(['email' => 'unsaved@example.test']);

        $this->assertFalse($this->app->make(LocalCredentialPolicy::class)->mayUseLocalCredentials($unsaved, Request::create('/')));
    }

    public function test_an_invalid_setting_throws(): void
    {
        config()->set('bherila-auth.local_credentials.provider_bound', 'sometimes');

        $this->expectException(\LogicException::class);

        $this->app->make(LocalCredentialPolicy::class)->mayUseLocalCredentials($this->user(false), Request::create('/'));
    }
}
