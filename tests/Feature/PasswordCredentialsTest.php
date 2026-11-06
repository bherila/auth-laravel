<?php

namespace BWH\Auth\Tests\Feature;

use BWH\Auth\Contracts\AuthUserPolicy;
use BWH\Auth\Services\DefaultAuthUserPolicy;
use BWH\Auth\Services\PasswordCredentials;
use BWH\Auth\Support\PasswordCredentialStatus;
use BWH\Auth\Tests\Fixtures\User;
use BWH\Auth\Tests\TestCase;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Validated;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use LogicException;
use Mockery;

class PasswordCredentialsTest extends TestCase
{
    private function user(): User
    {
        return User::create(['name' => 'Example Person', 'email' => 'person@example.test',
            'password' => Hash::make('example-password'), 'remember_token' => 'existing-remember-token']);
    }

    private function request(): Request
    {
        $request = Request::create('/login', 'POST');
        $request->setLaravelSession(app('session')->driver());
        $request->session()->put('existing', 'session-value');

        return $request;
    }

    public function test_valid_preflight_does_not_authenticate_or_mutate_a_session_or_remember_cookie(): void
    {
        Event::fake([Login::class, Failed::class, Validated::class]);
        $user = $this->user();
        $request = $this->request();
        $sessionId = $request->session()->getId();
        $before = $request->session()->all();
        $result = app(PasswordCredentials::class)->verify($request, ['email' => $user->email, 'password' => 'example-password']);

        $this->assertSame(PasswordCredentialStatus::Verified, $result->status);
        $this->assertTrue($user->is($result->user));
        $this->assertGuest();
        $this->assertSame($sessionId, $request->session()->getId());
        $this->assertSame($before, $request->session()->all());
        $this->assertSame('existing-remember-token', $user->fresh()->remember_token);
        $this->assertSame([], app('cookie')->getQueuedCookies());
        $this->assertDatabaseCount('auth_audit_log', 0);
        Event::assertNotDispatched(Login::class);
        Event::assertNotDispatched(Failed::class);
        Event::assertDispatchedTimes(Validated::class, 1);
    }

    public function test_missing_and_incorrect_credentials_return_a_typed_failure_without_login_or_audit(): void
    {
        Event::fake([Login::class, Failed::class]);
        $user = $this->user();
        $service = app(PasswordCredentials::class);
        $incorrect = $service->verify($this->request(), ['email' => $user->email, 'password' => 'incorrect']);
        $missing = $service->verify($this->request(), ['email' => 'missing@example.test', 'password' => 'example-password']);

        $this->assertSame(PasswordCredentialStatus::InvalidCredentials, $incorrect->status);
        $this->assertTrue($user->is($incorrect->user));
        $this->assertSame(PasswordCredentialStatus::InvalidCredentials, $missing->status);
        $this->assertNull($missing->user);
        $this->assertGuest();
        $this->assertDatabaseCount('auth_audit_log', 0);
        Event::assertNotDispatched(Login::class);
        Event::assertNotDispatched(Failed::class);
    }

    public function test_policy_denial_is_checked_after_password_validation_and_before_rehash(): void
    {
        $user = $this->user();
        $provider = Mockery::mock(UserProvider::class);
        $credentials = ['email' => $user->email, 'password' => 'example-password'];
        $provider->shouldReceive('retrieveByCredentials')->once()->with($credentials)->andReturn($user);
        $provider->shouldReceive('validateCredentials')->once()->with($user, $credentials)->andReturnTrue();
        $provider->shouldNotReceive('rehashPasswordIfRequired');
        Auth::guard()->setProvider($provider);
        $this->app->bind(AuthUserPolicy::class, fn () => new class extends DefaultAuthUserPolicy
        {
            public function canLogin(Authenticatable $user, Request $request): bool
            {
                return false;
            }
        });
        $result = app(PasswordCredentials::class)->verify($this->request(), $credentials);

        $this->assertSame(PasswordCredentialStatus::AccountDisabled, $result->status);
        $this->assertSame($user, $result->user);
        $this->assertGuest();
    }

    public function test_rehash_uses_the_user_provider_only_when_enabled(): void
    {
        $user = $this->user();
        $provider = Mockery::mock(UserProvider::class);
        $credentials = ['email' => $user->email, 'password' => 'example-password'];
        $provider->shouldReceive('retrieveByCredentials')->twice()->with($credentials)->andReturn($user);
        $provider->shouldReceive('validateCredentials')->twice()->with($user, $credentials)->andReturnTrue();
        $provider->shouldReceive('rehashPasswordIfRequired')->once()->with($user, $credentials);
        Auth::guard()->setProvider($provider);
        config(['hashing.rehash_on_login' => false]);
        $this->assertSame(PasswordCredentialStatus::Verified, app(PasswordCredentials::class)->verify($this->request(), $credentials)->status);
        config(['hashing.rehash_on_login' => true]);
        $this->assertSame(PasswordCredentialStatus::Verified, app(PasswordCredentials::class)->verify($this->request(), $credentials)->status);
    }

    public function test_an_accepted_password_is_rehashed_without_signing_in(): void
    {
        $user = $this->user();
        $user->forceFill(['password' => Hash::make('example-password', ['rounds' => 4])])->save();
        Hash::driver('bcrypt')->setRounds(5);
        $this->assertTrue(Hash::needsRehash($user->password));

        app(PasswordCredentials::class)->verify($this->request(), ['email' => $user->email, 'password' => 'example-password']);

        $this->assertFalse(Hash::needsRehash($user->fresh()->password));
        $this->assertTrue(Hash::check('example-password', $user->fresh()->password));
        $this->assertGuest();
    }

    public function test_guard_selection_is_resolved_per_call_and_never_changes_another_guards_session(): void
    {
        $user = $this->user();
        config(['auth.guards.directory' => ['driver' => 'session', 'provider' => 'users']]);
        $provider = Mockery::mock(UserProvider::class);
        $credentials = ['email' => 'directory@example.test', 'password' => 'directory-password'];
        $provider->shouldReceive('retrieveByCredentials')->twice()->with($credentials)->andReturn($user);
        $provider->shouldReceive('validateCredentials')->twice()->with($user, $credentials)->andReturnTrue();
        $provider->shouldReceive('rehashPasswordIfRequired')->twice()->with($user, $credentials);
        Auth::guard('directory')->setProvider($provider);
        Auth::guard('web')->login($user);
        $service = app(PasswordCredentials::class);

        $this->assertSame(PasswordCredentialStatus::Verified, $service->verify($this->request(), $credentials, 'directory')->status);
        $this->assertSame('web', Auth::getDefaultDriver());
        Auth::shouldUse('directory');
        $this->assertSame(PasswordCredentialStatus::Verified, $service->verify($this->request(), $credentials)->status);
        $this->assertGuest('directory');
        $this->assertAuthenticatedAs($user, 'web');
    }

    public function test_non_session_guards_are_refused_without_falling_back_to_the_default(): void
    {
        Auth::viaRequest('example-request', fn () => null);
        config(['auth.guards.request-only' => ['driver' => 'example-request']]);
        $this->expectException(LogicException::class);
        app(PasswordCredentials::class)->verify($this->request(), ['email' => 'person@example.test', 'password' => 'example-password'], 'request-only');
    }
}
