<?php

namespace BWH\Auth\Tests\Feature;

use BWH\Auth\Contracts\AuthAuditLogger;
use BWH\Auth\Services\AbstractAuthAuditLogger;
use BWH\Auth\Tests\Fixtures\User;
use BWH\Auth\Tests\TestCase;
use Illuminate\Auth\Events\OtherDeviceLogout;
use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Cookie\CookieValuePrefix;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Session\Middleware\AuthenticateSession;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Password;
use Illuminate\Support\Facades\Route;
use Orchestra\Testbench\Attributes\DefineEnvironment;
use RuntimeException;

/**
 * A password the package changes or resets ends the account's other sessions: remember-me
 * cookies issued under the old password stop working, and database sessions are deleted.
 */
class PasswordChangeSessionsTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        Mail::fake();
    }

    private function user(?string $rememberToken = 'old-remember-token'): User
    {
        $user = User::create([
            'name' => 'Test',
            'email' => 'user@example.com',
            'password' => bcrypt('old-password'),
        ]);
        $user->forceFill(['remember_token' => $rememberToken])->save();

        return $user;
    }

    /** @return array<string, string> */
    private function change(string $current = 'old-password'): array
    {
        return ['current_password' => $current, 'password' => 'a-new-password-123', 'password_confirmation' => 'a-new-password-123'];
    }

    /** @param  Application  $app */
    protected function useDatabaseSessions($app): void
    {
        $app['config']->set('session.driver', 'database');
    }

    private function otherSession(string $id, int $userId): void
    {
        DB::table('sessions')->insert([
            'id' => $id,
            'user_id' => $userId,
            'ip_address' => '203.0.113.1',
            'user_agent' => 'Other device',
            'payload' => base64_encode(serialize([])),
            'last_activity' => now()->getTimestamp(),
        ]);
    }

    public function test_changing_the_password_retires_remember_me_cookies(): void
    {
        $user = $this->user();

        $this->actingAs($user)->postJson('/api/change-password', $this->change())->assertOk();

        $this->assertNotSame('old-remember-token', $user->fresh()->remember_token);
        $this->assertNotNull($user->fresh()->remember_token);
        $this->assertAuthenticatedAs($user);
    }

    public function test_an_account_without_a_remember_token_is_not_given_one(): void
    {
        $user = $this->user(null);

        $this->actingAs($user)->postJson('/api/change-password', $this->change())->assertOk();

        $this->assertNull($user->fresh()->remember_token);
    }

    public function test_a_refused_change_keeps_the_remember_token(): void
    {
        $user = $this->user();

        $this->actingAs($user)->postJson('/api/change-password', $this->change('wrong-password'))->assertStatus(422);

        $this->assertSame('old-remember-token', $user->fresh()->remember_token);
    }

    public function test_the_changing_device_keeps_its_remember_me_cookie(): void
    {
        $user = $this->user();
        $guard = Auth::guard();
        $recaller = $user->id.'|old-remember-token|'.$guard->hashPasswordForCookie($user->getAuthPassword());

        // Signed in by the remember-me cookie alone.
        $response = $this->withCredentials()->withCookie($guard->getRecallerName(), $recaller)
            ->postJson('/api/change-password', $this->change())->assertOk();

        $fresh = $user->fresh();
        $this->assertTrue(Hash::check('a-new-password-123', $fresh->password));
        $cookie = collect($response->headers->getCookies())->first(fn ($cookie): bool => $cookie->getName() === $guard->getRecallerName());
        $this->assertNotNull($cookie, 'The recaller cookie is reissued.');
        $this->assertSame(
            $fresh->id.'|'.$fresh->remember_token.'|'.$guard->hashPasswordForCookie($fresh->password),
            $this->decryptCookie($cookie->getName(), $cookie->getValue()),
        );
    }

    #[DefineEnvironment('useDatabaseSessions')]
    public function test_changing_the_password_deletes_the_accounts_other_database_sessions(): void
    {
        $user = $this->user();
        $other = User::create(['name' => 'Other', 'email' => 'other@example.com', 'password' => bcrypt('x')]);
        $this->otherSession('device-a', $user->id);
        $this->otherSession('device-b', $user->id);
        $this->otherSession('someone-else', $other->id);

        $this->actingAs($user)->postJson('/api/change-password', $this->change())->assertOk();

        $this->assertSame(['someone-else'], DB::table('sessions')->where('id', '!=', session()->getId())->pluck('id')->all());
        $this->assertSame((string) $user->id, (string) DB::table('sessions')->where('id', session()->getId())->value('user_id'));
    }

    #[DefineEnvironment('useDatabaseSessions')]
    public function test_resetting_the_password_deletes_the_accounts_database_sessions(): void
    {
        $user = $this->user();
        $this->otherSession('device-a', $user->id);
        $token = Password::broker()->createToken($user);

        $this->postJson('/api/auth/reset-password', [
            'token' => $token,
            'email' => $user->email,
            'password' => 'a-new-password-123',
            'password_confirmation' => 'a-new-password-123',
        ])->assertOk();

        $this->assertFalse(DB::table('sessions')->where('id', 'device-a')->exists());
        $this->assertNotSame('old-remember-token', $user->fresh()->remember_token);
        $this->assertAuthenticatedAs($user);
    }

    /** @return array<string, string> */
    private function reset(User $user): array
    {
        return [
            'token' => Password::broker()->createToken($user),
            'email' => $user->email,
            'password' => 'a-new-password-123',
            'password_confirmation' => 'a-new-password-123',
        ];
    }

    private function failMail(): void
    {
        Mail::shouldReceive('to')->andThrow(new RuntimeException('Mail transport is down.'));
    }

    #[DefineEnvironment('useDatabaseSessions')]
    public function test_a_reset_whose_notice_mail_fails_still_ends_the_other_sessions(): void
    {
        $user = $this->user();
        $this->otherSession('device-a', $user->id);
        $this->failMail();

        $this->postJson('/api/auth/reset-password', $this->reset($user))->assertServerError();

        $this->assertTrue(Hash::check('a-new-password-123', $user->fresh()->password));
        $this->assertFalse(DB::table('sessions')->where('id', 'device-a')->exists());
        $this->assertNotSame('old-remember-token', $user->fresh()->remember_token);
    }

    #[DefineEnvironment('useDatabaseSessions')]
    public function test_a_reset_whose_listener_throws_still_ends_the_other_sessions(): void
    {
        $user = $this->user();
        $this->otherSession('device-a', $user->id);
        Event::listen(PasswordReset::class, function (): void {
            throw new RuntimeException('A listener failed.');
        });

        $this->postJson('/api/auth/reset-password', $this->reset($user))->assertServerError();

        $this->assertFalse(DB::table('sessions')->where('id', 'device-a')->exists());
    }

    #[DefineEnvironment('useDatabaseSessions')]
    public function test_a_reset_whose_audit_fails_still_ends_the_other_sessions(): void
    {
        $user = $this->user();
        $this->otherSession('device-a', $user->id);
        $this->app->bind(AuthAuditLogger::class, fn () => new class extends AbstractAuthAuditLogger
        {
            public function passwordResetCompleted(Request $request, Authenticatable $user): void
            {
                throw new RuntimeException('The audit store is down.');
            }
        });

        $this->postJson('/api/auth/reset-password', $this->reset($user))->assertServerError();

        $this->assertFalse(DB::table('sessions')->where('id', 'device-a')->exists());
    }

    public function test_the_resetting_device_keeps_a_remember_me_cookie_it_held(): void
    {
        $user = $this->user();
        $guard = Auth::guard();
        $recaller = $user->id.'|old-remember-token|'.$guard->hashPasswordForCookie($user->getAuthPassword());
        $payload = $this->reset($user);

        $response = $this->withCredentials()->withCookie($guard->getRecallerName(), $recaller)
            ->postJson('/api/auth/reset-password', $payload)->assertOk();

        $fresh = $user->fresh();
        $cookie = collect($response->headers->getCookies())->first(fn ($cookie): bool => $cookie->getName() === $guard->getRecallerName());
        $this->assertNotNull($cookie, 'The recaller cookie is reissued.');
        $this->assertSame(
            $fresh->id.'|'.$fresh->remember_token.'|'.$guard->hashPasswordForCookie($fresh->password),
            $this->decryptCookie($cookie->getName(), $cookie->getValue()),
        );
    }

    #[DefineEnvironment('useDatabaseSessions')]
    public function test_a_change_whose_notice_mail_fails_still_ends_the_other_sessions(): void
    {
        $user = $this->user();
        $this->otherSession('device-a', $user->id);
        $this->failMail();

        $this->actingAs($user)->postJson('/api/change-password', $this->change())->assertServerError();

        $this->assertTrue(Hash::check('a-new-password-123', $user->fresh()->password));
        $this->assertFalse(DB::table('sessions')->where('id', 'device-a')->exists());
    }

    #[DefineEnvironment('useDatabaseSessions')]
    public function test_a_change_whose_other_device_logout_listener_throws_still_ends_the_other_sessions(): void
    {
        $user = $this->user();
        $this->otherSession('device-a', $user->id);
        Event::listen(OtherDeviceLogout::class, function (): void {
            throw new RuntimeException('A listener failed.');
        });
        $guard = Auth::guard();
        $recaller = $user->id.'|old-remember-token|'.$guard->hashPasswordForCookie($user->getAuthPassword());

        // The remember-me cookie makes the change reissue it, which announces OtherDeviceLogout.
        $this->withCredentials()->withCookie($guard->getRecallerName(), $recaller)
            ->postJson('/api/change-password', $this->change())->assertServerError();

        $this->assertFalse(DB::table('sessions')->where('id', 'device-a')->exists());
    }

    /** @param  Application  $app */
    protected function keepOtherSessions($app): void
    {
        $app['config']->set('session.driver', 'database');
        $app['config']->set('bherila-auth.sessions.end_other_sessions_on_password_change', false);
    }

    #[DefineEnvironment('keepOtherSessions')]
    public function test_ending_other_sessions_can_be_turned_off(): void
    {
        $user = $this->user();
        $this->otherSession('device-a', $user->id);

        $this->actingAs($user)->postJson('/api/change-password', $this->change())->assertOk();

        $this->assertTrue(DB::table('sessions')->where('id', 'device-a')->exists());
        $this->assertSame('old-remember-token', $user->fresh()->remember_token);
    }

    /** @param  Application  $app */
    protected function authenticateSessions($app): void
    {
        $app['config']->set('bherila-auth.routes.middleware', ['web', AuthenticateSession::class]);
    }

    #[DefineEnvironment('authenticateSessions')]
    public function test_with_authenticate_sessions_the_changing_session_survives_and_others_end(): void
    {
        Route::middleware(['web', AuthenticateSession::class, 'auth'])->get('/probe', fn () => 'signed in');
        Route::get('/login', fn () => 'sign in')->name('login');
        $user = $this->user();
        $oldHash = Auth::guard()->hashPasswordForCookie($user->password);

        $this->actingAs($user)->getJson('/probe')->assertOk();
        $this->postJson('/api/change-password', $this->change())->assertOk();
        $this->getJson('/probe')->assertOk();

        // Another device's session, signed in under the old password.
        $this->actingAs($user->fresh())->withSession(['password_hash_web' => $oldHash])->getJson('/probe')->assertUnauthorized();
    }

    private function decryptCookie(string $name, string $value): string
    {
        $decrypted = app('encrypter')->decrypt($value, false);

        return CookieValuePrefix::remove($decrypted);
    }
}
