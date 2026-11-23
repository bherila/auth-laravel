<?php

namespace BWH\Auth\Tests\Feature;

use BWH\Auth\Http\Middleware\RequireActiveProviderSession;
use BWH\Auth\OAuth\OAuthIdentity;
use BWH\Auth\OAuth\Session\ProviderBinding;
use BWH\Auth\OAuth\Session\ProviderSession;
use BWH\Auth\OAuth\Session\ProviderSessionExpired;
use BWH\Auth\OAuth\Session\RememberedProviderLogins;
use BWH\Auth\Tests\Fixtures\User;
use BWH\Auth\Tests\TestCase;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Illuminate\Testing\TestResponse;

/**
 * A session restored from a remember-me cookie keeps being checked by provider lifecycle
 * enforcement, with the baseline of the login that issued the cookie, and a sign-in made
 * through another method (a social login) of a bound account is checked from the provider's
 * current answer. Neither may let a cookie or a session outlive a reset, disable or ungrant.
 */
class RememberedProviderLoginTest extends TestCase
{
    /** The generation the provider reports now; sign-ins are made under it unless a test says. */
    private int $current = 7;

    protected function defineDatabaseMigrations(): void
    {
        parent::defineDatabaseMigrations();

        Schema::table('users', function (Blueprint $table): void {
            $table->string('oauth_provider')->nullable();
            $table->string('oauth_subject')->nullable();
        });
    }

    protected function setUp(): void
    {
        parent::setUp();
        config(['app.env' => 'testing']);
        config(['bherila-auth.oauth_client' => [
            'provider' => 'example-provider',
            'base_url' => 'https://identity.example.test',
            'client_id' => 'example-client',
            'client_secret' => 'example-secret',
            'redirect_uri' => 'https://app.example.test/oauth/callback',
            'token_path' => '/oauth/token',
            'identity_path' => '/api/oauth/user',
        ]]);
        config(['bherila-auth.provider_identity.enabled' => true]);
        $this->travelTo(Carbon::parse('2026-01-01T00:00:00Z'));
        Http::preventStrayRequests();

        Route::middleware('web')->group(function (): void {
            // A provider sign-in as RelyingPartyLoginController makes it with remember-me on.
            Route::post('/test-login', function (Request $request) {
                $user = User::query()->where('oauth_subject', 'subject-example')->sole();
                $generation = $request->integer('generation');
                $guard = Auth::guard('web');
                $session = app(ProviderSession::class);
                if (! $request->boolean('unprepared')) {
                    $session->prepareRememberedLogin($request, $guard, $user, 'example-provider', 'subject-example', $generation);
                }
                $guard->login($user, true);
                $request->session()->regenerate();
                $session->establish($request, new OAuthIdentity('example-provider', 'subject-example',
                    'Example User', 'user@example.test', credentialVersion: $generation), $guard);

                return 'signed in';
            });
            // A sign-in through another method of a bound account (games' Google sign-in).
            Route::post('/test-social-login', function (Request $request) {
                $user = User::query()->where('oauth_subject', 'subject-example')->sole();
                $guard = Auth::guard('web');
                $session = app(ProviderSession::class);
                try {
                    $observation = $session->observe(new ProviderBinding('example-provider', 'subject-example'));
                } catch (ProviderSessionExpired) {
                    return response('refused', 403);
                }
                if ($observation !== null) {
                    $session->prepareRememberedLogin($request, $guard, $user,
                        $observation->provider, $observation->subject, $observation->generation);
                }
                $guard->login($user, true);
                $request->session()->regenerate();
                if ($observation !== null) {
                    $session->establishObserved($request, $guard, $observation, 'Example User', 'user@example.test');
                }

                return 'signed in';
            });
        });
        Route::middleware(['web', RequireActiveProviderSession::class])->get('/private', fn () => 'ok');
        Route::get('/', fn () => 'home');
    }

    /** The provider answers active, at whatever generation $current holds when asked. */
    private function fakeStatus(): void
    {
        Http::fake(fn () => Http::response($this->status()));
    }

    private function status(): array
    {
        return ['contract_version' => 1, 'active' => true, 'subject' => 'subject-example', 'credential_version' => $this->current];
    }

    private function user(): User
    {
        return User::query()->create([
            'name' => 'Example User', 'email' => 'user@example.test', 'password' => 'unused',
            'oauth_provider' => 'example-provider', 'oauth_subject' => 'subject-example',
        ]);
    }

    private function recallerName(): string
    {
        return Auth::guard('web')->getRecallerName();
    }

    /** Sign in on one device and return that device's remember-me cookie value. */
    private function signIn(?int $generation = null, bool $prepared = true, string $path = '/test-login'): string
    {
        $response = $this->post($path, ['generation' => $generation ?? $this->current, 'unprepared' => ! $prepared]);
        $response->assertOk();
        $cookie = $response->getCookie($this->recallerName());
        $this->assertNotNull($cookie, 'A remembered sign-in sets the remember-me cookie.');
        $this->newBrowser();

        return $cookie->getValue();
    }

    /** Forget the in-memory session and guard, as a browser whose session has ended. */
    private function newBrowser(): void
    {
        $this->flushSession();
        Auth::forgetGuards();
        $this->defaultCookies = [];
        $this->unencryptedCookies = [];
    }

    private function restore(string $cookie): TestResponse
    {
        $response = $this->withCookie($this->recallerName(), $cookie)->get('/private');
        $this->newBrowser();

        return $response;
    }

    private function row(): ?object
    {
        return DB::table(RememberedProviderLogins::TABLE)->first();
    }

    public function test_a_restored_session_adopts_the_baseline_of_the_login_that_set_its_cookie(): void
    {
        $this->fakeStatus();
        $this->user();
        $cookie = $this->signIn();

        $this->assertSame(7, (int) $this->row()->generation);
        $this->assertSame(RememberedProviderLogins::tokenHash((string) User::query()->sole()->remember_token), $this->row()->token_hash);

        $this->restore($cookie)->assertOk()->assertSee('ok');
        Http::assertSentCount(1);
    }

    public function test_a_restored_session_ends_once_the_provider_has_moved_on(): void
    {
        $this->fakeStatus();
        $this->user();
        $cookie = $this->signIn();
        $this->current = 8;

        $this->restore($cookie)->assertRedirect('/');
    }

    public function test_a_restored_session_ends_when_the_identity_is_disabled(): void
    {
        $this->user();
        $cookie = $this->signIn();
        Http::fake(fn () => Http::response(['contract_version' => 1, 'active' => false]));

        $this->restore($cookie)->assertRedirect('/');
    }

    public function test_a_sign_in_under_a_newer_generation_retires_every_older_cookie(): void
    {
        $this->fakeStatus();
        $user = $this->user();
        $old = $this->signIn();
        $oldToken = $user->fresh()->remember_token;

        // The person resets their password at the provider, then signs in on another device.
        $this->current = 8;
        $new = $this->signIn();

        $this->assertNotSame($oldToken, $user->fresh()->remember_token);
        $this->assertSame(8, (int) $this->row()->generation);
        // The old cookie names a token the account no longer has: it authenticates nobody.
        $this->withCookie($this->recallerName(), $old)->get('/private')->assertOk();
        $this->assertGuest('web');
        $this->newBrowser();
        $this->restore($new)->assertOk();
    }

    public function test_a_sign_in_under_the_same_baseline_keeps_other_devices_signed_in(): void
    {
        $this->fakeStatus();
        $user = $this->user();
        $first = $this->signIn();
        $token = $user->fresh()->remember_token;

        $this->signIn();

        $this->assertSame($token, $user->fresh()->remember_token);
        $this->restore($first)->assertOk()->assertSee('ok');
    }

    public function test_the_first_remembered_sign_in_retires_a_token_issued_before_any_baseline_was_kept(): void
    {
        $user = $this->user();
        $user->forceFill(['remember_token' => 'token-from-an-earlier-release'])->save();

        $this->signIn();

        $this->assertNotSame('token-from-an-earlier-release', $user->fresh()->remember_token);
    }

    public function test_an_unprepared_remembered_sign_in_records_nothing_and_its_cookie_must_sign_in_again(): void
    {
        $this->user();
        $cookie = $this->signIn(prepared: false);

        $this->assertNull($this->row());
        $this->restore($cookie)->assertRedirect('/');
    }

    public function test_with_enforcement_off_the_baseline_is_still_kept_for_later(): void
    {
        config(['bherila-auth.provider_identity.enabled' => false]);
        $this->user();
        $cookie = $this->signIn();
        Http::assertNothingSent();

        config(['bherila-auth.provider_identity.enabled' => true]);
        $this->fakeStatus();
        $this->restore($cookie)->assertOk()->assertSee('ok');
    }

    public function test_before_the_migration_a_remembered_sign_in_still_succeeds(): void
    {
        Schema::drop(RememberedProviderLogins::TABLE);
        $this->user();

        $cookie = $this->signIn();

        $this->restore($cookie)->assertRedirect('/');
    }

    public function test_a_social_sign_in_of_a_bound_account_is_baselined_from_the_current_answer(): void
    {
        $this->fakeStatus();
        $this->user();
        $cookie = $this->signIn(path: '/test-social-login');

        $this->assertSame(7, (int) $this->row()->generation);
        Http::assertSentCount(1);
        $this->restore($cookie)->assertOk()->assertSee('ok');

        $this->current = 8;
        $this->travel(300)->seconds();
        $this->restore($cookie)->assertRedirect('/');
    }

    public function test_a_social_sign_in_is_refused_for_an_identity_the_provider_has_ended(): void
    {
        $this->user();
        Http::fake(fn () => Http::response(['contract_version' => 1, 'active' => false]));

        $this->post('/test-social-login')->assertForbidden();
        $this->assertGuest('web');
    }

    public function test_a_social_sign_in_answers_503_while_the_provider_is_unavailable(): void
    {
        $this->user();
        Http::fake(fn () => Http::response('', 503));

        $this->postJson('/test-social-login')->assertStatus(503)->assertHeader('Retry-After', '30');
        $this->assertGuest('web');
    }

    public function test_with_enforcement_off_a_social_sign_in_proceeds_whatever_the_provider_says(): void
    {
        config(['bherila-auth.provider_identity.enabled' => false]);
        $this->user();
        Http::fake(fn () => Http::response('', 503));

        $this->post('/test-social-login')->assertOk();
        $this->assertNull($this->row());
    }

    public function test_forgetting_an_account_removes_its_rows(): void
    {
        $user = $this->user();
        $this->signIn();

        app(RememberedProviderLogins::class)->forgetUser((string) $user->getKey());

        $this->assertNull($this->row());
    }
}
