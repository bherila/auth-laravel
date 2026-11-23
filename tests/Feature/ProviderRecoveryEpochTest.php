<?php

namespace BWH\Auth\Tests\Feature;

use BWH\Auth\Http\Middleware\RequireActiveProviderSession;
use BWH\Auth\OAuth\OAuthIdentity;
use BWH\Auth\OAuth\Session\ProviderBinding;
use BWH\Auth\OAuth\Session\ProviderIdentityStatusClient;
use BWH\Auth\OAuth\Session\ProviderSession;
use BWH\Auth\OAuth\Session\ProviderSessionExpired;
use BWH\Auth\OAuth\Session\ProviderStatusUnavailable;
use BWH\Auth\OAuth\Session\RememberedProviderLogins;
use BWH\Auth\Tests\Fixtures\User;
use BWH\Auth\Tests\TestCase;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\DataProvider;

/**
 * The provider's recovery epoch. A provider restored from a backup raises it, so every session,
 * remembered login and credential captured before the restore ends at its next check, even
 * though the restored database reports the old generation again. Captures from before the
 * provider reported an epoch carry none and are not compared.
 */
final class ProviderRecoveryEpochTest extends TestCase
{
    private ?int $epoch = 3;

    private int $generation = 7;

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

        Route::middleware('web')->post('/test-login', function (Request $request) {
            $user = User::query()->where('oauth_subject', 'subject-example')->sole();
            $epoch = $request->filled('epoch') ? $request->integer('epoch') : null;
            $guard = Auth::guard('web');
            $session = app(ProviderSession::class);
            $session->prepareRememberedLogin($request, $guard, $user, 'example-provider', 'subject-example', 7, $epoch);
            $guard->login($user, true);
            $request->session()->regenerate();
            $session->establish($request, new OAuthIdentity('example-provider', 'subject-example',
                'Example User', 'user@example.test', credentialVersion: 7, recoveryEpoch: $epoch), $guard);

            return 'signed in';
        });
        Route::middleware(['web', RequireActiveProviderSession::class])->get('/private', fn () => 'ok');
        Route::get('/', fn () => 'home');
    }

    /** The provider answers active at $generation with $epoch (none when null), read per request. */
    private function fakeStatus(): void
    {
        Http::fake(fn () => Http::response(['contract_version' => 1, 'active' => true,
            'subject' => 'subject-example', 'credential_version' => $this->generation]
            + ($this->epoch === null ? [] : ['recovery_epoch' => $this->epoch])));
    }

    private function user(): User
    {
        return User::query()->create([
            'name' => 'Example User', 'email' => 'user@example.test', 'password' => 'unused',
            'oauth_provider' => 'example-provider', 'oauth_subject' => 'subject-example',
        ]);
    }

    private function request(): Request
    {
        $request = Request::create('/private');
        $request->setLaravelSession(app('session.store'));

        return $request;
    }

    private function signedIn(?int $epoch): Request
    {
        $request = $this->request();
        app(ProviderSession::class)->remember($request, new OAuthIdentity('example-provider', 'subject-example',
            'Example User', 'user@example.test', credentialVersion: 7, recoveryEpoch: $epoch));

        return $request;
    }

    private function verify(Request $request): OAuthIdentity
    {
        return app(ProviderSession::class)->assertActive($request, 'example-provider', 'subject-example', fresh: true);
    }

    // --- Reading the epoch --------------------------------------------------

    public function test_the_status_answer_carries_the_epoch_when_the_provider_sends_one(): void
    {
        $this->fakeStatus();
        $this->assertSame(3, app(ProviderIdentityStatusClient::class)->status('subject-example')?->recoveryEpoch);
    }

    public function test_a_provider_that_sends_no_epoch_still_answers(): void
    {
        $this->epoch = null;
        $this->fakeStatus();
        $status = app(ProviderIdentityStatusClient::class)->status('subject-example');

        $this->assertSame(7, $status?->credentialVersion);
        $this->assertNull($status?->recoveryEpoch);
    }

    /** @return array<string, array{mixed}> */
    public static function invalidEpochs(): array
    {
        return ['zero' => [0], 'negative' => [-1], 'a string' => ['3'], 'a fraction' => [3.5], 'a boolean' => [true]];
    }

    #[DataProvider('invalidEpochs')]
    public function test_a_malformed_epoch_is_an_unavailable_answer_not_a_missing_one(mixed $epoch): void
    {
        Http::fake(fn () => Http::response(['contract_version' => 1, 'active' => true,
            'subject' => 'subject-example', 'credential_version' => 7, 'recovery_epoch' => $epoch]));

        $this->expectException(ProviderStatusUnavailable::class);
        app(ProviderIdentityStatusClient::class)->status('subject-example');
    }

    // --- Browser sessions ---------------------------------------------------

    public function test_a_session_signed_in_under_the_current_epoch_stays_active(): void
    {
        $this->fakeStatus();

        $this->assertSame(3, $this->verify($this->signedIn(3))->recoveryEpoch);
    }

    public function test_a_restored_provider_ends_sessions_from_before_the_restore(): void
    {
        $this->fakeStatus();
        $request = $this->signedIn(3);
        $this->epoch = 4;

        $this->expectException(ProviderSessionExpired::class);
        $this->verify($request);
    }

    public function test_a_session_with_an_epoch_ends_when_the_provider_stops_reporting_one(): void
    {
        $this->fakeStatus();
        $request = $this->signedIn(3);
        $this->epoch = null;

        $this->expectException(ProviderSessionExpired::class);
        $this->verify($request);
    }

    public function test_a_session_from_before_the_provider_reported_an_epoch_is_not_compared(): void
    {
        $this->fakeStatus();
        $request = $this->signedIn(null);
        $this->epoch = 9;

        $this->assertNull($this->verify($request)->recoveryEpoch);
    }

    public function test_a_session_carrying_a_corrupt_epoch_is_ended(): void
    {
        $this->fakeStatus();
        $request = $this->signedIn(3);
        $state = $request->session()->get('bherila_auth.provider_session');
        $request->session()->put('bherila_auth.provider_session', ['epoch' => 'three'] + $state);

        $this->expectException(ProviderSessionExpired::class);
        $this->verify($request);
    }

    public function test_a_sign_in_through_another_method_takes_the_current_epoch(): void
    {
        $this->fakeStatus();
        $session = app(ProviderSession::class);
        $request = $this->request();

        $observation = $session->observe(new ProviderBinding('example-provider', 'subject-example'));
        $session->establishObserved($request, Auth::guard('web'), $observation, 'Example User', 'user@example.test');

        $this->assertSame(3, $observation->epoch);
        $this->assertSame(3, $session->epoch($request, 'example-provider', 'subject-example'));
    }

    public function test_an_observation_cached_by_an_earlier_release_is_asked_again(): void
    {
        $this->fakeStatus();
        $request = $this->signedIn(3);
        $this->travel(300)->seconds(); // past the session's own freshness
        // Written before observations carried an epoch: it must not read as "no epoch".
        $key = 'bherila_auth:provider_identity:'.app(ProviderIdentityStatusClient::class)->context()
            .':'.hash('sha256', 'subject-example');
        Cache::put($key, ['generation' => 7, 'checked_at' => Carbon::now()->getTimestamp()], 300);

        app(ProviderSession::class)->assertActive($request, 'example-provider', 'subject-example');

        Http::assertSentCount(1);
    }

    // --- Remembered logins --------------------------------------------------

    private function rememberedCookie(?int $epoch): string
    {
        $response = $this->post('/test-login', ['epoch' => $epoch])->assertOk();
        $cookie = $response->getCookie(Auth::guard('web')->getRecallerName());
        $this->assertNotNull($cookie);
        $this->newBrowser();

        return $cookie->getValue();
    }

    private function newBrowser(): void
    {
        $this->flushSession();
        Auth::forgetGuards();
        $this->defaultCookies = [];
    }

    public function test_a_remembered_login_records_its_epoch_and_a_restore_ends_the_cookie(): void
    {
        $this->fakeStatus();
        $this->user();
        $cookie = $this->rememberedCookie(3);
        $this->assertSame(3, (int) DB::table(RememberedProviderLogins::TABLE)->value('epoch'));

        $this->withCookie(Auth::guard('web')->getRecallerName(), $cookie)->get('/private')->assertOk();
        $this->newBrowser();

        $this->epoch = 4;
        $this->travel(300)->seconds();
        $this->withCookie(Auth::guard('web')->getRecallerName(), $cookie)->get('/private')->assertRedirect('/');
    }

    public function test_a_sign_in_under_a_new_epoch_retires_cookies_from_before_it(): void
    {
        $user = $this->user();
        $this->rememberedCookie(3);
        $before = $user->fresh()->remember_token;

        $this->rememberedCookie(4);

        $this->assertNotSame($before, $user->fresh()->remember_token);
        $this->assertSame(4, (int) DB::table(RememberedProviderLogins::TABLE)->value('epoch'));
    }

    public function test_a_sign_in_under_the_same_epoch_keeps_the_token(): void
    {
        $user = $this->user();
        $this->rememberedCookie(3);
        $before = $user->fresh()->remember_token;

        $this->rememberedCookie(3);

        $this->assertSame($before, $user->fresh()->remember_token);
    }

    public function test_before_the_epoch_column_exists_remembered_logins_are_still_recorded(): void
    {
        Schema::table(RememberedProviderLogins::TABLE, fn (Blueprint $table) => $table->dropColumn('epoch'));
        $this->fakeStatus();
        $this->user();

        $cookie = $this->rememberedCookie(3);

        $this->assertSame(7, (int) DB::table(RememberedProviderLogins::TABLE)->value('generation'));
        // Recorded without an epoch, so the restored session is not compared on it.
        $this->withCookie(Auth::guard('web')->getRecallerName(), $cookie)->get('/private')->assertOk();
    }
}
