<?php

namespace BWH\Auth\Tests\Feature;

use BWH\Auth\Http\Middleware\RequireActiveProviderSession;
use BWH\Auth\OAuth\OAuthIdentity;
use BWH\Auth\OAuth\Session\ProviderBinding;
use BWH\Auth\OAuth\Session\ProviderBindingResolver;
use BWH\Auth\OAuth\Session\ProviderIdentityPolicy;
use BWH\Auth\OAuth\Session\ProviderIdentityStatusClient;
use BWH\Auth\OAuth\Session\ProviderSession;
use BWH\Auth\OAuth\Session\ProviderSessionExpired;
use BWH\Auth\OAuth\Session\ProviderStatusUnavailable;
use BWH\Auth\Tests\Fixtures\User;
use BWH\Auth\Tests\TestCase;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Cache\ArrayStore;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Sleep;
use PHPUnit\Framework\Attributes\DataProvider;

class ProviderIdentityEnforcementTest extends TestCase
{
    protected function defineDatabaseMigrations(): void
    {
        parent::defineDatabaseMigrations();

        // The binding columns are the application's; the fixture app needs them here.
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

        Route::middleware(['web', RequireActiveProviderSession::class])->group(function (): void {
            Route::get('/private', fn () => 'ok');
            Route::post('/private', fn () => 'written');
        });
        Route::get('/signed-out', fn () => 'signed out')->name('signed-out');
    }

    private function payload(int $generation = 7, string $subject = 'subject-example'): array
    {
        return ['contract_version' => 1, 'active' => true, 'subject' => $subject, 'credential_version' => $generation];
    }

    private function policy(): ProviderIdentityPolicy
    {
        return app(ProviderIdentityPolicy::class);
    }

    private function user(?string $provider = 'example-provider', ?string $subject = 'subject-example'): User
    {
        return User::query()->create([
            'name' => 'Example User', 'email' => uniqid('user-', true).'@example.test', 'password' => 'unused',
            'oauth_provider' => $provider, 'oauth_subject' => $subject,
        ]);
    }

    /** The state ProviderSession::remember() writes at login, for a test session. */
    private function sessionState(int $generation = 7, ?int $checkedAt = null, string $subject = 'subject-example'): array
    {
        return ['bherila_auth.provider_session' => [
            'context' => app(ProviderIdentityStatusClient::class)->context(),
            'provider' => 'example-provider',
            'subject' => $subject,
            'generation' => $generation,
            'checked_at' => $checkedAt ?? Carbon::now()->getTimestamp(),
            'name' => 'Example User',
            'email' => 'user@example.test',
        ]];
    }

    // --- The shared policy -------------------------------------------------

    public function test_every_credential_of_one_person_shares_one_observation_per_window(): void
    {
        Http::fake(fn () => Http::response($this->payload()));

        $first = $this->policy()->verify('subject-example', 7);
        $this->travel(200)->seconds();
        $second = $this->policy()->verify('subject-example', 7);

        Http::assertSentCount(1);
        $this->assertSame($first, $second, 'A shared answer reports when it was observed, not now.');

        $this->travel(100)->seconds();
        $this->policy()->verify('subject-example', 7);
        Http::assertSentCount(2);
    }

    public function test_a_shared_answer_never_lets_a_credential_adopt_a_newer_generation(): void
    {
        Http::fake(fn () => Http::response($this->payload(8)));
        $this->policy()->verify('subject-example', 8);

        $this->expectException(ProviderSessionExpired::class);
        $this->policy()->verify('subject-example', 7);
    }

    public function test_inactive_is_shared_so_other_credentials_end_without_another_request(): void
    {
        Http::fake(fn () => Http::response(['contract_version' => 1, 'active' => false]));
        try {
            $this->policy()->verify('subject-example', 7);
            $this->fail('An inactive identity must not verify.');
        } catch (ProviderSessionExpired) {
        }

        try {
            $this->policy()->verify('subject-example', 7);
            $this->fail('A cached inactive answer must not verify.');
        } catch (ProviderSessionExpired) {
            Http::assertSentCount(1);
        }
    }

    public function test_fresh_checks_bypass_the_shared_observation_and_refresh_it(): void
    {
        Http::fake(['*' => Http::sequence()->push($this->payload())->push(['contract_version' => 1, 'active' => false])]);
        $this->policy()->verify('subject-example', 7);

        try {
            $this->policy()->verify('subject-example', 7, fresh: true);
            $this->fail('A privileged check must see the current status.');
        } catch (ProviderSessionExpired) {
        }

        $this->expectException(ProviderSessionExpired::class);
        $this->policy()->verify('subject-example', 7);
    }

    public function test_outages_are_never_cached_and_never_authorize(): void
    {
        Http::fake(['*' => Http::sequence()->pushStatus(503)->push($this->payload())]);
        try {
            $this->policy()->verify('subject-example', 7);
            $this->fail('An outage must not authorize.');
        } catch (ProviderStatusUnavailable) {
        }

        $this->policy()->verify('subject-example', 7);
        Http::assertSentCount(2);
    }

    public function test_observations_do_not_cross_subjects_or_provider_configuration(): void
    {
        Http::fake(fn ($request) => Http::response($this->payload(7, $request['subject'])));
        $this->policy()->verify('subject-example', 7);
        $this->policy()->verify('subject-other', 7);
        config(['bherila-auth.oauth_client.client_id' => 'other-client']);
        $this->policy()->verify('subject-example', 7);

        Http::assertSentCount(3);
    }

    public function test_a_cached_observation_from_the_future_is_not_fresh(): void
    {
        Http::fake(fn () => Http::response($this->payload()));
        $this->policy()->verify('subject-example', 7);
        $this->travel(-1)->seconds();
        $this->policy()->verify('subject-example', 7);

        Http::assertSentCount(2);
    }

    public function test_one_caller_at_a_time_asks_and_a_busy_refresh_is_retryable_not_a_second_request(): void
    {
        Http::fake(fn () => Http::response($this->payload()));
        Sleep::fake(syncWithCarbon: true);
        $key = 'bherila_auth:provider_identity:'.app(ProviderIdentityStatusClient::class)->context()
            .':'.hash('sha256', 'subject-example').':refresh';
        $held = Cache::lock($key, 10);
        $this->assertTrue($held->get(), 'Another worker is mid-refresh.');

        try {
            $this->policy()->verify('subject-example', 7);
            $this->fail('A caller must not ask while another refresh for the subject is in flight.');
        } catch (ProviderStatusUnavailable) {
            Http::assertNothingSent();
        }

        $held->release();
        $this->policy()->verify('subject-example', 7);
        Http::assertSentCount(1);
    }

    public function test_a_store_that_cannot_lock_refuses_rather_than_refreshing_unserialized(): void
    {
        Http::fake(fn () => Http::response($this->payload()));
        config(['cache.stores.lockless' => ['driver' => 'lockless']]);
        Cache::extend('lockless', fn () => Cache::repository(new class implements \Illuminate\Contracts\Cache\Store
        {
            private array $values = [];

            public function get($key): mixed { return $this->values[$key] ?? null; }

            public function many(array $keys): array { return array_map(fn ($k) => $this->get($k), array_combine($keys, $keys)); }

            public function put($key, $value, $seconds): bool { $this->values[$key] = $value; return true; }

            public function putMany(array $values, $seconds): bool { $this->values = [...$this->values, ...$values]; return true; }

            public function increment($key, $value = 1): int|bool { return false; }

            public function decrement($key, $value = 1): int|bool { return false; }

            public function forever($key, $value): bool { return $this->put($key, $value, 0); }

            public function touch($key, $seconds): bool { return true; }

            public function forget($key): bool { unset($this->values[$key]); return true; }

            public function flush(): bool { $this->values = []; return true; }

            public function getPrefix(): string { return ''; }
        }));
        config(['bherila-auth.provider_identity.cache_store' => 'lockless']);

        try {
            $this->policy()->verify('subject-example', 7);
            $this->fail('A refresh that cannot be serialized must not run.');
        } catch (ProviderStatusUnavailable) {
            Http::assertNothingSent();
        }
    }

    public function test_a_failing_shared_store_refuses_retryably_instead_of_erroring(): void
    {
        Http::fake(fn () => Http::response($this->payload()));
        config(['cache.stores.broken' => ['driver' => 'broken']]);
        Cache::extend('broken', fn () => Cache::repository(new class extends ArrayStore
        {
            public function get($key): mixed
            {
                throw new \RuntimeException('The cache backend is down.');
            }
        }));
        config(['bherila-auth.provider_identity.cache_store' => 'broken']);

        $this->expectException(ProviderStatusUnavailable::class);
        $this->policy()->verify('subject-example', 7);
    }

    public function test_a_session_keeps_the_observation_time_so_shared_answers_do_not_extend_it(): void
    {
        Http::fake(fn () => Http::response($this->payload()));
        $this->policy()->verify('subject-example', 7);      // another credential, at t=0
        $this->travel(200)->seconds();

        $request = Request::create('/private');
        $request->setLaravelSession(app('session.store'));
        $request->session()->put($this->sessionState(checkedAt: Carbon::now()->getTimestamp() - 400));
        app(ProviderSession::class)->assertActive($request, 'example-provider', 'subject-example');
        Http::assertSentCount(1);
        $this->assertSame(Carbon::now()->getTimestamp() - 200,
            $request->session()->get('bherila_auth.provider_session.checked_at'));

        $this->travel(100)->seconds();                      // 300s after the observation
        app(ProviderSession::class)->assertActive($request, 'example-provider', 'subject-example');
        Http::assertSentCount(2);
    }

    // --- Establishing a session at login ----------------------------------

    public function test_establish_undoes_the_login_when_enforcement_cannot_remember_a_generation(): void
    {
        $user = $this->user();
        $request = Request::create('/oauth/callback');
        $request->setLaravelSession(app('session.store'));
        Auth::guard('web')->setRequest($request);
        Auth::guard('web')->login($user);
        $token = $request->session()->token();

        try {
            app(ProviderSession::class)->establish($request,
                new OAuthIdentity('example-provider', 'subject-example', 'Example User', 'user@example.test'),
                Auth::guard('web'));
            $this->fail('A login without a generation baseline must not stand while enforcement is on.');
        } catch (ProviderStatusUnavailable) {
            $this->assertNull(Auth::guard('web')->user());
            $this->assertNotSame($token, $request->session()->token());
        }
    }

    public function test_establish_remembers_the_baseline_even_while_enforcement_is_off(): void
    {
        config(['bherila-auth.provider_identity.enabled' => false]);
        $request = Request::create('/oauth/callback');
        $request->setLaravelSession(app('session.store'));
        $guard = Auth::guard('web');
        $guard->setRequest($request);
        $guard->login($this->user());

        app(ProviderSession::class)->establish($request,
            new OAuthIdentity('example-provider', 'subject-example', 'Example User', 'user@example.test', credentialVersion: 7),
            $guard);
        $this->assertSame(7, $request->session()->get('bherila_auth.provider_session.generation'));

        // An old provider without generations does not block login while enforcement is off,
        // and the earlier login's baseline does not stand in for this one.
        app(ProviderSession::class)->establish($request,
            new OAuthIdentity('example-provider', 'subject-example', 'Example User', 'user@example.test'),
            $guard);
        $this->assertNotNull($guard->user());
        $this->assertFalse($request->session()->has('bherila_auth.provider_session'));
    }

    // --- The browser middleware --------------------------------------------

    public function test_disabled_enforcement_changes_nothing(): void
    {
        config(['bherila-auth.provider_identity.enabled' => false]);
        Http::fake();
        $this->actingAs($this->user())->get('/private')->assertOk();
        Http::assertNothingSent();
    }

    public function test_a_live_session_continues_within_freshness_without_a_request(): void
    {
        Http::fake();
        $this->actingAs($this->user())->withSession($this->sessionState())->get('/private')->assertOk();
        Http::assertNothingSent();
    }

    public function test_unsafe_methods_always_check_freshly(): void
    {
        Http::fake(fn () => Http::response($this->payload()));
        $this->actingAs($this->user())->withSession($this->sessionState())
            ->post('/private')->assertOk()->assertSee('written');
        Http::assertSentCount(1);
    }

    #[DataProvider('endedIdentities')]
    public function test_an_ended_identity_logs_out_and_asks_for_a_new_sign_in(array $payload): void
    {
        Http::fake(fn () => Http::response($payload));
        config(['bherila-auth.provider_identity.expired_redirect_route' => 'signed-out']);
        $user = $this->user();

        $this->actingAs($user)->withSession($this->sessionState())->post('/private')
            ->assertRedirect(route('signed-out'));
        $this->assertGuest('web');

        $this->actingAs($user)->withSession($this->sessionState())->postJson('/private')
            ->assertStatus(401)->assertHeader('Cache-Control', 'no-store, private');
    }

    public static function endedIdentities(): array
    {
        return [
            'disabled or deleted' => [['contract_version' => 1, 'active' => false]],
            'reset since sign-in' => [['contract_version' => 1, 'active' => true, 'subject' => 'subject-example', 'credential_version' => 8]],
        ];
    }

    public function test_a_session_without_a_login_baseline_requires_a_new_sign_in(): void
    {
        Http::fake();
        $this->actingAs($this->user())->getJson('/private')->assertStatus(401);
        Http::assertNothingSent();
    }

    public function test_an_outage_refuses_with_a_retryable_error_and_keeps_the_session(): void
    {
        Http::fake(['*' => Http::response(null, 503)]);
        $user = $this->user();
        $this->actingAs($user)->withSession($this->sessionState())->postJson('/private')
            ->assertStatus(503)->assertHeader('Retry-After', '30');
        $this->assertAuthenticatedAs($user, 'web');
    }

    public function test_unbound_accounts_are_left_to_the_application_policy(): void
    {
        Http::fake();
        $this->actingAs($this->user(null, null))->post('/private')->assertOk();
        Http::assertNothingSent();
    }

    #[DataProvider('brokenBindings')]
    public function test_a_broken_binding_is_never_treated_as_unbound(?string $provider, ?string $subject): void
    {
        Http::fake();
        $this->actingAs($this->user($provider, $subject))->getJson('/private')->assertStatus(401);
        Http::assertNothingSent();
    }

    public static function brokenBindings(): array
    {
        return [
            'subject only' => [null, 'subject-example'],
            'provider only' => ['example-provider', null],
            'another provider' => ['other-provider', 'subject-example'],
            'empty subject' => ['example-provider', ''],
        ];
    }

    public function test_a_missing_binding_column_is_refused_rather_than_exempting_everyone(): void
    {
        Http::fake();
        config(['bherila-auth.provider_identity.binding.subject_column' => 'misnamed_subject']);
        $this->actingAs($this->user(null, null))->getJson('/private')->assertStatus(401);

        config(['bherila-auth.provider_identity.binding.subject_column' => 'oauth_subject']);
        $partial = User::query()->select(['id', 'name', 'email'])->findOrFail($this->user(null, null)->getKey());
        $this->flushSession();
        $this->actingAs($partial)->getJson('/private')->assertStatus(401);
        Http::assertNothingSent();
    }

    public function test_the_session_binding_must_match_the_account_binding(): void
    {
        Http::fake();
        $this->actingAs($this->user(subject: 'subject-other'))
            ->withSession($this->sessionState())->getJson('/private')->assertStatus(401);
        Http::assertNothingSent();
    }

    public function test_applications_can_bind_their_own_binding_resolver(): void
    {
        $this->app->instance(ProviderBindingResolver::class, new class implements ProviderBindingResolver
        {
            public function binding(Authenticatable $user): ?ProviderBinding
            {
                return new ProviderBinding('example-provider', 'subject-example');
            }
        });
        Http::fake();
        $this->actingAs($this->user(null, null))->withSession($this->sessionState())->get('/private')->assertOk();
        // The resolver's binding, not the empty columns, is what the session must match.
        $this->flushSession();
        $this->actingAs($this->user(null, null))->getJson('/private')->assertStatus(401);
    }
}
