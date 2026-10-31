<?php

namespace BWH\Auth\Tests\Feature;

use BWH\Auth\Http\Controllers\RelyingPartyLoginController;
use BWH\Auth\Models\AuthAuditLog;
use BWH\Auth\OAuth\Login\RelyingPartyAccounts;
use BWH\Auth\OAuth\OAuthIdentity;
use BWH\Auth\OAuth\PendingAccount;
use BWH\Auth\OAuth\ProviderApplications;
use BWH\Auth\Tests\Fixtures\User;
use BWH\Auth\Tests\TestCase;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\Events\TransactionRolledBack;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Illuminate\Testing\TestResponse;

/**
 * The shared sign-in: which local account an identity reaches, and what a sign-in leaves
 * behind. The account rules are the security argument of the whole design, so each one is
 * pinned here rather than in the applications that rely on it.
 */
class RelyingPartyLoginControllerTest extends TestCase
{
    private const PROVIDER = 'test-provider';

    protected function setUp(): void
    {
        parent::setUp();

        Schema::table('users', function (Blueprint $table): void {
            $table->string('oauth_provider', 64)->nullable();
            $table->string('oauth_subject', 191)->nullable();
            $table->boolean('is_disabled')->default(false);
            $table->unique(['oauth_provider', 'oauth_subject'], 'users_oauth_identity_unique');
        });

        config(['bherila-auth.oauth_client' => [
            'provider' => self::PROVIDER,
            'base_url' => 'https://identity.example.test',
            'client_id' => 'test-client',
            'client_secret' => 'test-secret',
            'redirect_uri' => 'https://app.example.test/oauth/callback',
            'scope' => 'identity:read',
            'authorize_path' => '/oauth/authorize',
            'token_path' => '/oauth/token',
            'identity_path' => '/api/oauth/user',
            'end_session_path' => '/oauth/end-session',
        ]]);

        Route::middleware('web')->group(function (): void {
            Route::get('/oauth/redirect', [TestLoginController::class, 'redirect']);
            Route::get('/oauth/callback', [TestLoginController::class, 'callback']);
            Route::post('/logout', [TestLoginController::class, 'logout'])->name('logout');
            Route::get('/dashboard', fn () => 'dashboard')->name('dashboard');
        });

        TestLoginController::$afterSignIn = [];
        TestLoginController::$localOnly = false;
    }

    public function test_a_first_sign_in_creates_an_account_bound_to_the_subject(): void
    {
        $response = $this->signIn('subject-1', 'New Person', 'new@example.test', apps: [
            ['key' => 'phr', 'name' => 'Health', 'url' => 'https://phr.example.test'],
        ]);

        $response->assertRedirect('/');
        $user = User::query()->sole();
        $this->assertSame(self::PROVIDER, $user->oauth_provider);
        $this->assertSame('subject-1', $user->oauth_subject);
        $this->assertSame('New Person', $user->name);
        $this->assertSame('new@example.test', $user->email);
        $this->assertNotNull($user->email_verified_at);
        $this->assertAuthenticatedAs($user);
        $this->assertSame([['key' => 'phr', 'name' => 'Health', 'url' => 'https://phr.example.test']], session(ProviderApplications::SESSION_KEY));
        $this->assertDatabaseHas('auth_audit_log', ['user_id' => $user->id, 'event' => AuthAuditLog::EVENT_LOGIN_SUCCEEDED, 'auth_method' => 'oauth']);
    }

    public function test_a_returning_sign_in_resolves_on_the_subject_and_refreshes_the_profile(): void
    {
        $user = $this->account('Old Name', 'old@example.test', 'subject-2');

        $this->signIn('subject-2', 'New Name', 'new@example.test')->assertRedirect('/');

        $user->refresh();
        $this->assertSame('New Name', $user->name);
        $this->assertSame('new@example.test', $user->email);
        $this->assertAuthenticatedAs($user);
        $this->assertSame(1, User::query()->count());
    }

    public function test_a_matching_address_never_adopts_an_unbound_account(): void
    {
        $unbound = $this->account('Someone', 'shared@example.test');
        Log::spy();

        $this->signIn('attacker-subject', 'Someone', 'shared@example.test')->assertStatus(409);

        $this->assertGuest();
        $unbound->refresh();
        $this->assertNull($unbound->oauth_subject);
        $this->assertSame(1, User::query()->count());
        Log::shouldHaveReceived('warning')->once()->withArgs(function (string $message, array $context) use ($unbound): bool {
            // Row ids only: the address and subject the conflict is about stay out of logs.
            return $context['reason'] === 'email_held_by_another_account'
                && $context['email_held_by'] === $unbound->id
                && $context['subject_bound_to'] === null
                && ! str_contains(json_encode($context), 'shared@example.test')
                && ! str_contains(json_encode($context), 'attacker-subject');
        });
    }

    public function test_a_bound_account_is_not_signed_in_with_an_address_another_account_holds(): void
    {
        $bound = $this->account('Bound', 'bound@example.test', 'subject-3');
        $other = $this->account('Other', 'taken@example.test');

        $this->signIn('subject-3', 'Bound Renamed', 'taken@example.test')->assertStatus(409);

        $this->assertGuest();
        $this->assertSame('Bound', $bound->refresh()->name, 'nothing about the account is written when it is refused');
        $this->assertSame('bound@example.test', $bound->email);
        $this->assertSame('taken@example.test', $other->refresh()->email);
    }

    public function test_an_application_that_owns_the_address_keeps_it_and_skips_the_collision(): void
    {
        config(['bherila-auth.oauth_login.accounts' => KeepsConfirmedAddress::class]);
        $bound = $this->account('Bound', 'confirmed-here@example.test', 'subject-4');
        $this->account('Other', 'provider-address@example.test');

        $this->signIn('subject-4', 'Bound', 'provider-address@example.test')->assertRedirect('/');

        $this->assertAuthenticatedAs($bound);
        $this->assertSame('confirmed-here@example.test', $bound->refresh()->email);
    }

    public function test_subjects_are_compared_exactly(): void
    {
        $this->account('Upper', 'upper@example.test', 'Alice');

        $this->signIn('alice', 'Lower', 'lower@example.test')->assertRedirect('/');

        $this->assertSame(2, User::query()->count());
        $this->assertSame('alice', User::query()->where('email', 'lower@example.test')->sole()->oauth_subject);
    }

    public function test_an_account_the_application_disables_is_refused_without_a_session(): void
    {
        $user = $this->account('Disabled', 'disabled@example.test', 'subject-5');
        $user->forceFill(['is_disabled' => true])->save();

        $this->signIn('subject-5', 'Disabled', 'disabled@example.test')->assertForbidden();

        $this->assertGuest();
        $this->assertNull(session(ProviderApplications::SESSION_KEY));
        $this->assertDatabaseMissing('auth_audit_log', ['user_id' => $user->id, 'event' => AuthAuditLog::EVENT_LOGIN_SUCCEEDED]);
        $this->assertDatabaseHas('auth_audit_log', ['user_id' => $user->id, 'event' => AuthAuditLog::EVENT_LOGIN_FAILED, 'auth_method' => 'oauth']);
    }

    public function test_an_application_that_never_provisions_refuses_an_unknown_subject_and_writes_nothing(): void
    {
        config(['bherila-auth.oauth_login.accounts' => NeverProvisions::class]);
        $existing = $this->account('Someone', 'someone@example.test');

        $this->signIn('unknown-subject', 'Someone', 'someone@example.test', controller: ExplainsRefusals::class)
            ->assertRedirect('/login');

        $this->assertGuest();
        $this->assertSame(1, User::query()->count());
        $this->assertNull($existing->refresh()->oauth_subject);
        $this->assertSame('unknown', session('refused'));
        $this->assertDatabaseHas('auth_audit_log', ['event' => AuthAuditLog::EVENT_LOGIN_FAILED, 'reason' => 'No local account for provider subject']);
    }

    public function test_an_application_that_never_provisions_still_signs_in_a_linked_account(): void
    {
        config(['bherila-auth.oauth_login.accounts' => NeverProvisions::class]);
        $linked = $this->account('Linked', 'linked@example.test', 'linked-subject');

        $this->signIn('linked-subject', 'Linked', 'linked@example.test')->assertRedirect('/');

        $this->assertAuthenticatedAs($linked);
    }

    public function test_a_disabled_account_can_be_answered_with_the_application_page(): void
    {
        $user = $this->account('Disabled', 'disabled@example.test', 'subject-disabled');
        $user->forceFill(['is_disabled' => true])->save();

        $this->signIn('subject-disabled', 'Disabled', 'disabled@example.test', controller: ExplainsRefusals::class)
            ->assertRedirect('/login');

        $this->assertGuest();
        $this->assertSame('disabled', session('refused'));
    }

    public function test_a_lost_race_adopts_the_winning_row_when_it_asserts_the_same_profile(): void
    {
        $this->raceWith([
            'name' => 'Raced', 'email' => 'raced@example.test', 'password' => 'x',
            'oauth_provider' => self::PROVIDER, 'oauth_subject' => 'raced-subject',
        ]);

        $this->signIn('raced-subject', 'Raced', 'raced@example.test')->assertRedirect('/');

        $winner = User::query()->sole();
        $this->assertAuthenticatedAs($winner);
    }

    public function test_a_row_committed_after_the_address_check_is_adopted_through_the_unique_index(): void
    {
        // Later than the case above: past the locked address read, so this request's own
        // insert is what collides, and the catch path decides.
        $this->raceWith([
            'name' => 'Raced', 'email' => 'raced@example.test', 'password' => 'x',
            'oauth_provider' => self::PROVIDER, 'oauth_subject' => 'raced-subject',
        ], after: 'insert');

        $this->signIn('raced-subject', 'Raced', 'raced@example.test')->assertRedirect('/');

        $this->assertAuthenticatedAs(User::query()->sole());
    }

    public function test_a_lost_race_against_a_different_profile_is_refused(): void
    {
        $this->raceWith([
            'name' => 'Somebody Else', 'email' => 'else@example.test', 'password' => 'x',
            'oauth_provider' => self::PROVIDER, 'oauth_subject' => 'raced-subject',
        ]);

        $this->signIn('raced-subject', 'Raced', 'raced@example.test')->assertStatus(409);

        $this->assertGuest();
        $this->assertSame('Somebody Else', User::query()->sole()->name);
    }

    public function test_a_placeholder_committed_after_the_first_read_is_filled_in(): void
    {
        $this->raceWith([
            'name' => PendingAccount::name('Pending', 'pending-subject'),
            'email' => PendingAccount::email(self::PROVIDER, 'pending-subject'),
            'password' => 'x',
            'oauth_provider' => self::PROVIDER, 'oauth_subject' => 'pending-subject',
        ]);

        $this->signIn('pending-subject', 'Real Name', 'real@example.test')->assertRedirect('/');

        $user = User::query()->sole();
        $this->assertSame('Real Name', $user->name);
        $this->assertSame('real@example.test', $user->email);
        $this->assertAuthenticatedAs($user);
    }

    public function test_an_unverifiable_sign_in_is_undone_with_a_retryable_503_when_enforcement_is_on(): void
    {
        config(['bherila-auth.provider_identity.enabled' => true]);

        // No credential_version in the identity: the login generation cannot be recorded.
        $response = $this->signIn('subject-6', 'Person', 'person@example.test');

        $response->assertStatus(503);
        $this->assertSame('30', $response->headers->get('Retry-After'));
        $this->assertStringContainsString('no-store', (string) $response->headers->get('Cache-Control'));
        $this->assertGuest();
        $this->assertSame([], TestLoginController::$afterSignIn, 'nothing is applied to a sign-in that was undone');
    }

    public function test_the_application_hooks_run_after_sign_in_and_choose_the_landing_page(): void
    {
        $this->signIn('subject-7', 'Person', 'person@example.test', controller: LandsOnDashboard::class)
            ->assertRedirect('/dashboard');

        $this->assertSame(['subject-7'], TestLoginController::$afterSignIn);
    }

    public function test_a_same_site_return_page_is_honoured_and_an_off_site_one_is_dropped(): void
    {
        $this->get('/oauth/redirect?redirect='.rawurlencode('/somewhere?x=1'))->assertRedirect();
        $this->assertSame('http://localhost/somewhere?x=1', session('url.intended'));

        $this->flushSession();

        $this->get('/oauth/redirect?redirect='.rawurlencode('https://evil.example/'))->assertRedirect();
        $this->assertNull(session('url.intended'));
    }

    public function test_an_inertia_visit_gets_an_external_location_rather_than_a_redirect(): void
    {
        $response = $this->get('/oauth/redirect', ['X-Inertia' => 'true']);

        $response->assertStatus(409);
        $this->assertStringStartsWith('https://identity.example.test/oauth/authorize?', (string) $response->headers->get('X-Inertia-Location'));
    }

    public function test_signing_out_ends_the_session_here_and_at_the_provider(): void
    {
        $user = $this->account('Person', 'person@example.test', 'subject-8');

        $response = $this->actingAs($user)->post('/logout');

        $response->assertRedirectContains('https://identity.example.test/oauth/end-session');
        $this->assertGuest();
    }

    public function test_an_inertia_sign_out_navigates_the_browser_to_the_provider(): void
    {
        $user = $this->account('Person', 'person@example.test', 'subject-9');

        $response = $this->actingAs($user)->post('/logout', [], ['X-Inertia' => 'true']);

        $response->assertStatus(409);
        $this->assertStringStartsWith('https://identity.example.test/oauth/end-session', (string) $response->headers->get('X-Inertia-Location'));
        $this->assertGuest();
    }

    public function test_a_session_that_never_involved_the_provider_ends_only_here(): void
    {
        TestLoginController::$localOnly = true;
        $user = $this->account('Person', 'person@example.test');

        $response = $this->actingAs($user)->post('/logout');

        $response->assertRedirect('http://localhost');
        $this->assertGuest();
    }

    public function test_the_default_logout_response_is_unchanged_for_json_requests(): void
    {
        $user = $this->account('Person', 'person@example.test', 'subject-j0');

        $this->actingAs($user)->postJson('/logout')->assertRedirectContains('https://identity.example.test/oauth/end-session');
    }

    public function test_an_override_can_answer_json_for_both_sign_outs(): void
    {
        Route::middleware('web')->post('/json-logout', [JsonLogoutController::class, 'logout']);

        $user = $this->account('Person', 'person@example.test', 'subject-j1');
        $response = $this->actingAs($user)->postJson('/json-logout')->assertOk();
        $this->assertStringStartsWith('https://identity.example.test/oauth/end-session', (string) $response->json('redirect'));
        $this->assertGuest();

        JsonLogoutController::$localOnly = true;
        $user = $this->account('Other', 'other@example.test');
        $this->actingAs($user)->postJson('/json-logout')->assertOk()->assertExactJson(['redirect' => 'http://localhost']);
        $this->assertGuest();

        $this->actingAs($user)->post('/json-logout')->assertRedirect('http://localhost');
        JsonLogoutController::$localOnly = false;
    }

    private function account(string $name, string $email, ?string $subject = null): User
    {
        $user = new User;
        $user->forceFill([
            'name' => $name,
            'email' => $email,
            'password' => Hash::make('irrelevant'),
            'oauth_provider' => $subject === null ? null : self::PROVIDER,
            'oauth_subject' => $subject,
        ])->save();

        return $user;
    }

    /**
     * @param  list<array{key: string, name: string, url: string}>  $apps
     * @param  class-string<RelyingPartyLoginController>  $controller
     */
    private function signIn(string $subject, string $name, string $email, array $apps = [], string $controller = TestLoginController::class): TestResponse
    {
        if ($controller !== TestLoginController::class) {
            Route::middleware('web')->get('/oauth/callback', [$controller, 'callback']);
        }

        Http::fake([
            'identity.example.test/oauth/token' => Http::response(['access_token' => 'token']),
            'identity.example.test/api/oauth/user' => Http::response(array_filter([
                'sub' => $subject,
                'name' => $name,
                'email' => $email,
                'apps' => $apps === [] ? null : $apps,
            ], static fn (mixed $value): bool => $value !== null)),
        ]);

        $start = $this->get('/oauth/redirect');
        parse_str((string) parse_url((string) $start->headers->get('Location'), PHP_URL_QUERY), $query);

        return $this->get('/oauth/callback?'.http_build_query(['code' => 'code', 'state' => $query['state']]));
    }

    /**
     * A real race needs a second connection, which one in-memory database cannot give. Its
     * two observable effects are reproduced instead: the competing row lands between this
     * request's subject read and its insert, so the insert collides; and having been
     * committed elsewhere, it is still there after this request's rollback.
     *
     * @param  array<string, mixed>  $winner
     */
    private function raceWith(array $winner, string $after = 'subject read'): void
    {
        $winner += ['created_at' => now(), 'updated_at' => now()];

        $raced = false;
        $beforeInsert = $after === 'insert';
        if ($beforeInsert) {
            // Committed just before this request's insert: hook the address read, the last
            // statement before it.
            DB::listen(function (QueryExecuted $query) use (&$raced, $winner): void {
                if ($raced || ! str_starts_with($query->sql, 'select') || ! str_contains($query->sql, '"email" = ?')) {
                    return;
                }

                $raced = true;
                DB::table('users')->insert($winner);
            });
        } else {
            DB::listen(function (QueryExecuted $query) use (&$raced, $winner): void {
                if ($raced || ! str_starts_with($query->sql, 'select') || ! str_contains($query->sql, 'oauth_subject')) {
                    return;
                }

                $raced = true;
                DB::table('users')->insert($winner);
            });
        }

        $survived = false;
        Event::listen(function (TransactionRolledBack $event) use (&$survived, $winner): void {
            if ($survived) {
                return;
            }

            $survived = true;
            DB::table('users')->insert($winner);
        });
    }
}

class TestLoginController extends RelyingPartyLoginController
{
    /** @var list<string> */
    public static array $afterSignIn = [];

    public static bool $localOnly = false;

    protected function afterSignIn(Request $request, Authenticatable $account, OAuthIdentity $identity): void
    {
        self::$afterSignIn[] = $identity->subject;
    }

    protected function signsOutLocallyOnly(Request $request, ?Authenticatable $user): bool
    {
        return self::$localOnly;
    }
}

class JsonLogoutController extends TestLoginController
{
    protected function logoutResponse(Request $request, \Illuminate\Http\RedirectResponse $redirect): \Symfony\Component\HttpFoundation\Response
    {
        return $request->expectsJson()
            ? response()->json(['redirect' => $redirect->getTargetUrl()])
            : parent::logoutResponse($request, $redirect);
    }
}

class LandsOnDashboard extends TestLoginController
{
    protected function landingUrl(Request $request, Authenticatable $account): string
    {
        return route('dashboard');
    }
}

/** An application whose users confirm their own address, which the provider then never overwrites. */
class KeepsConfirmedAddress extends RelyingPartyAccounts
{
    public function refreshedAttributes(Model $account, OAuthIdentity $identity): array
    {
        return ['name' => $identity->name];
    }
}

class NeverProvisions extends RelyingPartyAccounts
{
    public function provisionsNewAccounts(): bool
    {
        return false;
    }
}

class ExplainsRefusals extends TestLoginController
{
    protected function unknownIdentityResponse(Request $request, OAuthIdentity $identity): \Symfony\Component\HttpFoundation\Response
    {
        return redirect('/login')->with('refused', 'unknown');
    }

    protected function disabledAccountResponse(Request $request, Authenticatable $account): \Symfony\Component\HttpFoundation\Response
    {
        return redirect('/login')->with('refused', 'disabled');
    }
}
