<?php

namespace BWH\Auth\Tests\Feature;

use BWH\Auth\Http\Middleware\RequireRecentAuthentication;
use BWH\Auth\Models\PasskeyCredential;
use BWH\Auth\OAuth\AuthenticationRequirement;
use BWH\Auth\OAuth\OAuthCallbackFailure;
use BWH\Auth\OAuth\OAuthCallbackRejected;
use BWH\Auth\OAuth\OAuthClient;
use BWH\Auth\OAuth\OAuthIdentity;
use BWH\Auth\OAuth\Session\AuthenticationContext;
use BWH\Auth\Services\WebAuthnService;
use BWH\Auth\Tests\Fixtures\User;
use BWH\Auth\Tests\TestCase;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Route;
use InvalidArgumentException;
use LogicException;
use PHPUnit\Framework\Attributes\DataProvider;
use RuntimeException;

/** auth-manager#113, slice L1: requesting, checking and enforcing recent authentication. */
class AuthenticationContextTest extends TestCase
{
    private const NOW = 1_800_000_000;

    private const PHISHING_RESISTANT = AuthenticationRequirement::ACR_PHISHING_RESISTANT;

    protected function setUp(): void
    {
        parent::setUp();
        Carbon::setTestNow(Carbon::createFromTimestamp(self::NOW));

        config(['bherila-auth.oauth_client' => [
            'provider' => 'test-provider',
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
            Route::get('/start', function (Request $request, OAuthClient $client) {
                return $client->redirect($request, AuthenticationRequirement::fromArray($request->session()->get('test.requirement')));
            });
            Route::get('/callback', function (Request $request, OAuthClient $client) {
                $identity = $client->identityFromCallback($request);

                return response()->json(['auth_time' => $identity->authTime, 'amr' => $identity->amr, 'acr' => $identity->acr]);
            });
            Route::get('/recent', fn () => 'allowed')->middleware(RequireRecentAuthentication::class.':900');
            Route::get('/resistant', fn () => 'allowed')->middleware(RequireRecentAuthentication::class.':900,acr='.self::PHISHING_RESISTANT);
            Route::get('/methods', fn () => 'allowed')->middleware(RequireRecentAuthentication::class.':900,amr=otp|hwk|swk');
        });
    }

    protected function tearDown(): void
    {
        Carbon::setTestNow();
        parent::tearDown();
    }

    public function test_no_requirement_sends_nothing_new_and_needs_no_claims(): void
    {
        $query = $this->startQuery();
        $this->assertArrayNotHasKey('prompt', $query);
        $this->assertArrayNotHasKey('max_age', $query);
        $this->assertArrayNotHasKey('acr_values', $query);

        $this->fakeProvider([]);
        $this->finish($query)->assertOk()->assertExactJson(['auth_time' => null, 'amr' => [], 'acr' => null]);
    }

    public function test_the_request_carries_the_requirement(): void
    {
        $query = $this->startQuery(new AuthenticationRequirement(true, 600, [self::PHISHING_RESISTANT, AuthenticationRequirement::AMR_PREFIX.'otp']));

        $this->assertSame('login', $query['prompt']);
        $this->assertSame('600', $query['max_age']);
        $this->assertSame(self::PHISHING_RESISTANT.' urn:auth-manager:amr:otp', $query['acr_values']);
    }

    public function test_a_returned_authentication_that_meets_the_request_is_accepted(): void
    {
        $query = $this->startQuery(new AuthenticationRequirement(maxAge: 600, acrValues: [self::PHISHING_RESISTANT]));
        $this->fakeProvider(['auth_time' => self::NOW - 60, 'amr' => ['swk'], 'acr' => self::PHISHING_RESISTANT]);

        $this->finish($query)->assertOk()->assertJson(['auth_time' => self::NOW - 60, 'amr' => ['swk']]);
    }

    /** @return iterable<string, array{AuthenticationRequirement, array<string, mixed>}> */
    public static function unmet(): iterable
    {
        $now = self::NOW;
        yield 'no claims at all' => [new AuthenticationRequirement(maxAge: 600), []];
        yield 'too old' => [new AuthenticationRequirement(maxAge: 600), ['auth_time' => $now - 3600, 'amr' => ['pwd'], 'acr' => AuthenticationRequirement::ACR_SINGLE]];
        yield 'wrong method' => [AuthenticationRequirement::methods(['otp']), ['auth_time' => $now, 'amr' => ['pwd'], 'acr' => AuthenticationRequirement::ACR_SINGLE]];
        yield 'wrong rung' => [new AuthenticationRequirement(acrValues: [self::PHISHING_RESISTANT]), ['auth_time' => $now, 'amr' => ['pwd', 'otp', 'mfa'], 'acr' => AuthenticationRequirement::ACR_MFA]];
        yield 'a method does not stand in for a rung' => [new AuthenticationRequirement(acrValues: [self::PHISHING_RESISTANT]), ['auth_time' => $now, 'amr' => ['swk'], 'acr' => AuthenticationRequirement::ACR_SINGLE]];
        yield 'a rung does not stand in for a method' => [AuthenticationRequirement::methods(['hwk']), ['auth_time' => $now, 'amr' => ['swk'], 'acr' => self::PHISHING_RESISTANT]];
        yield 'not fresh after a forced sign-in' => [new AuthenticationRequirement(forceLogin: true), ['auth_time' => $now - 3600, 'amr' => ['pwd'], 'acr' => AuthenticationRequirement::ACR_SINGLE]];
        yield 'max age zero is a forced sign-in' => [new AuthenticationRequirement(maxAge: 0), ['auth_time' => $now - 3600, 'amr' => ['pwd'], 'acr' => AuthenticationRequirement::ACR_SINGLE]];
    }

    /** @param  array<string, mixed>  $claims */
    #[DataProvider('unmet')]
    public function test_a_returned_authentication_that_misses_the_request_is_refused(AuthenticationRequirement $requirement, array $claims): void
    {
        $query = $this->startQuery($requirement);
        $this->fakeProvider($claims);
        $this->withoutExceptionHandling();

        try {
            $this->finish($query);
            $this->fail('The response should have been refused.');
        } catch (OAuthCallbackRejected $rejected) {
            $this->assertSame(OAuthCallbackFailure::AuthenticationRequirementUnmet, $rejected->reason);
        }
    }

    public function test_malformed_claims_are_refused(): void
    {
        $query = $this->startQuery();
        $this->fakeProvider(['auth_time' => 'yesterday', 'amr' => 'pwd']);

        $this->finish($query)->assertStatus(502);
    }

    public function test_the_lowest_rung_is_met_by_any_rung_but_the_others_only_by_themselves(): void
    {
        $single = new AuthenticationRequirement(acrValues: [AuthenticationRequirement::ACR_SINGLE]);
        $mfa = new AuthenticationRequirement(acrValues: [AuthenticationRequirement::ACR_MFA]);

        $this->assertTrue($single->satisfiedBy(self::NOW, ['swk'], self::PHISHING_RESISTANT, self::NOW));
        $this->assertFalse($single->satisfiedBy(self::NOW, ['swk'], null, self::NOW));
        $this->assertTrue($mfa->satisfiedBy(self::NOW, ['pwd', 'otp', 'mfa'], AuthenticationRequirement::ACR_MFA, self::NOW));
        $this->assertFalse($mfa->satisfiedBy(self::NOW, ['swk'], self::PHISHING_RESISTANT, self::NOW));
    }

    public function test_an_authentication_from_the_future_satisfies_nothing(): void
    {
        $this->assertFalse((new AuthenticationRequirement(maxAge: 600))->satisfiedBy(self::NOW + 3600, ['pwd'], null, self::NOW));
    }

    public function test_a_requirement_rejects_values_that_would_change_the_request(): void
    {
        $this->expectException(InvalidArgumentException::class);
        new AuthenticationRequirement(acrValues: ['one two']);
    }

    public function test_a_session_with_no_context_satisfies_nothing_and_a_browser_goes_to_sign_in(): void
    {
        config(['bherila-auth.recent_authentication.redirect_to' => '/oauth/redirect']);
        $this->actingAs($this->person());

        $this->get('/recent')
            ->assertRedirect('/oauth/redirect')
            ->assertSessionHas(AuthenticationContext::PENDING_KEY, ['force_login' => false, 'max_age' => 900, 'acr_values' => []])
            ->assertSessionHas('url.intended');
    }

    public function test_a_json_client_is_told_what_is_needed(): void
    {
        $this->actingAs($this->person());

        $this->getJson('/methods')->assertForbidden()->assertExactJson([
            'message' => 'Please sign in again to continue.',
            'error' => 'insufficient_user_authentication',
            'max_age' => 900,
            'acr_values' => ['urn:auth-manager:amr:otp', 'urn:auth-manager:amr:hwk', 'urn:auth-manager:amr:swk'],
        ]);
    }

    public function test_a_guest_never_passes(): void
    {
        $this->getJson('/recent')->assertForbidden();
    }

    public function test_a_recent_authentication_passes_until_it_ages_out(): void
    {
        $user = $this->person();
        $session = $this->context($user, self::NOW - 60, ['pwd'], AuthenticationRequirement::ACR_SINGLE);

        $this->actingAs($user)->withSession($session)->get('/recent')->assertOk();

        Carbon::setTestNow(Carbon::createFromTimestamp(self::NOW + 3600));
        $this->actingAs($user)->withSession($session)->get('/recent')->assertRedirect();
    }

    public function test_the_middleware_checks_rungs_and_methods(): void
    {
        $user = $this->person();
        $password = $this->context($user, self::NOW, ['pwd'], AuthenticationRequirement::ACR_SINGLE);
        $passkey = $this->context($user, self::NOW, ['swk'], self::PHISHING_RESISTANT);
        $code = $this->context($user, self::NOW, ['otp'], AuthenticationRequirement::ACR_SINGLE);

        $this->actingAs($user)->withSession($password)->getJson('/resistant')->assertForbidden();
        $this->actingAs($user)->withSession($passkey)->getJson('/resistant')->assertOk();
        $this->actingAs($user)->withSession($password)->getJson('/methods')->assertForbidden();
        $this->actingAs($user)->withSession($code)->getJson('/methods')->assertOk();
        $this->actingAs($user)->withSession($passkey)->getJson('/methods')->assertOk();
    }

    public function test_a_context_recorded_for_another_account_does_not_count(): void
    {
        $someone = $this->person('someone@example.test');
        $session = $this->context($someone, self::NOW, ['pwd'], AuthenticationRequirement::ACR_SINGLE);

        $this->actingAs($this->person())->withSession($session)->getJson('/recent')->assertForbidden();
    }

    public function test_a_later_sign_in_without_claims_clears_the_context(): void
    {
        $user = $this->person();
        $request = Request::create('/');
        $request->setLaravelSession($this->app['session.store']);

        AuthenticationContext::remember($request, new OAuthIdentity('p', 's', 'n', 'e@example.test', authTime: self::NOW), $user);
        $this->assertTrue($request->session()->has(AuthenticationContext::SESSION_KEY));

        AuthenticationContext::remember($request, new OAuthIdentity('p', 's', 'n', 'e@example.test'), $user);
        $this->assertFalse($request->session()->has(AuthenticationContext::SESSION_KEY));
    }

    public function test_the_middleware_refuses_a_mistyped_route_declaration(): void
    {
        Route::middleware('web')->get('/mistyped', fn () => 'allowed')->middleware(RequireRecentAuthentication::class.':soon');
        $this->withoutExceptionHandling();

        $this->expectException(LogicException::class);
        $this->get('/mistyped');
    }

    public function test_a_passkey_enrolled_before_the_flag_takes_it_from_its_next_assertion(): void
    {
        $credential = new PasskeyCredential;

        app(WebAuthnService::class)->reconcileBackupEligibility($credential, true);

        $this->assertTrue($credential->backup_eligible);
    }

    public function test_a_changed_backup_eligible_flag_is_refused(): void
    {
        $credential = new PasskeyCredential(['backup_eligible' => false]);

        $this->expectException(RuntimeException::class);
        app(WebAuthnService::class)->reconcileBackupEligibility($credential, true);
    }

    public function test_an_unchanged_backup_eligible_flag_is_accepted(): void
    {
        $credential = new PasskeyCredential(['backup_eligible' => true]);

        app(WebAuthnService::class)->reconcileBackupEligibility($credential, true);

        $this->assertTrue($credential->backup_eligible);
    }

    /** @return array<string, string> */
    private function startQuery(?AuthenticationRequirement $requirement = null): array
    {
        $response = $this->withSession(['test.requirement' => $requirement?->toArray()])->get('/start');
        parse_str((string) parse_url((string) $response->headers->get('Location'), PHP_URL_QUERY), $query);

        return $query;
    }

    /** @param  array<string, mixed>  $claims */
    private function fakeProvider(array $claims): void
    {
        Http::fake([
            'identity.example.test/oauth/token' => Http::response(['access_token' => 'access', 'token_type' => 'Bearer']),
            'identity.example.test/api/oauth/user' => Http::response(['sub' => 'subject', 'name' => 'Someone', 'email' => 'someone@example.test', ...$claims]),
        ]);
    }

    /** @param  array<string, string>  $query */
    private function finish(array $query)
    {
        return $this->get('/callback?'.http_build_query(['state' => $query['state'], 'code' => 'code']));
    }

    private function person(string $email = 'person@example.test'): User
    {
        return User::query()->create(['name' => 'Person', 'email' => $email, 'password' => 'unused']);
    }

    /**
     * @param  list<string>  $amr
     * @return array<string, mixed>
     */
    private function context(User $user, int $authTime, array $amr, string $acr): array
    {
        return [AuthenticationContext::SESSION_KEY => ['account' => (string) $user->getAuthIdentifier(), 'auth_time' => $authTime, 'amr' => $amr, 'acr' => $acr]];
    }
}
