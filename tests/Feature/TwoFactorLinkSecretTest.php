<?php

namespace BWH\Auth\Tests\Feature;

use BWH\Auth\Mail\TwoFactorLoginMail;
use BWH\Auth\Models\AuthAuditLog;
use BWH\Auth\Models\TwoFactorAttempt;
use BWH\Auth\Services\TwoFactorService;
use BWH\Auth\Tests\Fixtures\User;
use BWH\Auth\Tests\TestCase;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\DataProvider;

/**
 * The emailed confirm link completes a sign-in only with the link secret the email carries.
 *
 * The attempt token names the challenge and is handed to the browser that passed the password
 * step (as `attempt_token` from the application's login route, from resend, and from the
 * confirm page's JSON). If it were enough to finish the sign-in, the password alone would be.
 */
class TwoFactorLinkSecretTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        config(['app.url' => 'http://localhost']);
        Mail::fake();
    }

    protected function defineRoutes($router): void
    {
        // A consumer's password step: verify the password, start the challenge, return the token.
        Route::middleware('web')->post('/login', function (Request $request) {
            $user = User::query()->where('email', $request->input('email'))->firstOrFail();
            abort_unless(password_verify((string) $request->input('password'), $user->password), 422);
            $attempt = app(TwoFactorService::class)->startChallenge($user, $request);

            return response()->json(['success' => true, 'requires_2fa' => true, 'attempt_token' => $attempt->token]);
        });
    }

    private function user(): User
    {
        return User::create(['name' => 'Synthetic Person', 'email' => 'person@example.test', 'password' => bcrypt('synthetic-password')]);
    }

    private function passwordStep(): TestResponse
    {
        return $this->postJson('/login', ['email' => 'person@example.test', 'password' => 'synthetic-password'])->assertOk();
    }

    private function lastMail(): TwoFactorLoginMail
    {
        $mail = Mail::sent(TwoFactorLoginMail::class)->last();
        $this->assertInstanceOf(TwoFactorLoginMail::class, $mail);

        return $mail;
    }

    /** The path and query of an emailed URL, for the test client. */
    private function relative(?string $url): string
    {
        $this->assertIsString($url);
        $parts = parse_url($url);

        return $parts['path'].(isset($parts['query']) ? '?'.$parts['query'] : '');
    }

    private function assertNoSecretIn(TestResponse $response, TwoFactorAttempt $attempt): void
    {
        $this->assertStringNotContainsString('secret', $response->getContent());
        $this->assertStringNotContainsString((string) $attempt->getRawOriginal('link_secret_hash'), $response->getContent());
    }

    public function test_the_password_step_token_alone_cannot_complete_the_confirmation(): void
    {
        $this->user();
        $token = $this->passwordStep()->json('attempt_token');

        $this->postJson('/api/auth/two-factor/confirm/'.$token)->assertStatus(422)->assertJsonPath('success', false);
        $this->post('/api/auth/two-factor/confirm/'.$token)->assertRedirect('/login');
        $this->getJson('/api/auth/two-factor/confirm/'.$token)->assertStatus(422);
        $this->get('/api/auth/two-factor/confirm/'.$token)->assertRedirect('/login');

        $this->assertGuest();
        $this->assertFalse(TwoFactorAttempt::where('token', $token)->sole()->is_used);
    }

    public function test_the_resend_token_alone_cannot_complete_the_confirmation(): void
    {
        $this->user();
        $first = $this->passwordStep()->json('attempt_token');

        $resend = $this->postJson('/api/auth/two-factor/resend', ['attempt_token' => $first])->assertOk();
        $token = $resend->json('attempt_token');
        $attempt = TwoFactorAttempt::where('token', $token)->sole();
        $this->assertNoSecretIn($resend, $attempt);

        $this->postJson('/api/auth/two-factor/confirm/'.$token)->assertStatus(422);
        $this->assertGuest();
        $this->assertFalse($attempt->fresh()->is_used);

        // The resend's own email is the one that can.
        $this->post($this->relative($this->lastMail()->confirmUrl))->assertRedirect('/');
        $this->assertAuthenticatedAs($attempt->user);
    }

    public function test_the_emailed_link_completes_once_through_its_form_and_fails_on_replay(): void
    {
        $user = $this->user();
        $this->passwordStep();
        $mail = $this->lastMail();
        $attempt = $mail->attempt->fresh();

        // The GET page is side-effect-free and posts back with the secret.
        $page = $this->get($this->relative($mail->confirmUrl))->assertOk();
        $this->assertGuest();
        $this->assertFalse($attempt->fresh()->is_used);
        $this->assertSame(1, preg_match('/action="([^"]+)"/', $page->getContent(), $action));
        $submit = html_entity_decode($action[1]);
        $this->assertStringContainsString('secret=', $submit);

        $json = $this->getJson($this->relative($mail->confirmUrl))->assertOk()->assertJsonPath('attempt_token', $attempt->token);
        $this->assertNoSecretIn($json, $attempt);

        $this->post($submit)->assertRedirect('/');
        $this->assertAuthenticatedAs($user);
        $this->assertTrue($attempt->fresh()->is_used);

        Auth::logout();
        $this->post($submit)->assertRedirect('/login');
        $this->postJson($submit)->assertStatus(422);
        $this->assertGuest();
    }

    public function test_a_wrong_or_missing_secret_fails_and_leaves_the_challenge_usable(): void
    {
        $this->user();
        $this->passwordStep();
        $mail = $this->lastMail();
        $token = $mail->attempt->token;

        foreach (['', 'wrong', str_repeat('a', 64), $token] as $secret) {
            $this->postJson('/api/auth/two-factor/confirm/'.$token, ['secret' => $secret])->assertStatus(422);
            $this->postJson('/api/auth/two-factor/confirm/'.$token.'?secret='.rawurlencode($secret))->assertStatus(422);
        }
        $this->postJson('/api/auth/two-factor/confirm/'.$token, ['secret' => ['array']])->assertStatus(422);
        $this->assertGuest();

        // A secret belongs to its own attempt only.
        $other = TwoFactorAttempt::createForUser($mail->attempt->user);
        $this->postJson('/api/auth/two-factor/confirm/'.$other->token, ['secret' => parse_url((string) $mail->confirmUrl, PHP_URL_QUERY)])->assertStatus(422);
        $this->postJson('/api/auth/two-factor/confirm/'.$other->token, ['secret' => $this->secretFrom($mail)])->assertStatus(422);
        $this->assertGuest();

        $this->postJson('/api/auth/two-factor/confirm/'.$token, ['secret' => $this->secretFrom($mail)])->assertOk();
        $this->assertAuthenticated();
    }

    public function test_code_then_link_signs_in_once(): void
    {
        $user = $this->user();
        $this->passwordStep();
        $mail = $this->lastMail();

        $this->postJson('/api/auth/two-factor/verify', ['attempt_token' => $mail->attempt->token, 'code' => $mail->attempt->code])->assertOk();
        $this->assertAuthenticatedAs($user);
        Auth::logout();

        $this->postJson($this->relative($mail->confirmUrl))->assertStatus(422);
        $this->assertGuest();
    }

    public function test_link_then_code_signs_in_once(): void
    {
        $user = $this->user();
        $this->passwordStep();
        $mail = $this->lastMail();

        $this->postJson($this->relative($mail->confirmUrl))->assertOk();
        $this->assertAuthenticatedAs($user);
        Auth::logout();

        $this->postJson('/api/auth/two-factor/verify', ['attempt_token' => $mail->attempt->token, 'code' => $mail->attempt->code])->assertStatus(422);
        $this->assertGuest();
    }

    /**
     * The interleaving two concurrent requests produce: another writer spends the challenge
     * after this request has loaded and checked it, before it consumes it. (Two real
     * connections cannot share the suite's in-memory SQLite database, so the other writer
     * runs from the model's `retrieved` hook instead.)
     *
     * @return array<string, array{string}>
     */
    public static function completions(): array
    {
        return ['code' => ['code'], 'link' => ['link']];
    }

    #[DataProvider('completions')]
    public function test_a_challenge_spent_between_check_and_consume_does_not_sign_in(string $via): void
    {
        $this->user();
        $this->passwordStep();
        $mail = $this->lastMail();
        $attempt = $mail->attempt;

        $raced = false;
        TwoFactorAttempt::retrieved(function (TwoFactorAttempt $loaded) use (&$raced): void {
            if (! $raced) {
                $raced = true;
                TwoFactorAttempt::query()->whereKey($loaded->getKey())->update(['is_used' => true]);
            }
        });

        $response = $via === 'code'
            ? $this->postJson('/api/auth/two-factor/verify', ['attempt_token' => $attempt->token, 'code' => $attempt->code])
            : $this->postJson($this->relative($mail->confirmUrl));

        $this->assertTrue($raced);
        $response->assertStatus(422);
        $this->assertGuest();
    }

    public function test_the_token_alone_withdraws_the_attempt_but_cannot_report_it(): void
    {
        $this->user();
        $token = $this->passwordStep()->json('attempt_token');

        $this->getJson('/api/auth/two-factor/report/'.$token)->assertOk()->assertJsonPath('can_report', false);
        $this->get('/api/auth/two-factor/report/'.$token)->assertOk()->assertDontSee('<form', false);

        $this->postJson('/api/auth/two-factor/report/'.$token)->assertOk()->assertJsonPath('message', 'This login attempt has been cancelled.');

        $attempt = TwoFactorAttempt::where('token', $token)->sole();
        $this->assertTrue($attempt->is_used);
        $this->assertFalse($attempt->is_suspicious);
        $this->assertFalse(AuthAuditLog::query()->where('event', AuthAuditLog::EVENT_TWO_FACTOR_REPORTED_SUSPICIOUS)->exists());
    }

    public function test_the_emailed_report_link_reports_once_and_cannot_follow_a_sign_in(): void
    {
        $this->user();
        $this->passwordStep();
        $mail = $this->lastMail();

        $this->getJson($this->relative($mail->reportUrl))->assertOk()->assertJsonPath('can_report', true);
        $page = $this->get($this->relative($mail->reportUrl))->assertOk()->assertSee('<form', false);
        $this->assertFalse($mail->attempt->fresh()->is_used);
        $this->assertSame(1, preg_match('/action="([^"]+)"/', $page->getContent(), $action));

        $this->post(html_entity_decode($action[1]))->assertOk();
        $attempt = $mail->attempt->fresh();
        $this->assertTrue($attempt->is_used);
        $this->assertTrue($attempt->is_suspicious);
        $this->assertSame(1, AuthAuditLog::query()->where('event', AuthAuditLog::EVENT_TWO_FACTOR_REPORTED_SUSPICIOUS)->count());

        // Neither the link nor the code signs in afterwards, and a second report records nothing.
        $this->postJson($this->relative($mail->confirmUrl))->assertStatus(422);
        $this->postJson('/api/auth/two-factor/verify', ['attempt_token' => $attempt->token, 'code' => $attempt->code])->assertStatus(422);
        $this->postJson($this->relative($mail->reportUrl))->assertOk();
        $this->assertSame(1, AuthAuditLog::query()->where('event', AuthAuditLog::EVENT_TWO_FACTOR_REPORTED_SUSPICIOUS)->count());
        $this->assertGuest();
    }

    public function test_a_report_after_the_sign_in_completed_flags_nothing(): void
    {
        $this->user();
        $this->passwordStep();
        $mail = $this->lastMail();
        $this->postJson($this->relative($mail->confirmUrl))->assertOk();

        $this->postJson($this->relative($mail->reportUrl))->assertOk();
        $this->assertFalse($mail->attempt->fresh()->is_suspicious);
        $this->assertFalse(AuthAuditLog::query()->where('event', AuthAuditLog::EVENT_TWO_FACTOR_REPORTED_SUSPICIOUS)->exists());
    }

    public function test_the_secret_is_stored_hashed_and_never_serialized(): void
    {
        $this->user();
        $this->passwordStep();
        $mail = $this->lastMail();
        $secret = $this->secretFrom($mail);
        $stored = TwoFactorAttempt::where('token', $mail->attempt->token)->sole();

        $this->assertSame(64, strlen($secret));
        $this->assertNotSame($mail->attempt->token, $secret);
        $this->assertSame(hash('sha256', $secret), $stored->getRawOriginal('link_secret_hash'));
        $this->assertArrayNotHasKey('link_secret_hash', $stored->toArray());
        $this->assertStringNotContainsString($secret, $stored->toJson());
        $this->assertNull($stored->linkSecret(), 'Only the instance that created it holds the secret.');
    }

    public function test_without_the_column_the_challenge_works_by_code_and_mails_no_links(): void
    {
        Schema::table(config('bherila-auth.two_factor.table', 'auth_two_factor_attempts'), function (Blueprint $table): void {
            $table->dropColumn('link_secret_hash');
        });
        $user = $this->user();
        $token = $this->passwordStep()->json('attempt_token');
        $mail = $this->lastMail();

        $this->assertNull($mail->confirmUrl);
        $this->assertNull($mail->reportUrl);
        $this->assertStringNotContainsString('/two-factor/confirm/', $mail->render());
        $this->postJson('/api/auth/two-factor/confirm/'.$token)->assertStatus(422);
        $this->assertGuest();

        $this->postJson('/api/auth/two-factor/verify', ['attempt_token' => $token, 'code' => $mail->attempt->code])->assertOk();
        $this->assertAuthenticatedAs($user);
    }

    public function test_the_mail_renders_both_links_with_the_secret(): void
    {
        $this->user();
        $this->passwordStep();
        $mail = $this->lastMail();
        $html = $mail->render();

        $this->assertStringContainsString(e((string) $mail->confirmUrl), $html);
        $this->assertStringContainsString(e((string) $mail->reportUrl), $html);
    }

    private function secretFrom(TwoFactorLoginMail $mail): string
    {
        parse_str((string) parse_url((string) $mail->confirmUrl, PHP_URL_QUERY), $query);
        $this->assertIsString($query['secret'] ?? null);

        return $query['secret'];
    }
}
