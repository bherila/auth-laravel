<?php

namespace BWH\Auth\Http\Controllers;

use BWH\Auth\Contracts\AuthAuditLogger;
use BWH\Auth\Contracts\AuthUserPolicy;
use BWH\Auth\Contracts\LocalCredentialPolicy;
use BWH\Auth\Events\TwoFactorLoginSucceeded;
use BWH\Auth\Models\TwoFactorAttempt;
use BWH\Auth\Services\TwoFactorService;
use BWH\Auth\Support\TwoFactorRoutes;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\View\View;

class TwoFactorController extends Controller
{
    public function __construct(
        private readonly AuthUserPolicy $userPolicy,
        private readonly AuthAuditLogger $auditLogger,
        private readonly TwoFactorService $twoFactorService,
    ) {}

    public function verify(Request $request): JsonResponse|RedirectResponse
    {
        $validated = $request->validate([
            'attempt_token' => ['required', 'string'],
            'code' => ['required', 'string', 'size:6'],
        ]);

        $attempt = TwoFactorAttempt::where('token', $validated['attempt_token'])->first();

        if (! $attempt || ! $attempt->isValid()) {
            return $this->failure($request, $attempt, 'Invalid or expired verification attempt.');
        }

        $isValidCode = hash_equals($attempt->code, $validated['code'])
            || ($this->allowTestCode($attempt) && hash_equals(config('bherila-auth.two_factor.test_code', '999999'), $validated['code']));

        if (! $isValidCode) {
            if ($this->spendAfterWrongCode($attempt)) {
                return $this->failure($request, $attempt, 'Too many incorrect codes. Please sign in again for a new code.');
            }

            return $this->failure($request, $attempt, 'The verification code is incorrect. Please try again.');
        }

        return $this->completeLogin($request, $attempt);
    }

    public function resend(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'attempt_token' => ['required', 'string'],
        ]);

        $attempt = TwoFactorAttempt::where('token', $validated['attempt_token'])->first();
        $user = $attempt?->user;

        // isValid() rather than the is_used/is_suspicious pair on its own: an expired
        // attempt is no longer a live challenge, so it must not be able to mint a new
        // code (and a new expiry) for itself.
        if (! $attempt || ! $user instanceof Authenticatable || ! $attempt->isValid()) {
            return response()->json(['success' => false, 'message' => 'Invalid or expired verification attempt.'], 422);
        }

        $attempt->update(['is_used' => true]);
        $newAttempt = $this->twoFactorService->startChallenge($user, $request, (bool) $request->session()->get(config('bherila-auth.two_factor.session_remember_key', 'bherila_auth_2fa_remember'), false));

        return response()->json([
            'success' => true,
            'message' => 'A new verification code has been sent to your email address.',
            'attempt_token' => $newAttempt->token,
        ]);
    }

    /**
     * The emailed "this was me" page. Side-effect-free, so a mail scanner that follows the
     * link consumes nothing.
     *
     * The token names the challenge; the link secret (`secret`, carried only by the email) is
     * what authorizes finishing it. The token is returned to the browser that passed the
     * password step, so it proves nothing about the mailbox.
     */
    public function confirm(Request $request, string $token): JsonResponse|RedirectResponse|View
    {
        $attempt = TwoFactorAttempt::where('token', $token)->first();
        $secret = $this->linkSecret($request);

        if (! $attempt || ! $attempt->isValid() || ! $attempt->matchesLinkSecret($secret)) {
            return $this->failure($request, $attempt, 'Invalid or expired login link. Please log in again.', false);
        }

        if ($request->expectsJson()) {
            return response()->json(['success' => true, 'attempt_token' => $attempt->token]);
        }

        return view('bherila-auth::two-factor-confirm', [
            'attempt' => $attempt,
            'token' => $token,
            'userEmail' => $this->maskEmail((string) data_get($attempt->user, config('bherila-auth.users.email_attribute', 'email'), '')),
            // The secret rides on the form's action rather than a field the view must know
            // to render, so a view published before it existed keeps working.
            'submitRoute' => route(TwoFactorRoutes::name('confirm.submit'), ['token' => $token, 'secret' => $secret]),
            'loginUrl' => config('bherila-auth.two_factor.login_url', '/login'),
        ]);
    }

    /** Finish the sign-in from the emailed link: the token and its link secret, once. */
    public function confirmSubmit(Request $request, string $token): JsonResponse|RedirectResponse
    {
        $attempt = TwoFactorAttempt::where('token', $token)->first();

        if (! $attempt || ! $attempt->isValid() || ! $attempt->matchesLinkSecret($this->linkSecret($request))) {
            return $this->failure($request, $attempt, 'Invalid or expired login link. Please log in again.');
        }

        return $this->completeLogin($request, $attempt);
    }

    /**
     * The emailed "this wasn't me" page. Side-effect-free; offers the report only to a request
     * carrying the link secret.
     */
    public function report(Request $request, string $token): JsonResponse|View
    {
        $attempt = TwoFactorAttempt::where('token', $token)->first();
        $secret = $this->linkSecret($request);
        $fromEmail = $attempt !== null && $attempt->matchesLinkSecret($secret);

        if ($request->expectsJson()) {
            return response()->json([
                'success' => true,
                'can_report' => $attempt !== null && $fromEmail && ! $attempt->is_used,
            ]);
        }

        return view('bherila-auth::two-factor-report', [
            // A request without the secret sees the "already used or expired" state.
            'attempt' => $fromEmail ? $attempt : null,
            'token' => $token,
            'submitRoute' => route(TwoFactorRoutes::name('report.submit'), ['token' => $token, 'secret' => $secret]),
            'loginUrl' => config('bherila-auth.two_factor.login_url', '/login'),
        ]);
    }

    /**
     * With the link secret, the mailbox owner reports the attempt: it is flagged suspicious,
     * spent, and audited as reported. With the token alone (the browser that started the
     * attempt, through a "this was not me" button) it is only withdrawn: spent, and audited as
     * a failed sign-in. The token holder knows the password, so a report from it is no signal
     * about the account, and it must not be able to write one into the account's history.
     * Either way it is one conditional update, so it cannot race a completing sign-in.
     */
    public function reportSubmit(Request $request, string $token): JsonResponse|View
    {
        $attempt = TwoFactorAttempt::where('token', $token)->first();
        $fromEmail = $attempt !== null && $attempt->matchesLinkSecret($this->linkSecret($request));
        $user = $attempt?->user;

        if ($attempt && $fromEmail && $this->consume($attempt, ['is_suspicious' => true])) {
            if ($user instanceof Authenticatable) {
                $this->auditLogger->twoFactorReportedSuspicious($request, $user, $attempt);
            }
        } elseif ($attempt && ! $fromEmail && $this->consume($attempt)) {
            $this->auditLogger->twoFactorLoginFailed($request, $user instanceof Authenticatable ? $user : null, $attempt, 'Login attempt withdrawn.');
        }

        if ($request->expectsJson()) {
            return response()->json([
                'success' => true,
                'message' => $fromEmail ? 'This login attempt has been reported.' : 'This login attempt has been cancelled.',
            ]);
        }

        return view('bherila-auth::two-factor-reported', [
            'loginUrl' => config('bherila-auth.two_factor.login_url', '/login'),
            'passwordResetUrl' => config('bherila-auth.password_resets.request_url', '/forgot-password'),
        ]);
    }

    private function completeLogin(Request $request, TwoFactorAttempt $attempt): JsonResponse|RedirectResponse
    {
        $user = $attempt->user;

        if (! $user instanceof Authenticatable) {
            return $this->failure($request, $attempt, 'Authentication error. Please log in again.');
        }

        // Consume the attempt before deciding anything else: a challenge that reached
        // this point is spent whether or not the login is allowed to complete, so a
        // denied account cannot retry the same code once its state changes back. One
        // conditional update, so of two concurrent submissions (or a submission racing
        // the wrong-code cap) only one can consume it.
        if (! $this->consume($attempt)) {
            return $this->failure($request, $attempt, 'Invalid or expired verification attempt.');
        }

        if (! $this->userPolicy->canLogin($user, $request)) {
            // The challenge may have been created before the account was disabled.
            // canLogin() is the gate for *any* login, so it is rechecked here rather
            // than trusted from whenever the first factor passed.
            $request->session()->forget([
                config('bherila-auth.two_factor.session_user_key', 'bherila_auth_2fa_user_id'),
                config('bherila-auth.two_factor.session_remember_key', 'bherila_auth_2fa_remember'),
            ]);

            return $this->failure($request, $attempt, 'Your account is not active.');
        }

        // The first factor was a local password; an account that may not use one must not
        // finish signing in with it, whenever its challenge was created.
        if (! app(LocalCredentialPolicy::class)->mayUseLocalCredentials($user, $request)) {
            $request->session()->forget([
                config('bherila-auth.two_factor.session_user_key', 'bherila_auth_2fa_user_id'),
                config('bherila-auth.two_factor.session_remember_key', 'bherila_auth_2fa_remember'),
            ]);

            return $this->failure($request, $attempt, 'This account signs in through single sign-on.');
        }

        Auth::login($user, (bool) $request->session()->pull(config('bherila-auth.two_factor.session_remember_key', 'bherila_auth_2fa_remember'), false));
        $request->session()->forget(config('bherila-auth.two_factor.session_user_key', 'bherila_auth_2fa_user_id'));
        $request->session()->regenerate();

        $redirect = $this->userPolicy->redirectAfterLogin($user, $request);
        $this->auditLogger->twoFactorLoginSucceeded($request, $user, $attempt);
        event(new TwoFactorLoginSucceeded($user, $attempt));

        if ($request->expectsJson()) {
            return response()->json([
                'success' => true,
                'message' => 'Login successful.',
                'redirect' => $redirect,
            ]);
        }

        return redirect()->to($redirect);
    }

    /**
     * Mark the attempt used if nothing else has; whether this request was the one that did.
     *
     * @param  array<string, mixed>  $also  further columns written only by the request that wins
     */
    private function consume(TwoFactorAttempt $attempt, array $also = []): bool
    {
        $consumed = TwoFactorAttempt::query()
            ->whereKey($attempt->getKey())
            ->where('is_used', false)
            ->update(['is_used' => true, ...$also]) === 1;

        $written = ['is_used' => true, ...($consumed ? $also : [])];
        $attempt->forceFill($written)->syncOriginalAttributes(array_keys($written));

        return $consumed;
    }

    /** The emailed links' secret, from the query string or the body. */
    private function linkSecret(Request $request): ?string
    {
        $secret = $request->input('secret');

        return is_string($secret) && $secret !== '' ? $secret : null;
    }

    /**
     * Count a wrong code against its challenge, and spend the challenge at the cap.
     *
     * Counted here rather than in route middleware so every route that verifies through
     * this controller (an application's own emergency sign-in, for one) has the same cap.
     * The counter lives in Laravel's limiter cache store for the challenge's remaining
     * lifetime, keyed by a hash of the token. Whether the challenge was spent.
     */
    private function spendAfterWrongCode(TwoFactorAttempt $attempt): bool
    {
        $maximum = (int) config('bherila-auth.two_factor.max_wrong_codes', 5);
        if ($maximum < 1) {
            return false;
        }

        $key = 'bherila-auth.two-factor-wrong-codes:'.hash('sha256', $attempt->token);
        $misses = RateLimiter::increment($key, max(1, (int) ceil(now()->diffInSeconds($attempt->expires_at, true))));

        if ($misses < $maximum) {
            return false;
        }

        $this->consume($attempt);
        RateLimiter::clear($key);

        return true;
    }

    private function failure(Request $request, ?TwoFactorAttempt $attempt, string $message, bool $audit = true): JsonResponse|RedirectResponse
    {
        $user = $attempt?->user;
        if ($audit) {
            $this->auditLogger->twoFactorLoginFailed($request, $user instanceof Authenticatable ? $user : null, $attempt, $message);
        }

        if ($request->expectsJson()) {
            return response()->json(['success' => false, 'message' => $message], 422);
        }

        return redirect(config('bherila-auth.two_factor.login_url', '/login'))->withErrors(['code' => $message]);
    }

    /**
     * Whether the fixed test code may stand in for this attempt's real code.
     *
     * Every condition must hold: the setting is on, the environment is one the
     * setting is allowed in, and the account is explicitly marked as a test user.
     * Previously either the setting or an `is_test` account was enough on its own,
     * which meant the setting could not actually turn the bypass off, and its
     * default (any environment that is not literally `production`) left a public
     * staging deploy accepting one fixed code for every account.
     */
    private function allowTestCode(TwoFactorAttempt $attempt): bool
    {
        if (! (bool) config('bherila-auth.two_factor.allow_test_code', false)) {
            return false;
        }

        $environments = array_values(array_filter((array) config('bherila-auth.two_factor.test_code_environments', ['local', 'testing'])));

        if ($environments !== [] && ! app()->environment($environments)) {
            return false;
        }

        return (bool) data_get($attempt->user, 'is_test', false);
    }

    private function maskEmail(string $email): string
    {
        if (! str_contains($email, '@')) {
            return $email;
        }

        [$local, $domain] = explode('@', $email, 2);

        return mb_substr($local, 0, 1).str_repeat('*', max(mb_strlen($local) - 1, 1)).'@'.$domain;
    }
}
