<?php

namespace BWH\Auth\Http\Controllers;

use BWH\Auth\Contracts\AuthAuditLogger;
use BWH\Auth\Contracts\LocalCredentialPolicy;
use BWH\Auth\Contracts\AuthUserPolicy;
use BWH\Auth\Models\TwoFactorAttempt;
use BWH\Auth\Services\TwoFactorService;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Auth;
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

    public function confirm(Request $request, string $token): JsonResponse|RedirectResponse|View
    {
        $attempt = TwoFactorAttempt::where('token', $token)->first();

        if (! $attempt || ! $attempt->isValid()) {
            return $this->failure($request, $attempt, 'Invalid or expired login link. Please log in again.', false);
        }

        if ($request->expectsJson()) {
            return response()->json(['success' => true, 'attempt_token' => $attempt->token]);
        }

        return view('bherila-auth::two-factor-confirm', [
            'attempt' => $attempt,
            'token' => $token,
            'userEmail' => $this->maskEmail((string) data_get($attempt->user, config('bherila-auth.users.email_attribute', 'email'), '')),
            'submitRoute' => route('bherila-auth.two-factor.confirm.submit', ['token' => $token]),
            'loginUrl' => config('bherila-auth.two_factor.login_url', '/login'),
        ]);
    }

    public function confirmSubmit(Request $request, string $token): JsonResponse|RedirectResponse
    {
        $attempt = TwoFactorAttempt::where('token', $token)->first();

        if (! $attempt || ! $attempt->isValid()) {
            return $this->failure($request, $attempt, 'Invalid or expired login link. Please log in again.');
        }

        return $this->completeLogin($request, $attempt);
    }

    public function report(Request $request, string $token): JsonResponse|View
    {
        $attempt = TwoFactorAttempt::where('token', $token)->first();

        if ($request->expectsJson()) {
            return response()->json([
                'success' => true,
                'can_report' => (bool) ($attempt && ! $attempt->is_used),
            ]);
        }

        return view('bherila-auth::two-factor-report', [
            'attempt' => $attempt,
            'token' => $token,
            'submitRoute' => route('bherila-auth.two-factor.report.submit', ['token' => $token]),
            'loginUrl' => config('bherila-auth.two_factor.login_url', '/login'),
        ]);
    }

    public function reportSubmit(Request $request, string $token): JsonResponse|View
    {
        $attempt = TwoFactorAttempt::where('token', $token)->first();

        if ($attempt && ! $attempt->is_used) {
            $attempt->update(['is_suspicious' => true, 'is_used' => true]);
            if ($attempt->user instanceof Authenticatable) {
                $this->auditLogger->twoFactorReportedSuspicious($request, $attempt->user, $attempt);
            }
        }

        if ($request->expectsJson()) {
            return response()->json([
                'success' => true,
                'message' => 'This login attempt has been reported.',
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
        // denied account cannot retry the same code once its state changes back.
        $attempt->update(['is_used' => true]);

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

        if ($request->expectsJson()) {
            return response()->json([
                'success' => true,
                'message' => 'Login successful.',
                'redirect' => $redirect,
            ]);
        }

        return redirect()->to($redirect);
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
