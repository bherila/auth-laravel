<?php

namespace BWH\Auth\Services;

use BWH\Auth\Contracts\AuthAuditLogger;
use BWH\Auth\Mail\TwoFactorLoginMail;
use BWH\Auth\Models\TwoFactorAttempt;
use BWH\Auth\Support\TwoFactorRoutes;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Mail;

class TwoFactorService
{
    public function __construct(private readonly AuthAuditLogger $auditLogger) {}

    public function startChallenge(Authenticatable $user, Request $request, bool $remember = false): TwoFactorAttempt
    {
        // Freeze the recipient before creating the attempt: model hooks or another
        // writer may change the account while the challenge is being issued.
        $email = data_get($user, config('bherila-auth.users.email_attribute', 'email'));
        $attempt = TwoFactorAttempt::createForUser($user, $request->ip(), $request->userAgent(),
            recipient: is_string($email) ? $email : null);

        $request->session()->put(config('bherila-auth.two_factor.session_user_key', 'bherila_auth_2fa_user_id'), $user->getAuthIdentifier());
        $request->session()->put(config('bherila-auth.two_factor.session_remember_key', 'bherila_auth_2fa_remember'), $remember);

        $appName = config('app.name', 'Application');

        // The links carry the attempt's link secret as well as its token. The token is also
        // handed to the browser that passed the password step, so on its own it must not be
        // able to finish the sign-in the email is the second factor for. Without a secret
        // (the column has not been migrated) the email carries the code only.
        $secret = $attempt->linkSecret();

        Mail::to($email)->send(new TwoFactorLoginMail(
            $user,
            $attempt,
            $secret === null ? null : $this->routeFromAppUrl(TwoFactorRoutes::name('confirm'), ['token' => $attempt->token, 'secret' => $secret]),
            $secret === null ? null : $this->routeFromAppUrl(TwoFactorRoutes::name('report'), ['token' => $attempt->token, 'secret' => $secret]),
            $appName,
        ));

        $this->auditLogger->twoFactorChallengeCreated($request, $user, $attempt);

        return $attempt;
    }

    /**
     * Build a fully-qualified route URL rooted at the configured app.url
     * rather than the incoming request host.
     *
     * These URLs are emailed during the login challenge, so deriving them
     * from the request host would let an attacker poison them via a spoofed
     * Host / X-Forwarded-Host header and point the victim's 2FA confirm or
     * report link at an attacker-controlled domain (host-header injection).
     */
    private function routeFromAppUrl(string $name, array $parameters): string
    {
        $appUrl = rtrim((string) config('app.url'), '/');

        if ($appUrl === '') {
            // No app.url configured; fall back to the framework default.
            return route($name, $parameters);
        }

        return $appUrl.route($name, $parameters, false);
    }
}
