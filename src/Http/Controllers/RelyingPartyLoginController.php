<?php

namespace BWH\Auth\Http\Controllers;

use BWH\Auth\Concerns\LogsAuthEvents;
use BWH\Auth\Concerns\SignsOutThroughProvider;
use BWH\Auth\Contracts\AuthUserPolicy;
use BWH\Auth\OAuth\Login\AccountConflict;
use BWH\Auth\OAuth\Login\RelyingPartyAccounts;
use BWH\Auth\OAuth\Login\SubjectBoundAccounts;
use BWH\Auth\OAuth\OAuthClient;
use BWH\Auth\OAuth\OAuthIdentity;
use BWH\Auth\OAuth\ProviderApplications;
use BWH\Auth\OAuth\Session\ProviderSession;
use BWH\Auth\OAuth\Session\ProviderStatusUnavailable;
use BWH\Auth\Support\IntendedUrl;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Log;
use Symfony\Component\HttpFoundation\Response;

/**
 * Sign-in and sign-out through the identity provider, for an application that relies on it.
 *
 * Extend it and route to it; the package registers no routes for it:
 *
 *     final class OAuthLoginController extends RelyingPartyLoginController {}
 *
 *     Route::get('/oauth/redirect', [OAuthLoginController::class, 'redirect'])->middleware('throttle:20,1');
 *     Route::get('/oauth/callback', [OAuthLoginController::class, 'callback'])->middleware('throttle:20,1');
 *     Route::post('/logout', [OAuthLoginController::class, 'logout'])->name('logout');
 *
 * The callback, in order: exchange the code and fetch the identity; resolve the local account
 * ({@see SubjectBoundAccounts}, with the application's {@see RelyingPartyAccounts}); refuse an
 * account {@see AuthUserPolicy::canLogin()} rejects; log in on a new session; record the
 * provider session baseline ({@see ProviderSession}); remember the application list; run
 * {@see afterSignIn()}; audit; land on the intended page or {@see landingUrl()}.
 *
 * Nothing about the account is decided in a subclass. What a subclass decides is where the
 * person lands, what else happens once they are in, and, for an application with another way
 * to sign in, which sessions end only locally.
 *
 * Inertia requests get a 409 with `X-Inertia-Location` wherever a redirect leaves this origin:
 * an XHR cannot follow a cross-origin redirect, so without it the page would stay where it was.
 * Nothing here depends on Inertia; other requests get ordinary redirects.
 */
abstract class RelyingPartyLoginController extends Controller
{
    use LogsAuthEvents, SignsOutThroughProvider;

    /** Whether a successful sign-in also sets the remember-me cookie. */
    protected bool $remember = false;

    /** The query parameter a sign-in link may name its return page in; null accepts none. */
    protected ?string $returnParameter = 'redirect';

    public function redirect(Request $request, OAuthClient $oauth): Response
    {
        if ($this->returnParameter !== null) {
            IntendedUrl::remember($request, $this->returnParameter);
        }

        return $this->away($request, $oauth->redirect($request));
    }

    public function callback(Request $request, OAuthClient $oauth): Response
    {
        $identity = $oauth->identityFromCallback($request);

        try {
            $account = app(SubjectBoundAccounts::class)->resolve($identity, $this->accounts());
        } catch (AccountConflict $conflict) {
            Log::warning('OAuth sign-in could not be given an account.', $conflict->context());
            $this->auditLoginFailed($request, null, null, 'Identity could not be linked: '.$conflict->reason, 'oauth');

            throw $conflict;
        }

        if (! $account instanceof Authenticatable) {
            throw new \LogicException('The OAuth account model must be Authenticatable.');
        }

        if (! app(AuthUserPolicy::class)->canLogin($account, $request)) {
            $this->auditLoginFailed($request, $account, null, 'Account disabled', 'oauth');
            abort(403, 'This account is disabled.');
        }

        $guard = $this->sessionGuard();
        $guard->login($account, $this->remember);
        $request->session()->regenerate();

        // The provider credential generation this login was made under, the baseline every
        // later check of this session compares against. Recorded while enforcement is off
        // too, so turning it on does not end every session at once. With enforcement on, a
        // login that cannot be verified has already been undone here; the person retries.
        try {
            app(ProviderSession::class)->establish($request, $identity, $guard);
        } catch (ProviderStatusUnavailable) {
            $this->auditLoginFailed($request, $account, null, 'Provider session unverified', 'oauth');
            abort(503, 'Sign-in verification is unavailable. Please retry.', [
                'Retry-After' => '30',
                'Cache-Control' => 'private, no-store',
            ]);
        }

        // Only once the application has admitted the person: a refused sign-in leaves
        // nothing behind in the visitor's session.
        ProviderApplications::remember($request, $identity->apps);

        $this->afterSignIn($request, $account, $identity);

        $this->auditLoginSucceeded($request, $account, 'oauth');

        return redirect()->intended($this->landingUrl($request, $account));
    }

    /**
     * Left outside `auth` middleware on purpose: a page left open past its session still
     * shows the menu, and clicking it must still end the provider session rather than send
     * the person to sign in again.
     */
    public function logout(Request $request, OAuthClient $oauth): Response
    {
        $user = $this->sessionGuard()->user();

        if ($this->signsOutLocallyOnly($request, $user)) {
            $this->sessionGuard()->logout();
            $request->session()->invalidate();
            $request->session()->regenerateToken();
            $this->afterLocalSignOut($request, $user);

            return $this->away($request, redirect($this->afterSignOutUrl($request)));
        }

        return $this->away($request, $this->signOutThroughProvider($request, $oauth, $this->afterSignOutUrl($request)));
    }

    /** The application's account rules; `bherila-auth.oauth_login.accounts` by default. */
    protected function accounts(): RelyingPartyAccounts
    {
        return RelyingPartyAccounts::configured();
    }

    /** Where a sign-in lands when no page asked to be returned to. */
    protected function landingUrl(Request $request, Authenticatable $account): string
    {
        return '/';
    }

    /**
     * Runs once the person is signed in and verified, before the sign-in is audited.
     *
     * A sign-in undone earlier (refused, or unverifiable with enforcement on) never gets
     * here, so whatever this applies is applied only to a session that exists.
     */
    protected function afterSignIn(Request $request, Authenticatable $account, OAuthIdentity $identity): void
    {
        //
    }

    /**
     * Whether this session ends here only, without the provider's end-session hand-off.
     *
     * For an application with a sign-in that never involved the provider (Google, a local
     * break-glass password): ending the provider session for it would sign the person out
     * of every sibling application for no reason.
     */
    protected function signsOutLocallyOnly(Request $request, ?Authenticatable $user): bool
    {
        return false;
    }

    /** Where to come back to after signing out; the provider validates it against its registered origins. */
    protected function afterSignOutUrl(Request $request): string
    {
        return url('/');
    }

    protected function afterLocalSignOut(Request $request, ?Authenticatable $user): void
    {
        $this->auditLoggedOut($request, $user);
    }

    /**
     * The default guard: {@see SignsOutThroughProvider} ends that one, so signing in on any
     * other would leave a session sign-out cannot reach.
     */
    protected function sessionGuard(): StatefulGuard
    {
        $guard = Auth::guard();
        if (! $guard instanceof StatefulGuard) {
            throw new \LogicException('OAuth sign-in needs a stateful guard.');
        }

        return $guard;
    }

    /** A redirect, or for an Inertia visit the external-location response it can follow. */
    protected function away(Request $request, RedirectResponse $redirect): Response
    {
        if ($request->headers->has('X-Inertia')) {
            return response('', 409, ['X-Inertia-Location' => $redirect->getTargetUrl()]);
        }

        return $redirect;
    }
}
