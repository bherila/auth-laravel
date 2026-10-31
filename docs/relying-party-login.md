# Signing in through the identity provider

`BWH\Auth\Http\Controllers\RelyingPartyLoginController` is the sign-in, callback and sign-out
for an application that relies on the identity provider. It replaces the per-application
`OAuthLoginController` copies, and `oauth:bind-subject` replaces the copied
`BindOAuthSubjectCommand`.

## Adopting it

1. Give the account table its binding columns, if it does not have them, and make them
   compare exactly. Publish the migration, review it, and let the deployment run it:

   ```sh
   php artisan vendor:publish --tag=bherila-auth-oauth-identity-migration
   ```

   It calls `OAuthIdentityColumns::ensure('users')`. That adds nullable `oauth_provider` and
   `oauth_subject` columns with a composite unique index if they are missing. On MySQL and
   MariaDB it converts both to `VARBINARY`, so `Alice` and `alice` are different subjects. It
   is idempotent, refuses a table holding a value too long for the new width, and is safe
   against the previous release, so a code rollback needs no schema rollback. Column names
   come from `provider_identity.binding`.

2. Extend the controller and route to it. The package registers no routes for it:

   ```php
   final class OAuthLoginController extends RelyingPartyLoginController
   {
       protected function landingUrl(Request $request, Authenticatable $account): string
       {
           return route('dashboard');
       }
   }

   Route::get('/oauth/redirect', [OAuthLoginController::class, 'redirect'])->middleware('throttle:20,1');
   Route::get('/oauth/callback', [OAuthLoginController::class, 'callback'])->middleware('throttle:20,1');
   // Outside `auth`: a page left open past its session must still be able to sign out.
   Route::post('/logout', [OAuthLoginController::class, 'logout'])->name('logout');
   ```

3. If the account table is not a stock `users` table, extend
   `BWH\Auth\OAuth\Login\RelyingPartyAccounts` and name it as `oauth_login.accounts`.

4. Delete the application's copied controller logic and `BindOAuthSubjectCommand`. The
   package registers `oauth:bind-subject`.

## What the callback does

In order:

1. Exchange the code and fetch the identity.
2. Resolve the local account (below).
3. Refuse an account `AuthUserPolicy::canLogin()` rejects, with a 403.
4. Log in on a regenerated session.
5. Record the provider-session baseline (`ProviderSession::establish`). With
   [enforcement](provider-session-verification.md) on, a sign-in that cannot be verified is
   undone and answered 503 with `Retry-After: 30`.
6. Remember the provider's application list.
7. Run `afterSignIn()`.
8. Audit the sign-in, with method `oauth`.
9. Redirect to the intended page or to `landingUrl()`.

## Which account a sign-in reaches

`SubjectBoundAccounts` holds the rules. They are not overridable:

- An account is found by (provider, subject) and nothing else. A matching address never
  adopts an account.
- Before any write sets an address, the account already holding it is read under lock. If
  that is another account, the sign-in is refused with a 409. The operator log carries the
  reason and the row ids, never the address or subject. If the two are the same person, an
  operator links them with `php artisan oauth:bind-subject <id> <subject>`.
- If a concurrent sign-in for the same identity wins the race, its row is adopted only if
  it already carries the profile this sign-in asserts. Otherwise the sign-in is a 409.
- Delegated provisioning can commit a `PendingAccount` placeholder after the first read. That
  placeholder is filled in, not refused.
- Locks are taken in one order: the subject's row, then the address holder.

`RelyingPartyAccounts` decides what differs per application:

| Method | Default | Override for |
| --- | --- | --- |
| `model()` | `bherila-auth.users.model` | another model |
| `lockForUpdate($query)` | `lockForUpdate()` | a lock-ordering helper |
| `newAccountAttributes($identity)` | name, email, `email_verified_at = now()`, random password | extra defaults (a role), other columns (`alias`), `email_verified_at = null` |
| `refreshedAttributes($account, $identity)` | name, email, `email_verified_at = now()` | keeping an address the person confirmed locally: leave the email out, and the collision check is skipped |
| `assertsSameProfile($account, $identity)` | same name and address (case-insensitive) | the columns the application refreshes |
| `provisionsNewAccounts()` | `true` | `false` for an application whose accounts are made only by an operator or by delegated provisioning: an unknown subject is refused before anything is written, and the controller answers with `unknownIdentityResponse()`. Accounts are linked with `oauth:bind-subject`. |

The binding columns are always written by the package and are dropped from any attribute
array the application returns, so they need not be fillable.

## Controller hooks

| Hook | Default |
| --- | --- |
| `landingUrl($request, $account)` | `/` |
| `unknownIdentityResponse($request, $identity)` | 403. Only reached when `provisionsNewAccounts()` is false. |
| `disabledAccountResponse($request, $account)` | 403 "This account is disabled." Override to send the person to a page that explains. |
| `afterSignIn($request, $account, $identity)` | nothing. Runs only for a sign-in that completed. |
| `signsOutLocallyOnly($request, $user)` | `false`. Return `true` for a session that never involved the provider (Google, a break-glass password), so signing out does not end the person's sessions in every sibling application. |
| `afterSignOutUrl($request)` | `url('/')` |
| `logoutResponse($request, $redirect)` | `away()`: 409 with `X-Inertia-Location` for an Inertia visit, otherwise the redirect. Both the provider sign-out and the local-only sign-out end here. Override to answer a fetch client, e.g. `return $request->expectsJson() ? response()->json(['redirect' => $redirect->getTargetUrl()]) : parent::logoutResponse($request, $redirect);`. |
| `afterLocalSignOut($request, $user)` | audits the sign-out |
| `$remember` | `false` |
| `$returnParameter` | `'redirect'`. `?redirect=` on the redirect route names the page to return to. Only a path on this site, or an absolute URL on this origin, is kept (`BWH\Auth\Support\IntendedUrl`). Anything else is dropped. |

Inertia visits (`X-Inertia`) get a 409 with `X-Inertia-Location` wherever a redirect leaves
the origin. Nothing depends on Inertia.

## Local credentials for provider-bound accounts

`AuthUserPolicy::canLogin()` answers whether an account may sign in at all, by any method,
the provider included. `LocalCredentialPolicy::mayUseLocalCredentials()` answers whether it
may use a credential the application holds itself:
- a password
- a password reset
- a passkey
- the second factor of a password sign-in

Set `bherila-auth.local_credentials.provider_bound` (`BHERILA_AUTH_LOCAL_CREDENTIALS_PROVIDER_BOUND`)
to choose:

- `allow` (default). No change.
- `refuse`. An account the `ProviderBindingResolver` reports as bound, or whose binding is
  broken, cannot request or complete a password reset, change its password, add or use a
  passkey, or finish a two-factor password sign-in. A reset request for it answers exactly
  like one for an unknown address. Unbound accounts are unaffected.

Use `refuse` when every person signs in through the provider and local accounts exist only
for break-glass. A local credential would otherwise outlive the provider disabling the
account, revoking its grant, or requiring a second factor. An application's own
password-login controller must call the policy too:

```php
if (! app(LocalCredentialPolicy::class)->mayUseLocalCredentials($user, $request)) {
    // 'This account signs in through single sign-on.'
}
```

Do not override `canLogin()` to mean "not bound": the callback calls it, so every bound
account would be refused at the provider too.
