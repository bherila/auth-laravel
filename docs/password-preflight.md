# Password credential preflight

`BWH\Auth\Services\PasswordCredentials::verify($request, $credentials, $guard = null)`
checks a password through the configured session guard and its user provider.
The default guard is resolved at each call, including inside an embedded provider
context. An explicit guard name selects that guard without changing the default.
Token and request guards are refused; custom `SessionGuard` subclasses work.

The typed result contains `status` (`PasswordCredentialStatus::Verified`,
`InvalidCredentials`, or `AccountDisabled`) and the attempted `Authenticatable`
user when one was found. Successful validation also requires the bound
`AuthUserPolicy::canLogin()`. Password rehashing uses the user provider after
policy approval, respecting `hashing.rehash_on_login`.

Preflight does not sign anyone in, modify the session or remember cookie, send a
second factor, record authentication context, audit a login or inspect a throttle.
Laravel's validation timebox and `Validated` event remain in use. Callers must
inspect their throttle before preflight, record their own failure once, and decide
whether to issue a second-factor challenge or complete login with the same guard.
The result contains no password, hash, remember choice or redirect destination.
