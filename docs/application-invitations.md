# Application-requested admission invitations

An application that manages its own sharing can ask the identity provider to invite someone who
has never signed in. The invitation admits that person to **this application's sign-in client
only**, with no roles. What they may do inside the application is still the application's to
decide, usually when they first sign in.

This package supplies the client for the provider's three endpoints (create, resend, revoke) and
an in-memory fake for application tests. Nothing calls the provider until the application does,
and the provider refuses every application until an operator enables it there.

## Trust model

- **The application authenticates as itself**: a client credentials access token for its own
  sign-in client (`bherila-auth.oauth_client`), with exactly the scope `invitations:admit`.
- **It names the person asking** in an actor assertion: an RS256 JWS signed with a key pair the
  application holds for this purpose alone, whose public half the provider pins.
- **The provider relies on the application's authority check.** It verifies only that the actor
  is an active provider account with a current grant to this application's client. Decide that
  the actor may invite *before* calling.
- **The link is a bearer credential.** It is returned on every create and resend so the person who
  asked can copy it. Show it only to them, never log it, and never return it to automated agents.

## Configuration

The client uses the sign-in client's settings (`bherila-auth.oauth_client.base_url`,
`client_id`, `client_secret` and `token_path`) and these:

| Key (`bherila-auth.application_invitations.*`) | Environment | Default | Meaning |
|---|---|---|---|
| `issuer` | `BHERILA_AUTH_INVITATION_ISSUER` | `oauth_client.base_url` | The provider's exact issuer, an `https://` origin with no path. Requests go here, and each assertion's audience is this value plus the endpoint path, byte for byte. |
| `key_id` | `BHERILA_AUTH_INVITATION_KEY_ID` | none | The key id the provider pinned this application's public key under. |
| `private_key_path` | `BHERILA_AUTH_INVITATION_PRIVATE_KEY_PATH` | none | A readable PEM file holding the RSA private key (at least 2048 bits). |
| `private_key` | `BHERILA_AUTH_INVITATION_PRIVATE_KEY` | none | The PEM itself; escaped `\n` newlines are accepted. Set exactly one of this and `private_key_path`. |
| `private_key_passphrase` | `BHERILA_AUTH_INVITATION_PRIVATE_KEY_PASSPHRASE` | none | The key's passphrase, if it has one. |
| `timeout_seconds` | `BHERILA_AUTH_INVITATION_TIMEOUT_SECONDS` | `10` | Total time per request, clamped to 1 through 30. Connecting takes at most 3. |
| `token_cache_store` | `BHERILA_AUTH_INVITATION_TOKEN_CACHE_STORE` | default store | Where the token is kept between requests, encrypted with the application key. `false` keeps it in the current process only. |

Generate the key pair for this purpose alone, separate from the application's OAuth and delegated
access keys, keep the private key in the application's secret store, and give the operator the
public key and key id. The provider also has to allow the client credentials grant on the
application's sign-in client.

Any missing or invalid setting refuses every call with `ApplicationInvitationMisconfigured`
(`not_configured`) before anything is sent: no client id or secret, no key id, both or neither key
setting, an unreadable or non-RSA key, a key under 2048 bits, or an issuer that is not HTTPS
(loopback HTTP is allowed in `local` and `testing`), has a path, credentials, a query or a fragment.

## Calling it

Resolve `BWH\Auth\OAuth\Invitations\ApplicationInvitations` from the container. Every call names
the actor by their **provider subject**, the `sub` the provider's user endpoint returned for them
(a decimal string with no leading zeros), which the application stores in its provider binding.

```php
use BWH\Auth\OAuth\Invitations\ApplicationInvitationConflict;
use BWH\Auth\OAuth\Invitations\ApplicationInvitationError;
use BWH\Auth\OAuth\Invitations\ApplicationInvitationInvalid;
use BWH\Auth\OAuth\Invitations\ApplicationInvitationRateLimited;
use BWH\Auth\OAuth\Invitations\ApplicationInvitations;

// The application's own check comes first: may this manager invite?
$issued = app(ApplicationInvitations::class)->create($manager->oauth_subject, $email);

$issued->id;         // int: keep it for resend and revoke
$issued->status;     // 'pending'
$issued->expiresAt;  // DateTimeImmutable, UTC, seven days out
$issued->link;       // the acceptance link: a secret, for the manager only
$issued->emailSent;  // whether the provider's email was accepted for delivery

$resent = app(ApplicationInvitations::class)->resend($manager->oauth_subject, $issued->id);   // new link and expiry
$revoked = app(ApplicationInvitations::class)->revoke($manager->oauth_subject, $issued->id);  // RevokedInvitation{id, status: 'revoked'}
```

- **Create** supersedes this application's pending invitation to the same address. The answer is
  identical whether or not the address has a provider account.
- **Resend** works on a pending or expired invitation; the old link stops working at once.
- **Revoke** is idempotent. An accepted invitation cannot be revoked: remove the person's access in
  the application instead.

`IssuedInvitation` leaves the link out of `json_encode()` and debug output, so serializing or
dumping one never discloses it. Read `$issued->link` explicitly where the manager should see it.

The address is sent exactly as given; the provider validates it. An empty address, one over 255
characters or one that is not UTF-8 is refused before sending (`ApplicationInvitationInvalid` with
a null `status`). An actor subject not in the provider's form, or an invitation id under 1, throws
`InvalidArgumentException`.

## Failures

Every failure is an `ApplicationInvitationException`. Catch the subclass for the kind, and read
`$e->error` (an `ApplicationInvitationError`) for the exact reason. `$e->status` is the provider's
HTTP status, null when nothing was answered, and `$e->retryAfter` its `Retry-After` in seconds.
Messages are fixed per reason; no exception carries the address, the link, a token, the assertion,
a response body or the transport's exception.

| Exception | `error` (status) | What to do |
|---|---|---|
| `ApplicationInvitationMisconfigured` | `not_configured`, `token_refused` (400/401 from the token endpoint), `invalid_token` (401), `insufficient_scope` (403), `application_not_enabled` (403), `invalid_actor_assertion` (401), `replayed_actor_assertion` (401), `invalid_configuration` (503) | Tell the manager invitations are unavailable and alert an operator; retrying does not help. |
| `ApplicationInvitationActorNotEligible` | `actor_not_eligible` (403) | The manager cannot sign in to this application at the provider. |
| `ApplicationInvitationInvalid` | `invalid_request` (422, or null when refused here) | Show `$e->errors` (messages by field; they never repeat the address). |
| `ApplicationInvitationNotFound` | `invitation_not_found` (404) | The id was not requested through this application's client. |
| `ApplicationInvitationConflict` | `invitation_not_pending` (409), `invitation_accepted` (409), `concurrent_invitation` (409) | Refresh the invitation's state; `concurrent_invitation` may be tried again. |
| `ApplicationInvitationRateLimited` | `rate_limited` (429) | `$e->limit` is `application`, `actor`, `recipient`, or null for the provider's coarse request throttle. |
| `ApplicationInvitationUnavailable` | `mail_unavailable` (503), `replay_storage_unavailable` (503), `unavailable` (unreachable, or a status the contract does not define), `invalid_response` (an answer outside the contract) | Try again later. |

A provider `error` code is trusted only at the status the contract gives it; anything else is
`unavailable`. A refused request changed nothing at the provider. After `unavailable` or
`invalid_response` the outcome is unknown: a create may have happened, and creating again simply
supersedes it.

## What is sent

All three calls `POST` to the issuer:

| Operation | Path | Body | Success |
|---|---|---|---|
| Create | `/api/application-invitations` | `{"email":"<address>"}` | `201` |
| Resend | `/api/application-invitations/{id}/resend` | `{}` | `200` |
| Revoke | `/api/application-invitations/{id}/revoke` | `{}` | `200` |

Headers: `Authorization: Bearer <token>`, `Actor-Assertion: <JWS>`, `Content-Type:
application/json`, `Accept: application/json`.

The token comes from `POST <issuer><token_path>` with `grant_type=client_credentials`, the client
id and secret, and `scope=invitations:admit`. It is reused until 30 seconds before `expires_in`,
cached under a key derived from the issuer, client id, secret and scope, so a rotated secret never
reuses an old token. If the provider refuses a *reused* token as `invalid_token`, which it decides
before reading the assertion or changing anything, the client fetches one new token and sends once
more with a new assertion. Nothing else is retried.

The assertion's header is exactly `{alg: RS256, typ: application-invitation+jwt, kid}`. Its claims
are exactly:

| Claim | Value |
|---|---|
| `iss` | `oauth_client.client_id` |
| `sub` | the actor's provider subject |
| `aud` | the exact URL called: issuer plus path |
| `iat`, `exp` | integer seconds, `exp` = `iat` + 60 |
| `jti` | 64 lowercase hex characters, new for every request |
| `method` | `POST` |
| `body_sha256` | lowercase hex SHA-256 of the exact body bytes sent |

The package's tests sign with this client and verify with a verbatim copy of the provider's
verifier, so an assertion the provider would refuse fails the suite.

Requests never follow redirects, are bounded in connect and total time, and read at most 16 KiB of
any answer. Success answers are checked field by field: the status must be `201` or `200` as above,
the `id` an integer (the same id for resend and revoke), `status` exactly `pending` or `revoked`,
`expires_at` a UTC `Y-m-d\TH:i:s\Z` instant, `link` an absolute HTTPS URL without credentials (loopback HTTP in `local` and `testing`), and
`email_sent` a boolean.

## Testing an application

`BWH\Auth\Testing\FakeApplicationInvitations` is an in-memory provider. `swap()` binds it in place
of the client and returns it:

```php
use BWH\Auth\OAuth\Invitations\ApplicationInvitationError;
use BWH\Auth\Testing\FakeApplicationInvitations;

$invitations = FakeApplicationInvitations::swap();

$this->actingAs($manager)->post('/settings/contacts', ['email' => 'person@example.test']);

$invitations->assertCreated('person@example.test', actor: $manager->oauth_subject);
$invitations->calls();              // every call: operation, actor, email, invitation_id, result, error
$invitations->invitation(1);        // the fake provider's view: status, expires_at, link, ...

// Script the next call of an operation; the refusal is the client's own exception for the reason.
$invitations->refuseNext('create', ApplicationInvitationError::RateLimited, retryAfter: 60, limit: 'actor');
$invitations->refuseNext('resend', ApplicationInvitationError::InvitationNotPending);
$invitations->respondNext('create', $issuedInvitation);

$invitations->accept(1);            // the recipient accepted: revoke and resend now refuse
$invitations->assertResent(1);
$invitations->assertRevoked(1);
$invitations->assertNotCreated();
$invitations->assertNothingRequested();
$invitations->assertRequestCount(2, 'create');
```

Unscripted, the fake behaves as the provider does: ids count up from 1; a create supersedes the
pending invitation to the same address (case-insensitive) and returns a new link
(`https://identity.example.test/invitations/fake-…`); resend and revoke answer
`invitation_not_found` for an id it did not create; resend refuses a revoked or accepted invitation;
revoke refuses an accepted one and is otherwise idempotent; invitations expire seven days after
their create or resend (it follows the test clock). It refuses an address that fails
`FILTER_VALIDATE_EMAIL` with `invalid_request` (422), and checks arguments exactly as the client
does. It sends nothing over HTTP.
