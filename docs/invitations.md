# Invitation secrets and lifecycle

Applications invite people to a workspace, a company, shared records or a single document.
The mechanism underneath is the same each time, and these pieces supply it so each
application keeps only what the invitation means:

| Piece | What it does |
| --- | --- |
| `InvitationSecret` | 256-bit bearer secret for a link; stores only its SHA-256 |
| `InvitationDigest` | Whether that digest is stored as hex or as raw bytes |
| `InvitationState` | Pending, accepted, declined, revoked or expired, derived from timestamps and the clock |
| `HasInvitationSecret` | Model trait: issue a secret, find the row a presented secret belongs to |
| `HasInvitationLifecycle` | Model trait: an invitation's state, and a query scope for the open ones |

The package adds no table, route, mail or acceptance logic. Who may invite, what accepting
grants, quotas, and whether the person accepting must be the one invited stay in the
application.

## Secrets

```php
use BWH\Auth\Invitations\InvitationSecret;

$secret = InvitationSecret::generate();   // 64 lowercase hex characters
$secret->plaintext;                      // goes into the link, once
$secret->digest();                       // what the database stores
```

Only the digest is stored. A lookup hashes the presented value, so a digest read out of the
database or a backup cannot be used as a link. The plaintext is redacted from `var_dump()`
and `print_r()` and marked `#[\SensitiveParameter]`, so it stays out of stack traces. Never
log it.

`InvitationSecret::digestOf($presented, InvitationDigest::Binary)` hashes a value without a
model. Choose the encoding the column already uses: a `CHAR(64)` column holds hex, a
`BINARY(32)` column raw bytes. Changing the encoding of a table that holds invitations orphans
every link already sent.

A digest lookup needs no `hash_equals()`: the database compares SHA-256 digests of the
presented value, so timing reveals nothing usable about the stored secret.

## Models

```php
use BWH\Auth\Invitations\HasInvitationLifecycle;
use BWH\Auth\Invitations\HasInvitationSecret;
use BWH\Auth\Invitations\InvitationDigest;

class WorkspaceInvitation extends Model
{
    use HasInvitationLifecycle, HasInvitationSecret;

    // Defaults: hex digest in `token_hash`. Override to match an existing column.
    protected function invitationSecretDigest(): InvitationDigest
    {
        return InvitationDigest::Binary;
    }

    protected function casts(): array
    {
        return [
            'accepted_at' => 'datetime',
            'declined_at' => 'datetime',
            'revoked_at' => 'datetime',
            'expires_at' => 'datetime',
        ];
    }
}
```

Issuing sets the digest on the model without saving it, and returns the only copy of the
plaintext:

```php
$invitation = new WorkspaceInvitation([...]);
$secret = $invitation->issueInvitationSecret();
$invitation->save();

Mail::to($email)->send(new InvitationMail(route('invitations.show', $secret->plaintext)));
```

Calling `issueInvitationSecret()` again replaces the secret, so the earlier link stops working.

Resolve a presented secret with the scope, and lock the row when accepting it, so two
concurrent accepts cannot both succeed:

```php
DB::transaction(function () use ($presented, $user) {
    $invitation = WorkspaceInvitation::query()
        ->whereInvitationSecret($presented)
        ->lockForUpdate()
        ->first();

    if ($invitation === null || ! $invitation->isOpenInvitation()) {
        abort(404);
    }

    // The application's own checks and side effects, then:
    $invitation->forceFill(['accepted_at' => now()])->save();
});
```

An empty value, or one over `InvitationSecret::MAX_PRESENTED_LENGTH` (512) characters,
matches nothing without being hashed. Tokens issued before an application adopted these
pieces still resolve, whatever their format, as long as their digest is stored with the same
hash and encoding.

To say *why* an invitation cannot be used, look it up without `openInvitations()` and read
`invitationState()`. Whether to tell the visitor is the application's choice: a link that
needs no sign-in should usually answer every failure alike, so a probe learns nothing.

## State

`InvitationState::of($acceptedAt, $declinedAt, $revokedAt, $expiresAt, $now)` applies a fixed
precedence:

1. **Accepted**, whatever happened after.
2. **Revoked**: the inviter's deliberate action is never reported as declined or expired.
3. **Declined**
4. **Expired**, from the expiry instant itself. A null expiry never lapses.
5. **Pending**: the only open state.

`invitationState(?$now)` and `isOpenInvitation(?$now)` read the model's columns and use the
application clock unless given an instant. The `openInvitations(?$now)` scope applies the same
rule in SQL, so a row it returns reports `Pending` at that instant.

Rename columns, or map one to `null` when the table has no such transition, by overriding
`invitationLifecycleColumns()`:

```php
protected function invitationLifecycleColumns(): array
{
    return ['accepted' => 'redeemed_at', 'declined' => null, 'revoked' => 'revoked_at', 'expires' => 'expires_at'];
}
```

Every mapped column must be cast to a datetime; an uncast one throws rather than being read
as text.
