<?php

namespace BWH\Auth\Invitations;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;

/**
 * An Eloquent invitation whose link carries a bearer {@see InvitationSecret}, of which the model
 * stores only the digest.
 *
 * By default the digest is hex in `token_hash`. Override {@see self::invitationSecretColumn()}
 * and {@see self::invitationSecretDigest()} to match an existing column: changing either for a
 * table that already holds invitations would orphan every link already sent.
 *
 * Issue with {@see self::issueInvitationSecret()} and resolve with the `whereInvitationSecret`
 * scope. Whether the invitation found can still be used is the application's question, usually
 * answered with {@see HasInvitationLifecycle}.
 *
 * @mixin Model
 */
trait HasInvitationSecret
{
    /** The column holding the secret's digest. */
    protected function invitationSecretColumn(): string
    {
        return 'token_hash';
    }

    /** How that column stores the digest. */
    protected function invitationSecretDigest(): InvitationDigest
    {
        return InvitationDigest::Hex;
    }

    /**
     * Give this invitation a new secret, replacing any earlier one, and return it. The plaintext
     * is available only from the returned value: put it in the link and let it go. The model is
     * not saved.
     */
    public function issueInvitationSecret(): InvitationSecret
    {
        $secret = InvitationSecret::generate();
        $this->forceFill([$this->invitationSecretColumn() => $secret->digest($this->invitationSecretDigest())]);

        return $secret;
    }

    /**
     * Narrow a query to the invitation a presented secret belongs to. An empty or oversized
     * value matches nothing.
     *
     * @param  Builder<static>  $query
     * @return Builder<static>
     */
    public function scopeWhereInvitationSecret(Builder $query, #[\SensitiveParameter] string $presented): Builder
    {
        if (! InvitationSecret::plausible($presented)) {
            return $query->whereRaw('1 = 0');
        }

        return $query->where(
            $query->qualifyColumn($this->invitationSecretColumn()),
            InvitationSecret::digestOf($presented, $this->invitationSecretDigest()),
        );
    }
}
