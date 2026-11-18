<?php

namespace BWH\Auth\Invitations;

use DateTimeInterface;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Date;

/**
 * An Eloquent invitation whose {@see InvitationState} is derived from its timestamp columns.
 *
 * By default those are `accepted_at`, `declined_at`, `revoked_at` and `expires_at`, each cast
 * to a datetime. Override {@see self::invitationLifecycleColumns()} to rename one, or map it to
 * null when the table has no such column: an invitation that cannot be declined maps `declined`
 * to null. A null expiry, in the column or in the map, never lapses.
 *
 * {@see self::invitationState()} and the `openInvitations` scope apply the same rule, so a row
 * the scope returns always reports {@see InvitationState::Pending} at the same instant.
 *
 * @mixin Model
 */
trait HasInvitationLifecycle
{
    /**
     * The timestamp column behind each transition, or null when the table has none.
     *
     * @return array{accepted: ?string, declined: ?string, revoked: ?string, expires: ?string}
     */
    protected function invitationLifecycleColumns(): array
    {
        return [
            'accepted' => 'accepted_at',
            'declined' => 'declined_at',
            'revoked' => 'revoked_at',
            'expires' => 'expires_at',
        ];
    }

    /** Where this invitation stands at `$now` (default: the application clock). */
    public function invitationState(?DateTimeInterface $now = null): InvitationState
    {
        $columns = $this->invitationLifecycleColumns();

        return InvitationState::of(
            $this->invitationLifecycleMoment($columns['accepted']),
            $this->invitationLifecycleMoment($columns['declined']),
            $this->invitationLifecycleMoment($columns['revoked']),
            $this->invitationLifecycleMoment($columns['expires']),
            $now ?? Date::now(),
        );
    }

    /** Whether this invitation can still be accepted, declined or revoked at `$now`. */
    public function isOpenInvitation(?DateTimeInterface $now = null): bool
    {
        return $this->invitationState($now)->isOpen();
    }

    /**
     * Narrow a query to invitations that are pending at `$now` (default: the application clock).
     *
     * @param  Builder<static>  $query
     * @return Builder<static>
     */
    public function scopeOpenInvitations(Builder $query, ?DateTimeInterface $now = null): Builder
    {
        $columns = $this->invitationLifecycleColumns();

        foreach ([$columns['accepted'], $columns['declined'], $columns['revoked']] as $column) {
            if ($column !== null) {
                $query->whereNull($query->qualifyColumn($column));
            }
        }

        if ($columns['expires'] !== null) {
            $expires = $query->qualifyColumn($columns['expires']);
            $at = $now ?? Date::now();
            $query->where(fn (Builder $open): Builder => $open->whereNull($expires)->orWhere($expires, '>', $at));
        }

        return $query;
    }

    private function invitationLifecycleMoment(?string $column): ?DateTimeInterface
    {
        if ($column === null) {
            return null;
        }

        $value = $this->getAttribute($column);
        if ($value === null || $value instanceof DateTimeInterface) {
            return $value;
        }

        throw new \LogicException(static::class.'::$'.$column.' must be cast to a datetime to derive its invitation state.');
    }
}
