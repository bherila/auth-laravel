<?php

namespace BWH\Auth\OAuth\Login;

use BWH\Auth\OAuth\OAuthIdentity;
use BWH\Auth\OAuth\PendingAccount;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;

/**
 * The local account an identity-provider sign-in reaches.
 *
 * The rules, which no application overrides:
 *
 *  - An account is found by (provider, subject) and nothing else. A matching address is never
 *    a reason to adopt an account: whoever controls an address at the provider would otherwise
 *    take over the local account that happens to share it.
 *  - Before any write sets an address, the row that already holds it is read under lock. If it
 *    is another account, the sign-in is refused rather than letting a unique index decide, or
 *    letting a case-insensitive collation quietly match a different person. An operator who
 *    knows the two are the same person links them with `oauth:bind-subject`.
 *  - A write that loses a race on a unique index adopts the row that won only when that row
 *    already carries the profile this sign-in asserts. Otherwise the two requests disagree
 *    about the account and neither wins silently.
 *  - A placeholder that delegated provisioning committed for this subject after the first read
 *    ({@see PendingAccount}) is resolved once more through the same locked path, so it is
 *    filled in rather than refused.
 *
 * Row locks are taken in one order, the subject's row first and then the address holder's, so
 * two sign-ins cannot deadlock each other.
 */
final class SubjectBoundAccounts
{
    /** SQLSTATE classes a unique violation reports as: MySQL, MariaDB and SQLite; PostgreSQL. */
    private const UNIQUE_VIOLATION = ['23000', '23505'];

    public function resolve(OAuthIdentity $identity, RelyingPartyAccounts $accounts): Model
    {
        return $this->attempt($identity, $accounts, retryPending: true);
    }

    private function attempt(OAuthIdentity $identity, RelyingPartyAccounts $accounts, bool $retryPending): Model
    {
        try {
            return DB::connection($this->connection($accounts))->transaction(
                fn (): Model => $this->resolveLocked($identity, $accounts),
            );
        } catch (QueryException $exception) {
            if (! in_array($exception->errorInfo[0] ?? null, self::UNIQUE_VIOLATION, true)) {
                throw $exception;
            }

            $account = $this->bound($identity, $accounts, lock: false);

            if ($retryPending && $account !== null
                && $account->getAttribute($accounts->emailColumn()) === PendingAccount::email($identity->provider, $identity->subject)) {
                return $this->attempt($identity, $accounts, retryPending: false);
            }

            if ($account !== null && $accounts->assertsSameProfile($account, $identity)) {
                return $account;
            }

            throw AccountConflict::concurrentSignInDisagrees($identity->provider, $account?->getKey());
        }
    }

    private function resolveLocked(OAuthIdentity $identity, RelyingPartyAccounts $accounts): Model
    {
        $account = $this->bound($identity, $accounts, lock: true);

        $attributes = $account === null
            ? $accounts->newAccountAttributes($identity)
            : $accounts->refreshedAttributes($account, $identity);

        // The binding is this class's to write, never the application's.
        unset($attributes[$accounts->providerColumn()], $attributes[$accounts->subjectColumn()]);

        $holder = $this->addressHolder($accounts, $account, $attributes);

        if ($holder !== null) {
            // A concurrent first sign-in for this same identity committed between the subject
            // read and this one. Its row is the canonical one, under the same rule as a lost
            // insert race: adopted only if it already asserts this profile.
            if ($account === null && $this->boundTo($holder, $identity, $accounts)) {
                if ($accounts->assertsSameProfile($holder, $identity)) {
                    return $holder;
                }

                throw AccountConflict::concurrentSignInDisagrees($identity->provider, $holder->getKey());
            }

            throw AccountConflict::emailHeldByAnotherAccount($identity->provider, $account?->getKey(), $holder->getKey());
        }

        if ($account === null) {
            $class = $accounts->model();
            $account = new $class;
            $account->forceFill($attributes + [
                $accounts->providerColumn() => $identity->provider,
                $accounts->subjectColumn() => $identity->subject,
            ])->save();

            return $account;
        }

        $account->forceFill($attributes)->save();

        return $account;
    }

    /**
     * The other account, read under lock, that already holds the address about to be written.
     *
     * @param  array<string, mixed>  $attributes
     */
    private function addressHolder(RelyingPartyAccounts $accounts, ?Model $account, array $attributes): ?Model
    {
        $column = $accounts->emailColumn();
        if (! array_key_exists($column, $attributes) || $attributes[$column] === null) {
            return null;
        }

        // Unchanged addresses need no check: the row already holds it.
        if ($account !== null && $account->getAttribute($column) === $attributes[$column]) {
            return null;
        }

        $holder = $accounts->lockForUpdate($accounts->query()->where($column, $attributes[$column]))->first();

        return $holder !== null && ($account === null || $holder->getKey() !== $account->getKey()) ? $holder : null;
    }

    private function boundTo(Model $account, OAuthIdentity $identity, RelyingPartyAccounts $accounts): bool
    {
        return $account->getAttribute($accounts->providerColumn()) === $identity->provider
            && $account->getAttribute($accounts->subjectColumn()) === $identity->subject;
    }

    private function bound(OAuthIdentity $identity, RelyingPartyAccounts $accounts, bool $lock): ?Model
    {
        $query = $accounts->query()
            ->where($accounts->providerColumn(), $identity->provider)
            ->where($accounts->subjectColumn(), $identity->subject);

        return ($lock ? $accounts->lockForUpdate($query) : $query)->first();
    }

    private function connection(RelyingPartyAccounts $accounts): ?string
    {
        return $accounts->query()->getModel()->getConnectionName();
    }
}
