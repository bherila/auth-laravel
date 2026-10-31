<?php

namespace BWH\Auth\OAuth\Login;

use BWH\Auth\OAuth\OAuthIdentity;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;

/**
 * How one application keeps the local accounts its identity-provider sign-ins resolve to.
 *
 * The rules that decide *which* account a sign-in reaches live in {@see SubjectBoundAccounts}
 * and are not overridable: resolve on (provider, subject), never adopt an account because its
 * address matches, refuse rather than guess when two accounts would collide. What this class
 * decides is everything that differs between applications: which model, which columns, what a
 * new account starts with, what a returning sign-in refreshes, and how a row must look before
 * a concurrent sign-in may adopt it.
 *
 * The defaults suit a stock Laravel `users` table with `name`, `email`, `email_verified_at`
 * and `password`, on the model named by `bherila-auth.users.model`. An application that
 * differs extends this class and names it as `bherila-auth.oauth_login.accounts`.
 */
class RelyingPartyAccounts
{
    /** The application's account rules: `bherila-auth.oauth_login.accounts`, or these defaults. */
    public static function configured(): self
    {
        $class = config('bherila-auth.oauth_login.accounts') ?? self::class;
        $accounts = app($class);
        if (! $accounts instanceof self) {
            throw new \LogicException('bherila-auth.oauth_login.accounts must extend '.self::class.'.');
        }

        return $accounts;
    }

    /** @return class-string<Model> */
    public function model(): string
    {
        $model = config('bherila-auth.users.model') ?? config('auth.providers.users.model');
        if (! is_string($model) || ! is_subclass_of($model, Model::class)) {
            throw new \LogicException('bherila-auth.users.model must name an Eloquent model for OAuth sign-in.');
        }

        return $model;
    }

    /** @return Builder<Model> */
    public function query(): Builder
    {
        $model = $this->model();

        return $model::query();
    }

    /**
     * Lock the rows `$query` reads until the surrounding transaction ends.
     *
     * Override to route locks through an application's lock-ordering helper; the order of
     * acquisition is fixed by {@see SubjectBoundAccounts}: the subject's row first, then the
     * owner of the address about to be written.
     *
     * @param  Builder<Model>  $query
     * @return Builder<Model>
     */
    public function lockForUpdate(Builder $query): Builder
    {
        return $query->lockForUpdate();
    }

    public function providerColumn(): string
    {
        return (string) config('bherila-auth.provider_identity.binding.provider_column', 'oauth_provider');
    }

    public function subjectColumn(): string
    {
        return (string) config('bherila-auth.provider_identity.binding.subject_column', 'oauth_subject');
    }

    public function nameColumn(): string
    {
        return (string) config('bherila-auth.users.name_attribute', 'name');
    }

    /** The unique address column, checked under lock before any write sets it. */
    public function emailColumn(): string
    {
        return (string) config('bherila-auth.users.email_attribute', 'email');
    }

    /**
     * Whether a sign-in for a subject with no local account creates one.
     *
     * Return false for an application whose accounts are made only by an operator, or by
     * delegated provisioning: an unknown subject is then refused ({@see AccountNotProvisioned})
     * and an existing account is linked with `oauth:bind-subject`.
     */
    public function provisionsNewAccounts(): bool
    {
        return true;
    }

    /**
     * Attributes for an account created at its first sign-in, apart from the binding,
     * which is always added and cannot be overridden here.
     *
     * The password is random and never used: sign-in resolves on the subject. A random hash
     * rather than an empty one keeps a local password guard from ever matching this row.
     *
     * @return array<string, mixed>
     */
    public function newAccountAttributes(OAuthIdentity $identity): array
    {
        return [
            $this->nameColumn() => $identity->name,
            $this->emailColumn() => $identity->email,
            'email_verified_at' => now(),
            'password' => Hash::make(Str::random(64)),
        ];
    }

    /**
     * Attributes a returning sign-in refreshes from the provider's current profile.
     *
     * Return without the address column to keep an address the application owns (one the
     * person confirmed locally, for example); the collision check then has nothing to check.
     *
     * @return array<string, mixed>
     */
    public function refreshedAttributes(Model $account, OAuthIdentity $identity): array
    {
        return [
            $this->nameColumn() => $identity->name,
            $this->emailColumn() => $identity->email,
            'email_verified_at' => now(),
        ];
    }

    /**
     * Whether a row another request committed for this subject already carries the profile
     * this sign-in asserts, so adopting it cannot hide a disagreement about the account.
     *
     * Called only after this request's own write lost a race on a unique index.
     */
    public function assertsSameProfile(Model $account, OAuthIdentity $identity): bool
    {
        return $account->getAttribute($this->nameColumn()) === $identity->name
            && strcasecmp((string) $account->getAttribute($this->emailColumn()), $identity->email) === 0;
    }
}
