<?php

namespace BWH\Auth\Console;

use BWH\Auth\OAuth\Login\RelyingPartyAccounts;
use BWH\Auth\OAuth\OAuthClient;
use Illuminate\Console\Command;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Symfony\Component\HttpKernel\Exception\HttpExceptionInterface;

/**
 * Link an existing local account to its identity-provider subject.
 *
 * For accounts that predate the provider, or were copied from it, and so hold an address but
 * no subject. Sign-in resolves only on the subject, so such a row is unreachable: the first
 * sign-in finds no account, and is refused because the address already belongs to one.
 *
 * The link cannot be inferred at sign-in. Adopting an unbound row because its address matches
 * is the takeover the subject binding exists to prevent. It is an operator action, taken once
 * per account after confirming out of band that the two are the same person.
 *
 * The guards make it safe to run and to re-run: it never re-points an account that is already
 * bound, never gives one subject to a second account, and decides and writes under one row
 * lock, so the worst a mistyped id can do is be refused.
 */
class BindOAuthSubjectCommand extends Command
{
    /** SQLSTATE classes a unique violation reports as: MySQL, MariaDB and SQLite; PostgreSQL. */
    private const UNIQUE_VIOLATION = ['23000', '23505'];

    protected $signature = 'oauth:bind-subject
        {user : The local account id to link}
        {subject : The provider subject (the `sub` value) for that account}
        {--provider= : Provider name; defaults to the configured identity provider}';

    protected $description = 'Link an existing local account to its identity-provider subject.';

    public function handle(OAuthClient $oauth): int
    {
        $accounts = RelyingPartyAccounts::configured();
        $provider = $this->resolveProvider($oauth);

        if (
            $provider === null
            || $provider !== trim($provider)
            || Str::length($provider) > 64
            || strlen($provider) > 256
        ) {
            $this->components->error('The provider must have no surrounding whitespace and contain at most 64 characters.');

            return self::FAILURE;
        }

        // Subjects are exact, case-sensitive strings. Never trimmed: a trailing space is part
        // of the identifier, and a case-sensitive column preserves it.
        $subject = (string) $this->argument('subject');

        if ($subject === '' || strlen($subject) > 191) {
            $this->components->error('The subject must be a non-empty value of at most 191 characters.');

            return self::FAILURE;
        }

        $userId = (string) $this->argument('user');

        // MySQL coerces a string to a number when comparing it with an integer key, so
        // `find('12oops')` matches #12. Binding is close to irreversible (the no-re-point
        // guard below then stops this command correcting it), so a typo is refused rather
        // than rounded to a real account.
        $model = $accounts->query()->getModel();
        if (in_array($model->getKeyType(), ['int', 'integer'], true) && preg_match('/^[1-9][0-9]*$/', $userId) !== 1) {
            $this->components->error('The account must be given by its positive integer id.');

            return self::FAILURE;
        }

        $providerColumn = $accounts->providerColumn();
        $subjectColumn = $accounts->subjectColumn();

        try {
            $result = DB::connection($model->getConnectionName())->transaction(function () use ($accounts, $userId, $provider, $subject, $providerColumn, $subjectColumn): array {
                // The decision and the write belong under one row lock. Checking first and
                // opening the transaction afterwards would let a concurrent bind re-point the
                // account between the two.
                $account = $accounts->lockForUpdate($accounts->query()->whereKey($userId))->first();

                if (! $account instanceof Model) {
                    return $this->result(self::FAILURE, 'error', sprintf('There is no account #%s to link.', $userId));
                }

                if ($account->getAttribute($subjectColumn) !== null || $account->getAttribute($providerColumn) !== null) {
                    if ($account->getAttribute($providerColumn) === $provider && $account->getAttribute($subjectColumn) === $subject) {
                        return $this->result(self::SUCCESS, 'info', sprintf('Account #%s is already linked to that subject.', $account->getKey()));
                    }

                    return $this->result(self::FAILURE, 'error', sprintf(
                        'Account #%s is already linked to a different identity. Refusing to re-point it.',
                        $account->getKey(),
                    ));
                }

                $claimant = $accounts->lockForUpdate($accounts->query()
                    ->where($providerColumn, $provider)
                    ->where($subjectColumn, $subject))
                    ->first();

                if ($claimant instanceof Model) {
                    return $this->result(self::FAILURE, 'error', sprintf(
                        'That subject is already linked to account #%s. Refusing to link it twice.',
                        $claimant->getKey(),
                    ));
                }

                $account->forceFill([
                    $providerColumn => $provider,
                    $subjectColumn => $subject,
                ])->save();

                return $this->result(self::SUCCESS, 'info', sprintf('Linked account #%s to the %s identity.', $account->getKey(), $provider));
            });
        } catch (QueryException $exception) {
            // A second account can still race for the same unclaimed subject on a database
            // without gap locks. The unique index is the final guard; report its refusal.
            if (! in_array($exception->errorInfo[0] ?? null, self::UNIQUE_VIOLATION, true)) {
                throw $exception;
            }

            $claimant = $accounts->query()
                ->where($providerColumn, $provider)
                ->where($subjectColumn, $subject)
                ->first();

            $result = $this->result(self::FAILURE, 'error', $claimant === null
                ? 'The identity changed while it was being linked. Nothing was re-pointed; retry after checking the account.'
                : sprintf('That subject is already linked to account #%s. Refusing to link it twice.', $claimant->getKey()));
        }

        $result['kind'] === 'info'
            ? $this->components->info($result['message'])
            : $this->components->error($result['message']);

        return $result['exit'];
    }

    private function resolveProvider(OAuthClient $oauth): ?string
    {
        $option = $this->option('provider');

        if (is_string($option) && $option !== '') {
            return $option;
        }

        try {
            return $oauth->providerName();
        } catch (HttpExceptionInterface) {
            return null;
        }
    }

    /**
     * @return array{exit: int, kind: 'error'|'info', message: string}
     */
    private function result(int $exit, string $kind, string $message): array
    {
        return ['exit' => $exit, 'kind' => $kind, 'message' => $message];
    }
}
