<?php

namespace BWH\Auth\Database;

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

/**
 * The provider binding columns on an application's account table, for its own migrations.
 *
 * The package never alters an application's tables itself; each application calls this from a
 * migration it owns (`php artisan vendor:publish --tag=bherila-auth-oauth-identity-migration`).
 *
 * Subjects are exact byte strings: `Alice` and `alice` are different identities, and a trailing
 * space is part of one. On MySQL and MariaDB a `utf8mb4_*_ci` column would make the lookup and
 * the unique index treat case variants as one identity, so both columns become VARBINARY.
 * Not `utf8mb4_bin`: that collation still pads, so `a` and `a ` would still collide. Other
 * databases already compare these columns exactly and are left alone.
 *
 * Every step is safe against the previous release: the columns stay nullable and keep their
 * names and the values they hold; only how they compare changes. So a code rollback needs no
 * schema rollback.
 */
final class OAuthIdentityColumns
{
    /** Bytes, matching the provider column's 64-character limit at four bytes each. */
    public const PROVIDER_BYTES = 256;

    public const SUBJECT_BYTES = 191;

    public const UNIQUE_INDEX = 'users_oauth_identity_unique';

    /** Add both nullable columns and their composite unique index to a table being defined. */
    public static function add(Blueprint $table, ?string $after = 'email'): void
    {
        [$provider, $subject] = self::columns();

        $providerColumn = $table->string($provider, 64)->nullable();
        $subjectColumn = $table->string($subject, self::SUBJECT_BYTES)->nullable();
        if ($after !== null) {
            $providerColumn->after($after);
            $subjectColumn->after($provider);
        }

        $table->unique([$provider, $subject], self::UNIQUE_INDEX);
    }

    /**
     * Converge an existing table: add the columns if they are missing, add their composite
     * unique index if it is missing, then make them compare exactly. Idempotent, so it is safe in an application that already has the columns.
     */
    public static function ensure(string $table = 'users', ?string $connection = null, ?string $after = 'email'): void
    {
        [$provider, $subject] = self::columns();
        $schema = Schema::connection($connection);

        $hasProvider = $schema->hasColumn($table, $provider);
        $hasSubject = $schema->hasColumn($table, $subject);
        if ($hasProvider !== $hasSubject) {
            throw new \RuntimeException("Only one of {$table}.{$provider} and {$table}.{$subject} exists; fix the table by hand before converging it.");
        }

        if (! $hasProvider) {
            $schema->table($table, fn (Blueprint $blueprint) => self::add($blueprint, $after));
        }

        // Exact comparison first: under a case-insensitive collation the index below would
        // refuse distinct subjects such as `Alice` and `alice`.
        self::makeCaseSensitive($table, $connection);

        if (! self::hasUniqueIndex($table, $connection)) {
            // The unique index is the final guard against two accounts holding one binding
            // (two concurrent binds on a database without gap locks). Creating it fails, and
            // so refuses the migration, if byte-identical bindings already exist.
            $schema->table($table, fn (Blueprint $blueprint) => $blueprint->unique([$provider, $subject], self::UNIQUE_INDEX));
        }
    }

    /** On MySQL or MariaDB, store both columns as VARBINARY; elsewhere nothing to do. */
    public static function makeCaseSensitive(string $table = 'users', ?string $connection = null): void
    {
        $db = DB::connection($connection);
        if (! in_array($db->getDriverName(), ['mysql', 'mariadb'], true)) {
            return;
        }

        [$provider, $subject] = self::columns();
        $types = self::types($table, $connection);
        if (($types[$provider] ?? null) === 'varbinary' && ($types[$subject] ?? null) === 'varbinary') {
            return;
        }

        // A value longer than the new width would be truncated, or refused, mid-ALTER.
        $longest = $db->table($table)
            ->selectRaw("MAX(LENGTH({$db->getQueryGrammar()->wrap($provider)})) AS provider_bytes, MAX(LENGTH({$db->getQueryGrammar()->wrap($subject)})) AS subject_bytes")
            ->first();
        if ((int) ($longest->provider_bytes ?? 0) > self::PROVIDER_BYTES || (int) ($longest->subject_bytes ?? 0) > self::SUBJECT_BYTES) {
            throw new \RuntimeException("{$table} holds a provider or subject longer than the binding columns allow; nothing was changed.");
        }

        $grammar = $db->getQueryGrammar();
        $db->statement(sprintf(
            'ALTER TABLE %s MODIFY %s VARBINARY(%d) NULL, MODIFY %s VARBINARY(%d) NULL',
            $grammar->wrapTable($table),
            $grammar->wrap($provider),
            self::PROVIDER_BYTES,
            $grammar->wrap($subject),
            self::SUBJECT_BYTES,
        ));
    }

    /**
     * Undo {@see makeCaseSensitive()} for a migration's `down()`. Fails, changing nothing, if
     * two bindings differ only by case: the unique index would no longer hold.
     */
    public static function revertCaseSensitivity(string $table = 'users', ?string $connection = null): void
    {
        $db = DB::connection($connection);
        if (! in_array($db->getDriverName(), ['mysql', 'mariadb'], true)) {
            return;
        }

        [$provider, $subject] = self::columns();
        $grammar = $db->getQueryGrammar();
        $db->statement(sprintf(
            'ALTER TABLE %s MODIFY %s VARCHAR(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NULL, MODIFY %s VARCHAR(%d) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NULL',
            $grammar->wrapTable($table),
            $grammar->wrap($provider),
            $grammar->wrap($subject),
            self::SUBJECT_BYTES,
        ));
    }

    /** @return array{string, string} */
    private static function columns(): array
    {
        return [
            (string) config('bherila-auth.provider_identity.binding.provider_column', 'oauth_provider'),
            (string) config('bherila-auth.provider_identity.binding.subject_column', 'oauth_subject'),
        ];
    }

    /** Whether a unique index covers exactly (provider, subject), in either order or name. */
    private static function hasUniqueIndex(string $table, ?string $connection): bool
    {
        [$provider, $subject] = self::columns();

        foreach (Schema::connection($connection)->getIndexes($table) as $index) {
            $columns = $index['columns'] ?? [];
            sort($columns);
            $wanted = [$provider, $subject];
            sort($wanted);
            if (($index['unique'] ?? false) && $columns === $wanted) {
                return true;
            }
        }

        return false;
    }

    /** @return array<string, string> lower-cased type names by column */
    private static function types(string $table, ?string $connection): array
    {
        $types = [];
        foreach (Schema::connection($connection)->getColumns($table) as $column) {
            $types[$column['name']] = strtolower((string) ($column['type_name'] ?? ''));
        }

        return $types;
    }
}
