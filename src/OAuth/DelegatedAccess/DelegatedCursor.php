<?php

namespace BWH\Auth\OAuth\DelegatedAccess;

use Illuminate\Contracts\Encryption\Encrypter;
use Throwable;

/**
 * An opaque keyset cursor for `subjects` and `workspaces` pages.
 *
 * It carries the last key shown, never an offset, so a row removed between pages cannot make the
 * next page skip one. It is encrypted and bound to the actor and the operation, so it cannot be
 * forged, replayed by somebody else, or used against another listing. The actor is bound by digest,
 * which keeps every cursor within the contract's 512-byte bound whatever the subject's length.
 */
final readonly class DelegatedCursor
{
    public function __construct(private Encrypter $encrypter) {}

    /**
     * @param  int  $after  The key of the last entry on this page.
     */
    public function encode(string $actorSubject, string $operation, int $after): string
    {
        return $this->encrypter->encryptString((string) json_encode([
            'a' => self::actor($actorSubject),
            'o' => $operation,
            'n' => $after,
        ]));
    }

    /**
     * The key to list after: 0 for the first page, when the payload carries no cursor.
     *
     * @param  array<string, mixed>  $payload
     *
     * @throws DelegatedAccessException `invalid_cursor` (422) for a cursor that is not this actor's for this operation.
     */
    public function after(string $actorSubject, string $operation, array $payload): int
    {
        if (! isset($payload['cursor'])) {
            return 0;
        }

        try {
            $cursor = json_decode($this->encrypter->decryptString((string) $payload['cursor']), true, 8, JSON_THROW_ON_ERROR);
        } catch (Throwable) {
            throw new DelegatedAccessException('invalid_cursor', 422);
        }

        if (! is_array($cursor) || ! hash_equals(self::actor($actorSubject), (string) ($cursor['a'] ?? ''))
            || ($cursor['o'] ?? null) !== $operation || ! is_int($cursor['n'] ?? null) || $cursor['n'] < 0) {
            throw new DelegatedAccessException('invalid_cursor', 422);
        }

        return $cursor['n'];
    }

    private static function actor(string $actorSubject): string
    {
        return rtrim(strtr(base64_encode(hash('sha256', $actorSubject, true)), '+/', '-_'), '=');
    }
}
