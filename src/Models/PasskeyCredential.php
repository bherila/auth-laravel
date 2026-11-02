<?php

namespace BWH\Auth\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class PasskeyCredential extends Model
{
    private static array $credentialIdHashColumnCache = [];

    /** @var array<string, bool> */
    private static array $backupEligibleColumnCache = [];

    protected $fillable = [
        'user_id',
        'credential_id',
        'credential_id_hash',
        'public_key',
        'counter',
        'aaguid',
        'name',
        'transports',
        'last_used_at',
        'rp_id',
        'backup_eligible',
    ];

    protected $casts = [
        'counter' => 'integer',
        'transports' => 'array',
        'last_used_at' => 'datetime',
        'backup_eligible' => 'boolean',
    ];

    protected static function booted(): void
    {
        static::saving(function (PasskeyCredential $credential): void {
            if (
                ! is_string($credential->credential_id)
                || $credential->credential_id === ''
                || ! $credential->hasCredentialIdHashColumn()
            ) {
                return;
            }

            if ($credential->isDirty('credential_id') || ! $credential->credential_id_hash) {
                $credential->credential_id_hash = self::hashCredentialId($credential->credential_id);
            }
        });
    }

    public function getTable(): string
    {
        return config('bherila-auth.passkeys.table', 'auth_passkeys');
    }

    public static function hashCredentialId(string $credentialId): string
    {
        return hash('sha256', $credentialId);
    }

    public function hasCredentialIdHashColumn(): bool
    {
        $connection = $this->getConnection();
        $key = $connection->getName().'.'.$this->getTable();

        if (! array_key_exists($key, self::$credentialIdHashColumnCache)) {
            self::$credentialIdHashColumnCache[$key] = $connection
                ->getSchemaBuilder()
                ->hasColumn($this->getTable(), 'credential_id_hash');
        }

        return self::$credentialIdHashColumnCache[$key];
    }

    public function hasBackupEligibleColumn(): bool
    {
        $connection = $this->getConnection();
        $key = $connection->getName().'.'.$this->getTable();

        return self::$backupEligibleColumnCache[$key] ??= $connection
            ->getSchemaBuilder()
            ->hasColumn($this->getTable(), 'backup_eligible');
    }

    public function user(): BelongsTo
    {
        return $this->belongsTo(config('bherila-auth.users.model'), 'user_id');
    }
}
