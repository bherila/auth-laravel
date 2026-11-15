<?php

namespace BWH\Auth\Models;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Str;

class TwoFactorAttempt extends Model
{
    private ?string $plainLinkSecret = null;

    protected $fillable = [
        'user_id',
        'token',
        'code',
        'is_used',
        'is_suspicious',
        'ip_address',
        'user_agent',
        'expires_at',
        'link_secret_hash',
    ];

    protected $hidden = [
        'link_secret_hash',
    ];

    protected $casts = [
        'is_used' => 'boolean',
        'is_suspicious' => 'boolean',
        'expires_at' => 'datetime',
    ];

    public function getTable(): string
    {
        return config('bherila-auth.two_factor.table', 'auth_two_factor_attempts');
    }

    public function user(): BelongsTo
    {
        return $this->belongsTo(config('bherila-auth.users.model'), 'user_id');
    }

    public function isExpired(): bool
    {
        return $this->expires_at->isPast();
    }

    public function isValid(): bool
    {
        return ! $this->is_used && ! $this->is_suspicious && ! $this->isExpired();
    }

    /**
     * Whether the secret matches the one this attempt's emailed links carry.
     *
     * The token alone never does: it is returned to the browser that passed the password
     * step, so it proves nothing about the mailbox. An attempt without a stored secret
     * (created before the column existed, or without it) matches nothing.
     */
    public function matchesLinkSecret(mixed $secret): bool
    {
        $hash = $this->getAttribute('link_secret_hash');

        return is_string($hash) && $hash !== ''
            && is_string($secret) && $secret !== ''
            && hash_equals($hash, self::hashLinkSecret($secret));
    }

    /**
     * The emailed links' secret, only on the instance createForUser() returned and only when
     * it could be stored. Never persisted in the clear, and never part of toArray()/JSON.
     */
    public function linkSecret(): ?string
    {
        return $this->plainLinkSecret;
    }

    public static function hashLinkSecret(#[\SensitiveParameter] string $secret): string
    {
        return hash('sha256', $secret);
    }

    public static function createForUser(Authenticatable $user, ?string $ipAddress = null, ?string $userAgent = null): self
    {
        $attributes = [
            'user_id' => $user->getAuthIdentifier(),
            'token' => Str::random(64),
            'code' => str_pad((string) random_int(0, 999999), 6, '0', STR_PAD_LEFT),
            'is_used' => false,
            'is_suspicious' => false,
            'ip_address' => $ipAddress,
            'user_agent' => $userAgent,
            'expires_at' => now()->addMinutes((int) config('bherila-auth.two_factor.expires_minutes', 15)),
        ];

        // Distinct from the token, which the browser gets: only the email carries this.
        // Without the column (2026_11_15_000000 not yet run) the challenge still works by
        // code, and its email has no links.
        $secret = null;
        if ((new self)->hasLinkSecretColumn()) {
            $secret = Str::random(64);
            $attributes['link_secret_hash'] = self::hashLinkSecret($secret);
        }

        $attempt = self::create($attributes);
        $attempt->plainLinkSecret = $secret;

        return $attempt;
    }

    private function hasLinkSecretColumn(): bool
    {
        return $this->getConnection()->getSchemaBuilder()->hasColumn($this->getTable(), 'link_secret_hash');
    }
}
