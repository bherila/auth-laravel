<?php

namespace BWH\Auth\Console;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Date;
use Laravel\Passport\Passport;

/**
 * Delete stale, unused self-registered (dynamic) OAuth clients.
 *
 * Public dynamic registration is an open door, so registrations that were
 * never used, or not used within the retention window, are removed together
 * with their tokens and codes. A client with any live access or refresh token
 * is kept, and person-registered clients (no registration timestamp) are never
 * touched. Schedule it daily.
 */
class PruneDynamicClientsCommand extends Command
{
    protected $signature = 'bherila-auth:prune-dynamic-clients {--days= : Override the configured retention window} {--pretend : Report without deleting}';

    protected $description = 'Delete stale, unused self-registered OAuth clients and their tokens.';

    public function handle(): int
    {
        $registeredAt = (string) config('bherila-auth.oauth_server.dynamic_clients.registered_at_column', 'dynamically_registered_at');
        // Null disables last-use tracking: candidates are then judged by
        // registration age alone (live credentials still protect a client).
        $lastUsedAt = config('bherila-auth.oauth_server.dynamic_clients.last_used_at_column');
        $lastUsedAt = is_string($lastUsedAt) && $lastUsedAt !== '' ? $lastUsedAt : null;
        $clientModel = Passport::client();
        if (! $clientModel->getConnection()->getSchemaBuilder()->hasColumns($clientModel->getTable(), array_values(array_filter([$registeredAt, $lastUsedAt])))) {
            $this->warn('Dynamic client registration columns are not migrated; nothing was pruned.');

            return self::SUCCESS;
        }

        $days = $this->option('days');
        $days = $days === null
            ? (int) config('bherila-auth.oauth_server.dynamic_clients.retention_days', 30)
            : filter_var($days, FILTER_VALIDATE_INT);
        if (! is_int($days) || $days < 1 || $days > 3650) {
            $this->error('Retention days must be an integer from 1 through 3650.');

            return self::INVALID;
        }
        if ($this->hasUnattributedActiveRefreshCredential()) {
            // A live refresh token whose access-token row is gone cannot be
            // attributed to a client, so no client can be shown unused.
            $this->warn('An active refresh credential has no access-token row; pruning was deferred.');

            return self::SUCCESS;
        }

        $cutoff = Date::now()->subDays($days);
        $candidates = Passport::client()->newQuery()
            ->whereNotNull($registeredAt)
            ->where($registeredAt, '<', $cutoff)
            ->when($lastUsedAt !== null, fn ($query) => $query->where(fn ($query) => $query->whereNull($lastUsedAt)->orWhere($lastUsedAt, '<', $cutoff)))
            // Streamed: registration is public, so the backlog is unbounded.
            ->lazyById(200, $clientModel->getKeyName());

        $pruned = 0;
        foreach ($candidates as $client) {
            if ($this->inUse((string) $client->getKey())) {
                continue;
            }
            if ($this->option('pretend')) {
                $pruned++;

                continue;
            }
            // Re-checked under a lock on the client row, inside the deletion: a
            // flow that started after the first check (a fresh code or token)
            // keeps its client rather than losing it mid-exchange.
            $deleted = $client->getConnection()->transaction(function () use ($client): bool {
                $locked = Passport::client()->newQuery()->whereKey($client->getKey())->lockForUpdate()->first();
                if ($locked === null || $this->inUse((string) $client->getKey())) {
                    return false;
                }
                $tokenIds = Passport::token()->newQuery()->where('client_id', $client->getKey())->pluck('id');
                if ($tokenIds->isNotEmpty()) {
                    Passport::refreshToken()->newQuery()->whereIn('access_token_id', $tokenIds)->delete();
                    Passport::token()->newQuery()->whereIn('id', $tokenIds)->delete();
                }
                Passport::authCode()->newQuery()->where('client_id', $client->getKey())->delete();
                $locked->delete();

                return true;
            });
            $pruned += $deleted ? 1 : 0;
        }

        $this->info(($this->option('pretend') ? 'Would prune ' : 'Pruned ').$pruned.' stale dynamic OAuth client(s).');

        return self::SUCCESS;
    }

    /** A live access or refresh token, or a live authorization code (a flow in progress). */
    private function inUse(string $clientId): bool
    {
        return $this->hasActiveCredential($clientId)
            || Passport::authCode()->newQuery()->where('client_id', $clientId)->where('revoked', false)->where('expires_at', '>', Date::now())->exists();
    }

    private function hasActiveCredential(string $clientId): bool
    {
        $now = Date::now();
        if (Passport::token()->newQuery()->where('client_id', $clientId)->where('revoked', false)->where('expires_at', '>', $now)->exists()) {
            return true;
        }

        return Passport::refreshToken()->newQuery()
            ->where('revoked', false)
            ->where('expires_at', '>', $now)
            ->whereIn('access_token_id', Passport::token()->newQuery()->select('id')->where('client_id', $clientId))
            ->exists();
    }

    private function hasUnattributedActiveRefreshCredential(): bool
    {
        return Passport::refreshToken()->newQuery()
            ->where('revoked', false)
            ->where('expires_at', '>', Date::now())
            ->whereNotIn('access_token_id', Passport::token()->newQuery()->select('id'))
            ->exists();
    }
}
