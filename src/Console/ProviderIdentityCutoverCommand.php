<?php

namespace BWH\Auth\Console;

use BWH\Auth\OAuth\Session\ProviderIdentityEnforcement;
use Illuminate\Console\Command;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Log;

/**
 * Record, inspect, check or withdraw this installation's provider identity cutover.
 *
 * Recording it makes provider lifecycle enforcement a committed state of the installation:
 * from then on enforcement stays on even if `bherila-auth.provider_identity.enabled` is false.
 * Withdrawing it is the one way back, and is meant for leaving the identity provider on
 * purpose, never for an outage: an unavailable provider already answers a retryable 503.
 */
class ProviderIdentityCutoverCommand extends Command
{
    protected $signature = 'bherila-auth:provider-identity-cutover
        {action=status : status, record, check or withdraw}
        {--force : Withdraw without the interactive confirmation}';

    protected $description = 'Record, inspect, check or withdraw the provider identity cutover, which keeps enforcement on.';

    public function handle(ProviderIdentityEnforcement $enforcement): int
    {
        $action = (string) $this->argument('action');

        return match ($action) {
            'status' => $this->status($enforcement),
            'record' => $this->record($enforcement),
            'check' => $this->check($enforcement),
            'withdraw' => $this->withdraw($enforcement),
            default => $this->unknown($action),
        };
    }

    private function status(ProviderIdentityEnforcement $enforcement): int
    {
        $record = $enforcement->record();
        $this->line('Configured: '.($enforcement->configured() ? 'on' : 'off'));
        if ($record === null) {
            $this->line('Cutover: not recorded');
        } elseif ($record->withdrawn_at !== null) {
            $this->line("Cutover: withdrawn at {$record->withdrawn_at} (recorded at {$record->recorded_at} for {$record->provider})");
        } else {
            $this->line("Cutover: recorded at {$record->recorded_at} for {$record->provider}");
        }
        $enforcement->forget();
        $this->line('Enforcement: '.($enforcement->enabled() ? 'on' : 'off'));

        return self::SUCCESS;
    }

    private function record(ProviderIdentityEnforcement $enforcement): int
    {
        if (! $enforcement->tableExists()) {
            $this->components->error('Run the package migrations first: the cutover table does not exist.');

            return self::FAILURE;
        }
        // Lock in only a configuration already proven to work: enforcement must be on, and the
        // client the status checks authenticate with must be configured.
        if (! $enforcement->configured()) {
            $this->components->error('Turn enforcement on (BHERILA_AUTH_PROVIDER_IDENTITY_ENABLED=true) and confirm it works before recording the cutover.');

            return self::FAILURE;
        }
        $missing = $this->missingClientSettings();
        if ($missing !== []) {
            $this->components->error('The identity provider client is not configured: '.implode(', ', $missing).'.');

            return self::FAILURE;
        }

        $provider = (string) config('bherila-auth.oauth_client.provider');
        $connection = $enforcement->connection();
        $existing = $enforcement->record();
        if ($existing !== null && $existing->withdrawn_at === null) {
            $this->components->info("The cutover is already recorded (at {$existing->recorded_at} for {$existing->provider}).");

            return self::SUCCESS;
        }

        $now = Carbon::now();
        $connection->table(ProviderIdentityEnforcement::TABLE)->upsert(
            [['id' => 1, 'provider' => $provider, 'recorded_at' => $now, 'withdrawn_at' => null, 'created_at' => $now, 'updated_at' => $now]],
            ['id'],
            ['provider', 'recorded_at', 'withdrawn_at', 'updated_at'],
        );
        $enforcement->forget();
        Log::notice('Provider identity cutover recorded; enforcement now stays on whatever the configuration says.', ['provider' => $provider]);
        $this->components->info("Cutover recorded for {$provider}. Provider lifecycle enforcement now stays on, even if the setting is turned off.");

        return self::SUCCESS;
    }

    /**
     * For deploy pipelines: fails when a recorded cutover disagrees with the configuration, so
     * a deploy that would rely on the lock alone (setting off, or the client unconfigured) is
     * stopped and fixed instead of running every protected request into a 503.
     */
    private function check(ProviderIdentityEnforcement $enforcement): int
    {
        if (! $enforcement->cutOver()) {
            $this->components->info('No cutover is recorded; enforcement follows the configuration.');

            return self::SUCCESS;
        }
        $problems = $this->missingClientSettings();
        if (! $enforcement->configured()) {
            array_unshift($problems, 'bherila-auth.provider_identity.enabled is off');
        }
        if ($problems !== []) {
            $this->components->error('The cutover is recorded, so enforcement stays on, but the configuration disagrees: '.implode('; ', $problems).'.');

            return self::FAILURE;
        }
        $this->components->info('The cutover is recorded and the configuration agrees.');

        return self::SUCCESS;
    }

    private function withdraw(ProviderIdentityEnforcement $enforcement): int
    {
        $record = $enforcement->record();
        if ($record === null || $record->withdrawn_at !== null) {
            $this->components->info('No cutover is recorded; nothing to withdraw.');

            return self::SUCCESS;
        }
        $this->components->warn('Withdrawing the cutover lets the configuration turn provider lifecycle enforcement off again. '
            .'Accounts the provider has disabled, deleted or reset could then keep their sessions and tokens here.');
        if (! $this->option('force') && ! $this->confirm('Withdraw the provider identity cutover?')) {
            $this->components->info('Nothing changed.');

            return self::FAILURE;
        }

        $now = Carbon::now();
        $enforcement->connection()->table(ProviderIdentityEnforcement::TABLE)
            ->where('id', 1)
            ->update(['withdrawn_at' => $now, 'updated_at' => $now]);
        $enforcement->forget();
        Log::warning('Provider identity cutover withdrawn; enforcement follows the configuration again.', ['provider' => $record->provider]);
        $this->components->info('Cutover withdrawn. Enforcement follows bherila-auth.provider_identity.enabled again.');

        return self::SUCCESS;
    }

    private function unknown(string $action): int
    {
        $this->components->error("Unknown action [{$action}]. Use status, record, check or withdraw.");

        return self::FAILURE;
    }

    /** @return list<string> */
    private function missingClientSettings(): array
    {
        $missing = [];
        foreach (['provider', 'base_url', 'client_id', 'client_secret'] as $key) {
            $value = config('bherila-auth.oauth_client.'.$key);
            if (! is_string($value) || trim($value) === '') {
                $missing[] = 'bherila-auth.oauth_client.'.$key;
            }
        }

        return $missing;
    }
}
