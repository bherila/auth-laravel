<?php

namespace BWH\Auth\Tests\Feature;

use BWH\Auth\Tests\Fixtures\User;
use BWH\Auth\Tests\TestCase;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\Events\TransactionBeginning;
use Illuminate\Database\Events\TransactionCommitted;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;

/**
 * Linking an account to a provider subject writes the binding every later sign-in trusts, so
 * each guard is asserted rather than left to the operator's care.
 */
final class BindOAuthSubjectCommandTest extends TestCase
{
    private const PROVIDER = 'test-provider';

    protected function defineDatabaseMigrations(): void
    {
        parent::defineDatabaseMigrations();

        Schema::table('users', function (Blueprint $table): void {
            $table->string('oauth_provider', 64)->nullable();
            $table->string('oauth_subject', 191)->nullable();
            $table->unique(['oauth_provider', 'oauth_subject']);
        });
    }

    protected function setUp(): void
    {
        parent::setUp();

        config()->set('bherila-auth.oauth_client.provider', self::PROVIDER);
    }

    private function user(array $attributes = []): User
    {
        static $n = 0;
        $n++;

        return User::create(array_merge([
            'name' => 'Test '.$n,
            'email' => "user{$n}@example.com",
            'password' => bcrypt('secret-password'),
        ], $attributes));
    }

    public function test_it_links_an_unbound_account_and_is_safe_to_re_run(): void
    {
        $user = $this->user();

        $this->artisan('oauth:bind-subject', ['user' => $user->getKey(), 'subject' => '4211'])
            ->expectsOutputToContain('Linked account #'.$user->getKey())
            ->assertSuccessful();

        $user->refresh();
        $this->assertSame(self::PROVIDER, $user->oauth_provider);
        $this->assertSame('4211', $user->oauth_subject);

        $this->artisan('oauth:bind-subject', ['user' => $user->getKey(), 'subject' => '4211'])
            ->expectsOutputToContain('already linked to that subject')
            ->assertSuccessful();
    }

    public function test_it_refuses_to_re_point_an_account_that_is_already_linked(): void
    {
        $user = $this->user();
        $user->forceFill(['oauth_provider' => self::PROVIDER, 'oauth_subject' => '4211'])->save();

        $this->artisan('oauth:bind-subject', ['user' => $user->getKey(), 'subject' => '9999'])
            ->expectsOutputToContain('already linked to a different identity')
            ->assertFailed();

        $this->assertSame('4211', $user->refresh()->oauth_subject);
    }

    public function test_an_account_with_only_the_provider_set_counts_as_bound(): void
    {
        $user = $this->user();
        $user->forceFill(['oauth_provider' => self::PROVIDER, 'oauth_subject' => null])->save();

        $this->artisan('oauth:bind-subject', ['user' => $user->getKey(), 'subject' => '4211'])
            ->expectsOutputToContain('already linked to a different identity')
            ->assertFailed();

        $user->refresh();
        $this->assertSame(self::PROVIDER, $user->oauth_provider);
        $this->assertNull($user->oauth_subject);
    }

    public function test_it_refuses_to_hand_one_subject_to_a_second_account(): void
    {
        $holder = $this->user();
        $holder->forceFill(['oauth_provider' => self::PROVIDER, 'oauth_subject' => '4211'])->save();
        $other = $this->user();

        $this->artisan('oauth:bind-subject', ['user' => $other->getKey(), 'subject' => '4211'])
            ->expectsOutputToContain('already linked to account #'.$holder->getKey())
            ->assertFailed();

        $this->assertNull($other->refresh()->oauth_subject);
        $this->assertSame($holder->getKey(), User::query()->where('oauth_subject', '4211')->sole()->getKey());
    }

    public function test_it_reports_a_missing_account_rather_than_creating_one(): void
    {
        $this->artisan('oauth:bind-subject', ['user' => '999000001', 'subject' => '4211'])
            ->expectsOutputToContain('There is no account #999000001 to link.')
            ->assertFailed();

        $this->assertSame(0, User::query()->count());
    }

    public function test_it_refuses_a_user_argument_that_is_not_a_canonical_id(): void
    {
        $user = $this->user();

        foreach ([$user->getKey().'oops', '12oops', ' '.$user->getKey(), '0'.$user->getKey(), '', '-1', '0'] as $argument) {
            $this->artisan('oauth:bind-subject', ['user' => $argument, 'subject' => '4211'])
                ->expectsOutputToContain('positive integer id')
                ->assertFailed();
        }

        $this->assertNull($user->refresh()->oauth_subject);
    }

    public function test_it_refuses_an_empty_subject_and_one_over_191_bytes(): void
    {
        $user = $this->user();

        $this->artisan('oauth:bind-subject', ['user' => $user->getKey(), 'subject' => ''])
            ->assertFailed();
        $this->artisan('oauth:bind-subject', ['user' => $user->getKey(), 'subject' => str_repeat('s', 192)])
            ->assertFailed();

        $this->assertNull($user->refresh()->oauth_subject);

        $this->artisan('oauth:bind-subject', ['user' => $user->getKey(), 'subject' => str_repeat('s', 191)])
            ->assertSuccessful();
    }

    public function test_it_preserves_the_exact_subject_bytes(): void
    {
        $user = $this->user();

        $this->artisan('oauth:bind-subject', ['user' => $user->getKey(), 'subject' => 'Subject-A '])
            ->assertSuccessful();

        $this->assertSame('Subject-A ', $user->refresh()->oauth_subject);
    }

    public function test_an_explicit_provider_wins_over_the_configured_one(): void
    {
        $user = $this->user();

        $this->artisan('oauth:bind-subject', [
            'user' => $user->getKey(),
            'subject' => '4211',
            '--provider' => 'somewhere-else',
        ])->assertSuccessful();

        $this->assertSame('somewhere-else', $user->refresh()->oauth_provider);
    }

    public function test_it_refuses_when_no_provider_is_configured_or_given(): void
    {
        config()->set('bherila-auth.oauth_client.provider', '');
        $user = $this->user();

        $this->artisan('oauth:bind-subject', ['user' => $user->getKey(), 'subject' => '4211'])
            ->assertFailed();

        $this->assertNull($user->refresh()->oauth_subject);
    }

    public function test_it_refuses_provider_whitespace_and_a_provider_over_64_characters(): void
    {
        $user = $this->user();

        foreach ([' '.self::PROVIDER.' ', str_repeat('p', 65)] as $provider) {
            $this->artisan('oauth:bind-subject', [
                'user' => $user->getKey(),
                'subject' => '4211',
                '--provider' => $provider,
            ])->assertFailed();
        }

        $this->assertNull($user->refresh()->oauth_subject);
        $this->assertNull($user->oauth_provider);
    }

    public function test_it_locks_and_checks_the_target_inside_the_write_transaction(): void
    {
        $user = $this->user();
        $transactionOpen = false;
        $targetReadInsideTransaction = false;

        Event::listen(function (TransactionBeginning $event) use (&$transactionOpen): void {
            $transactionOpen = true;
        });
        Event::listen(function (TransactionCommitted $event) use (&$transactionOpen): void {
            $transactionOpen = false;
        });
        DB::listen(function (QueryExecuted $query) use ($user, &$transactionOpen, &$targetReadInsideTransaction): void {
            if (
                $transactionOpen
                && str_starts_with($query->sql, 'select')
                && str_contains($query->sql, 'from "users"')
                && in_array((string) $user->getKey(), array_map('strval', $query->bindings), true)
            ) {
                $targetReadInsideTransaction = true;
            }
        });

        $this->artisan('oauth:bind-subject', ['user' => $user->getKey(), 'subject' => '4211'])
            ->assertSuccessful();

        $this->assertTrue($targetReadInsideTransaction, 'The target binding guard must run while the write transaction is open.');
        $this->assertFalse($transactionOpen);
    }
}
