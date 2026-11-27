<?php

namespace BWH\Auth\Tests\Feature;

use BWH\Auth\Mail\TwoFactorLoginMail;
use BWH\Auth\Models\TwoFactorAttempt;
use BWH\Auth\Services\TwoFactorService;
use BWH\Auth\Tests\Fixtures\User;
use BWH\Auth\Tests\TestCase;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Schema;

class TwoFactorRecipientTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        Mail::fake();
    }

    public function test_an_attempt_identifies_only_the_address_its_code_was_mailed_to(): void
    {
        $user = $this->person();
        $attempt = $this->issue($user)->fresh();
        $this->assertTrue($attempt->wasMailedTo('original@example.test'));
        $this->assertFalse($attempt->wasMailedTo('changed@example.test'));
        $this->assertArrayNotHasKey('recipient_hash', $attempt->toArray());
        Mail::assertSent(TwoFactorLoginMail::class, fn ($mail) => $mail->hasTo('original@example.test'));
    }

    public function test_recording_the_attempt_and_sending_mail_use_the_same_address_snapshot(): void
    {
        $user = $this->person();
        TwoFactorAttempt::creating(static function () use ($user): void {
            $user->email = 'changed@example.test';
        });
        $attempt = $this->issue($user)->fresh();
        $this->assertTrue($attempt->wasMailedTo('original@example.test'));
        $this->assertFalse($attempt->wasMailedTo($user->email));
        Mail::assertSent(TwoFactorLoginMail::class, fn ($mail) => $mail->hasTo('original@example.test') && ! $mail->hasTo('changed@example.test'));
    }

    public function test_legacy_attempts_and_unmigrated_tables_never_claim_an_address(): void
    {
        $user = $this->person();
        $legacy = TwoFactorAttempt::createForUser($user);
        $this->assertFalse($legacy->wasMailedTo($user->email));
        Schema::table('auth_two_factor_attempts', fn (Blueprint $table) => $table->dropColumn('recipient_hash'));
        $attempt = $this->issue($user);
        $this->assertTrue($attempt->isValid());
        $this->assertFalse($attempt->wasMailedTo($user->email));
        Mail::assertSent(TwoFactorLoginMail::class);
    }

    public function test_the_destination_migration_obeys_the_configured_table_and_can_be_repeated(): void
    {
        Schema::rename('auth_two_factor_attempts', 'synthetic_challenges');
        config(['bherila-auth.two_factor.table' => 'synthetic_challenges']);
        $migration = require __DIR__.'/../../database/migrations/2026_11_27_000000_add_recipient_hash_to_two_factor_attempts.php';
        $migration->down();
        $migration->up();
        $migration->up();
        $this->assertTrue($this->issue($this->person())->fresh()->wasMailedTo('original@example.test'));
    }

    private function person(): User
    {
        return User::create(['name' => 'Synthetic Person', 'email' => 'original@example.test', 'password' => bcrypt('synthetic-password')]);
    }

    private function issue(User $user): TwoFactorAttempt
    {
        $request = Request::create('/synthetic-sign-in');
        $request->setLaravelSession(app('session')->driver());

        return app(TwoFactorService::class)->startChallenge($user, $request);
    }
}
