<?php

namespace BWH\Auth\Tests\Feature;

use BWH\Auth\Invitations\InvitationState;
use BWH\Auth\Tests\Fixtures\Invitations\CustomInvitation;
use BWH\Auth\Tests\Fixtures\Invitations\DefaultInvitation;
use BWH\Auth\Tests\Fixtures\Invitations\PreciseInvitation;
use BWH\Auth\Tests\Fixtures\Invitations\UncastInvitation;
use BWH\Auth\Tests\TestCase;
use Carbon\CarbonImmutable;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Date;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

class InvitationModelTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        Schema::create('default_invitations', function (Blueprint $table): void {
            $table->id();
            $table->string('label')->nullable();
            $table->string('token_hash', 64)->nullable()->unique();
            $table->timestamp('accepted_at')->nullable();
            $table->timestamp('declined_at')->nullable();
            $table->timestamp('revoked_at')->nullable();
            $table->timestamp('expires_at')->nullable();
            $table->timestamps();
        });

        Schema::create('custom_invitations', function (Blueprint $table): void {
            $table->id();
            $table->string('label')->nullable();
            $table->binary('secret_digest')->nullable();
            $table->timestamp('redeemed_at')->nullable();
            $table->timestamp('withdrawn_at')->nullable();
            $table->timestamp('lapses_at');
            $table->timestamps();
        });
    }

    public function test_only_the_hex_digest_is_stored_and_the_secret_finds_its_row(): void
    {
        $invitation = new DefaultInvitation(['label' => 'target']);
        $secret = $invitation->issueInvitationSecret();
        $invitation->save();
        DefaultInvitation::query()->create(['label' => 'other', 'token_hash' => hash('sha256', 'other')]);

        $stored = DB::table('default_invitations')->where('id', $invitation->id)->first();
        $this->assertSame(hash('sha256', $secret->plaintext), $stored->token_hash);
        foreach ((array) $stored as $value) {
            $this->assertNotSame($secret->plaintext, $value);
        }

        $this->assertSame('target', DefaultInvitation::query()->whereInvitationSecret($secret->plaintext)->sole()->label);
    }

    public function test_a_stored_digest_cannot_be_replayed_as_the_secret(): void
    {
        $invitation = new DefaultInvitation;
        $invitation->issueInvitationSecret();
        $invitation->save();

        $this->assertNull(DefaultInvitation::query()->whereInvitationSecret((string) $invitation->token_hash)->first());
    }

    public function test_wrong_empty_and_oversized_secrets_match_nothing(): void
    {
        $invitation = new DefaultInvitation;
        $invitation->issueInvitationSecret();
        $invitation->save();

        foreach (['', 'not-the-secret', str_repeat('a', 513)] as $presented) {
            $this->assertNull(DefaultInvitation::query()->whereInvitationSecret($presented)->first(), "Presented: {$presented}");
        }
    }

    public function test_reissuing_replaces_the_old_secret(): void
    {
        $invitation = new DefaultInvitation;
        $old = $invitation->issueInvitationSecret();
        $invitation->save();

        $new = $invitation->issueInvitationSecret();
        $invitation->save();

        $this->assertNull(DefaultInvitation::query()->whereInvitationSecret($old->plaintext)->first());
        $this->assertTrue($invitation->is(DefaultInvitation::query()->whereInvitationSecret($new->plaintext)->first()));
    }

    public function test_a_binary_digest_in_a_renamed_column_round_trips(): void
    {
        $invitation = new CustomInvitation(['label' => 'binary', 'lapses_at' => now()->addDay()]);
        $secret = $invitation->issueInvitationSecret();
        $invitation->save();

        $this->assertSame(hash('sha256', $secret->plaintext, true), DB::table('custom_invitations')->value('secret_digest'));
        $this->assertSame('binary', CustomInvitation::query()->whereInvitationSecret($secret->plaintext)->sole()->label);
        $this->assertNull(CustomInvitation::query()->whereInvitationSecret(hash('sha256', $secret->plaintext))->first());
    }

    public function test_a_legacy_token_issued_before_adoption_still_resolves(): void
    {
        $legacy = 'Legacy48CharacterRandomTokenIssuedBeforeAdoption';
        CustomInvitation::query()->create(['label' => 'legacy', 'secret_digest' => hash('sha256', $legacy, true), 'lapses_at' => now()->addDay()]);

        $this->assertSame('legacy', CustomInvitation::query()->whereInvitationSecret($legacy)->sole()->label);
    }

    public function test_state_follows_the_timestamps_and_the_application_clock(): void
    {
        Date::setTestNow(CarbonImmutable::parse('2026-11-18 12:00:00'));

        $invitation = DefaultInvitation::query()->create(['expires_at' => now()->addHour()]);
        $this->assertSame(InvitationState::Pending, $invitation->invitationState());
        $this->assertTrue($invitation->isOpenInvitation());
        $this->assertSame(InvitationState::Expired, $invitation->invitationState(now()->addHour()));

        Date::setTestNow(now()->addHour());
        $this->assertSame(InvitationState::Expired, $invitation->invitationState());
        $this->assertFalse($invitation->isOpenInvitation());

        $invitation->forceFill(['declined_at' => now(), 'revoked_at' => now()]);
        $this->assertSame(InvitationState::Revoked, $invitation->invitationState());
        $invitation->forceFill(['accepted_at' => now()]);
        $this->assertSame(InvitationState::Accepted, $invitation->invitationState());

        $this->assertSame(InvitationState::Pending, DefaultInvitation::query()->create()->invitationState(), 'A null expiry never lapses.');
    }

    public function test_the_open_scope_agrees_with_the_state(): void
    {
        Date::setTestNow(CarbonImmutable::parse('2026-11-18 12:00:00'));
        $now = CarbonImmutable::now();

        $rows = [
            'open' => [],
            'open-forever' => ['expires_at' => null],
            'lapses-now' => ['expires_at' => $now],
            'lapsed' => ['expires_at' => $now->subSecond()],
            'accepted' => ['accepted_at' => $now->subDay()],
            'declined' => ['declined_at' => $now->subDay()],
            'revoked' => ['revoked_at' => $now->subDay()],
        ];
        foreach ($rows as $label => $attributes) {
            DefaultInvitation::query()->create(['label' => $label, 'expires_at' => $now->addSecond(), ...$attributes]);
        }

        $open = DefaultInvitation::query()->openInvitations()->orderBy('id')->pluck('label')->all();
        $this->assertSame(['open', 'open-forever'], $open);

        foreach (DefaultInvitation::query()->get() as $invitation) {
            $this->assertSame(in_array($invitation->label, $open, true), $invitation->isOpenInvitation(), (string) $invitation->label);
        }

        $this->assertSame(['open-forever'], DefaultInvitation::query()->openInvitations($now->addSecond())->pluck('label')->all(), 'The scope takes an explicit instant.');
    }

    public function test_renamed_columns_and_a_missing_decline_column_drive_state_and_scope(): void
    {
        Date::setTestNow(CarbonImmutable::parse('2026-11-18 12:00:00'));
        $now = CarbonImmutable::now();

        $open = CustomInvitation::query()->create(['label' => 'open', 'lapses_at' => $now->addDay()]);
        CustomInvitation::query()->create(['label' => 'redeemed', 'lapses_at' => $now->addDay(), 'redeemed_at' => $now]);
        CustomInvitation::query()->create(['label' => 'withdrawn', 'lapses_at' => $now->addDay(), 'withdrawn_at' => $now]);
        CustomInvitation::query()->create(['label' => 'lapsed', 'lapses_at' => $now]);

        $this->assertSame(['open'], CustomInvitation::query()->openInvitations()->pluck('label')->all());
        $this->assertSame(InvitationState::Pending, $open->invitationState());
        $this->assertSame(
            ['redeemed' => InvitationState::Accepted, 'withdrawn' => InvitationState::Revoked, 'lapsed' => InvitationState::Expired],
            CustomInvitation::query()->where('label', '!=', 'open')->orderBy('id')->get()
                ->mapWithKeys(fn (CustomInvitation $invitation): array => [$invitation->label => $invitation->invitationState()])->all(),
        );
    }

    public function test_the_scopes_compose_with_each_other_and_row_locks(): void
    {
        $invitation = new DefaultInvitation(['expires_at' => now()->addDay()]);
        $secret = $invitation->issueInvitationSecret();
        $invitation->save();

        $found = DB::transaction(fn () => DefaultInvitation::query()->whereInvitationSecret($secret->plaintext)->openInvitations()->lockForUpdate()->first());
        $this->assertTrue($invitation->is($found));

        $invitation->forceFill(['revoked_at' => now()])->save();
        $this->assertNull(DefaultInvitation::query()->whereInvitationSecret($secret->plaintext)->openInvitations()->first());
        $this->assertNotNull(DefaultInvitation::query()->whereInvitationSecret($secret->plaintext)->first(), 'Without the open scope the caller can still say why it is closed.');
    }

    public function test_a_digest_stored_as_a_blob_still_resolves(): void
    {
        $presented = 'issued-by-another-writer';
        DB::insert(
            "insert into custom_invitations (label, secret_digest, lapses_at) values ('blob', x'".hash('sha256', $presented)."', ?)",
            [now()->addDay()->format('Y-m-d H:i:s')],
        );
        $this->assertSame('blob', DB::scalar('select typeof(secret_digest) from custom_invitations'), 'The row must hold a real BLOB for this test to mean anything.');

        $this->assertSame('blob', CustomInvitation::query()->whereInvitationSecret($presented)->sole()->label);
        $this->assertNull(CustomInvitation::query()->whereInvitationSecret('a-different-secret')->first());
    }

    public function test_the_open_scope_compares_instants_not_wall_clocks(): void
    {
        Date::setTestNow(CarbonImmutable::parse('2026-11-18 10:00:00', 'UTC'));
        DefaultInvitation::query()->create(['label' => 'noon', 'expires_at' => CarbonImmutable::parse('2026-11-18 12:00:00', 'UTC')]);
        $invitation = DefaultInvitation::query()->sole();

        foreach ([
            '2026-11-18 11:00:00-01:00' => false,
            '2026-11-18 13:00:00+01:00' => false,
            '2026-11-18 10:59:59-01:00' => true,
            '2026-11-18 07:59:59-04:00' => true,
            '2026-11-18 21:00:00+09:00' => false,
        ] as $instant => $open) {
            $at = CarbonImmutable::parse($instant);
            $this->assertSame($open, $invitation->isOpenInvitation($at), "State at {$instant}");
            $this->assertSame($open, DefaultInvitation::query()->openInvitations($at)->exists(), "Scope at {$instant}");
        }
    }

    public function test_the_open_scope_keeps_fractional_seconds_a_model_stores(): void
    {
        Date::setTestNow(CarbonImmutable::parse('2026-11-18 10:00:00', 'UTC'));
        PreciseInvitation::query()->create(['label' => 'precise', 'expires_at' => CarbonImmutable::parse('2026-11-18 12:00:00.500000', 'UTC')]);
        $invitation = PreciseInvitation::query()->sole();
        $this->assertSame('500000', $invitation->expires_at->format('u'), 'The fixture must round-trip microseconds.');

        foreach ([
            '2026-11-18 12:00:00.499999' => true,
            '2026-11-18 12:00:00.500000' => false,
            '2026-11-18 12:00:00.500001' => false,
        ] as $instant => $open) {
            $at = CarbonImmutable::parse($instant, 'UTC');
            $this->assertSame($open, $invitation->isOpenInvitation($at), "State at {$instant}");
            $this->assertSame($open, PreciseInvitation::query()->openInvitations($at)->exists(), "Scope at {$instant}");
        }
    }

    public function test_an_uncast_timestamp_is_refused_rather_than_misread(): void
    {
        DB::table('default_invitations')->insert(['accepted_at' => '2026-11-18 12:00:00']);

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('must be cast to a datetime');

        UncastInvitation::query()->sole()->invitationState();
    }

    protected function tearDown(): void
    {
        Date::setTestNow();

        parent::tearDown();
    }
}
