<?php

namespace BWH\Auth\Tests\Feature;

use BWH\Auth\Http\Middleware\RequirePasswordConfirmation;
use BWH\Auth\Models\PasskeyCredential;
use BWH\Auth\Tests\Fixtures\User;
use BWH\Auth\Tests\TestCase;
use Illuminate\Support\Str;
use Illuminate\Testing\TestResponse;
use OpenSSLAsymmetricKey;

/**
 * A user-verified assertion of the account's own passkey satisfies the confirmation passkey
 * enrollment requires, so an account that only uses passkeys (its local password random or
 * unknown) can add a second one. Real assertions, signed with a throwaway P-256 key.
 */
class PasskeyConfirmationTest extends TestCase
{
    private const ORIGIN = 'https://id.example.test';

    private const PRESENT = "\x01";

    private const PRESENT_AND_VERIFIED = "\x05";

    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);
        $app['config']->set('app.url', self::ORIGIN);
        $app['config']->set('session.driver', 'array');
    }

    private function passkeyOnlyUser(string $email = 'person@example.test'): User
    {
        // Nobody knows this password, so POST /auth/confirm-password can never succeed.
        return User::create(['name' => 'Synthetic Person', 'email' => $email, 'password' => bcrypt(Str::random(40))]);
    }

    /** @return array{credential_id: string, key: OpenSSLAsymmetricKey} */
    private function passkey(User $user): array
    {
        $privateKey = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        $this->assertInstanceOf(OpenSSLAsymmetricKey::class, $privateKey);
        $details = openssl_pkey_get_details($privateKey);
        $this->assertIsArray($details);
        // COSE EC2 / ES256 / P-256: {1:2, 3:-7, -1:1, -2:x, -3:y}.
        // OpenSSL drops leading zero bytes; COSE needs both coordinates at their full 32 bytes.
        $x = str_pad($details['ec']['x'], 32, "\0", STR_PAD_LEFT);
        $y = str_pad($details['ec']['y'], 32, "\0", STR_PAD_LEFT);
        $publicKey = "\xa5\x01\x02\x03\x26\x20\x01\x21\x58\x20".$x."\x22\x58\x20".$y;
        $credentialId = $this->base64Url(random_bytes(32));
        PasskeyCredential::create([
            'user_id' => $user->id, 'credential_id' => $credentialId, 'public_key' => base64_encode($publicKey),
            'counter' => 0, 'rp_id' => 'id.example.test', 'name' => 'Synthetic device',
        ]);

        return ['credential_id' => $credentialId, 'key' => $privateKey];
    }

    /**
     * @param  array{credential_id: string, key: OpenSSLAsymmetricKey}  $passkey
     * @return array<string, mixed>
     */
    private function assertion(array $passkey, User $owner, string $challenge, string $flags, int $counter = 1): array
    {
        $clientData = json_encode([
            'type' => 'webauthn.get', 'challenge' => $challenge, 'origin' => self::ORIGIN,
        ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        $authenticatorData = hash('sha256', 'id.example.test', true).$flags.pack('N', $counter);
        $this->assertTrue(openssl_sign($authenticatorData.hash('sha256', $clientData, true), $signature, $passkey['key'], OPENSSL_ALGO_SHA256));

        return [
            'id' => $passkey['credential_id'], 'rawId' => $passkey['credential_id'], 'type' => 'public-key',
            'response' => [
                'clientDataJSON' => $this->base64Url($clientData), 'authenticatorData' => $this->base64Url($authenticatorData),
                'signature' => $this->base64Url($signature), 'userHandle' => $this->base64Url((string) $owner->id),
            ],
        ];
    }

    /** @param  array{credential_id: string, key: OpenSSLAsymmetricKey}  $passkey */
    private function confirmWith(array $passkey, User $owner, string $flags = self::PRESENT_AND_VERIFIED): TestResponse
    {
        $options = $this->postJson(self::ORIGIN.'/api/passkeys/confirm/options')->assertOk();

        return $this->postJson(self::ORIGIN.'/api/passkeys/confirm', [
            'credential' => $this->assertion($passkey, $owner, $options->json('challenge'), $flags),
        ]);
    }

    private function assertEnrollmentLocked(): void
    {
        $this->postJson(self::ORIGIN.'/api/passkeys/register/options')
            ->assertStatus(423)->assertJsonPath('error', RequirePasswordConfirmation::ERROR);
    }

    public function test_a_passkey_only_account_confirms_with_its_passkey_and_can_enroll_another(): void
    {
        $user = $this->passkeyOnlyUser();
        $passkey = $this->passkey($user);
        $this->actingAs($user);
        $this->assertEnrollmentLocked();

        $options = $this->postJson(self::ORIGIN.'/api/passkeys/confirm/options')->assertOk()
            ->assertJsonPath('userVerification', 'required');
        $this->assertCount(1, $options->json('allowCredentials'));

        $this->postJson(self::ORIGIN.'/api/passkeys/confirm', [
            'credential' => $this->assertion($passkey, $user, $options->json('challenge'), self::PRESENT_AND_VERIFIED),
        ])->assertOk()->assertJsonPath('success', true)->assertJsonPath('expires_in', RequirePasswordConfirmation::timeout());

        $this->postJson(self::ORIGIN.'/api/passkeys/register/options')->assertOk();
        $this->assertAuthenticatedAs($user);
        // It is not a password confirmation: Laravel's password.confirm is not satisfied.
        $this->assertFalse(session()->has('auth.password_confirmed_at'));
    }

    public function test_an_assertion_without_user_verification_does_not_confirm(): void
    {
        $user = $this->passkeyOnlyUser();
        $passkey = $this->passkey($user);
        $this->actingAs($user);

        $this->confirmWith($passkey, $user, self::PRESENT)->assertStatus(422)->assertJsonPath('success', false);

        $this->assertEnrollmentLocked();
    }

    public function test_another_accounts_passkey_does_not_confirm(): void
    {
        $user = $this->passkeyOnlyUser();
        $this->passkey($user);
        $other = $this->passkeyOnlyUser('other@example.test');
        $othersPasskey = $this->passkey($other);
        $this->actingAs($user);

        $this->confirmWith($othersPasskey, $other)->assertStatus(422);

        $this->assertEnrollmentLocked();
        $this->assertAuthenticatedAs($user);
    }

    public function test_sign_in_options_cannot_finish_a_confirmation(): void
    {
        $user = $this->passkeyOnlyUser();
        $passkey = $this->passkey($user);
        $this->actingAs($user);

        $options = $this->postJson(self::ORIGIN.'/api/passkeys/auth/options')->assertOk();
        $this->postJson(self::ORIGIN.'/api/passkeys/confirm', [
            'credential' => $this->assertion($passkey, $user, $options->json('challenge'), self::PRESENT_AND_VERIFIED),
        ])->assertStatus(422);

        $this->assertEnrollmentLocked();
    }

    public function test_a_confirmation_challenge_is_single_use(): void
    {
        $user = $this->passkeyOnlyUser();
        $passkey = $this->passkey($user);
        $this->actingAs($user);
        $options = $this->postJson(self::ORIGIN.'/api/passkeys/confirm/options')->assertOk();
        $credential = $this->assertion($passkey, $user, $options->json('challenge'), self::PRESENT_AND_VERIFIED);

        $this->postJson(self::ORIGIN.'/api/passkeys/confirm', ['credential' => $credential])->assertOk();
        $this->postJson(self::ORIGIN.'/api/passkeys/confirm', ['credential' => $credential])->assertStatus(422);
    }

    public function test_confirming_needs_a_signed_in_account(): void
    {
        $this->postJson(self::ORIGIN.'/api/passkeys/confirm/options')->assertUnauthorized();
        $this->postJson(self::ORIGIN.'/api/passkeys/confirm', ['credential' => ['id' => 'x']])->assertUnauthorized();
    }

    public function test_a_passkey_confirmation_expires_with_the_window_and_belongs_to_its_account(): void
    {
        config(['bherila-auth.password_confirmation.timeout' => 600]);
        $user = $this->passkeyOnlyUser();
        $passkey = $this->passkey($user);
        $this->actingAs($user);
        $this->confirmWith($passkey, $user)->assertOk();

        $this->travel(599)->seconds();
        $this->postJson(self::ORIGIN.'/api/passkeys/register/options')->assertOk();
        $this->travel(2)->seconds();
        $this->assertEnrollmentLocked();

        // A record for another account in the same session satisfies nothing.
        $this->withSession([RequirePasswordConfirmation::PASSKEY_SESSION_KEY => ['account' => (string) ($user->id + 1), 'at' => now()->getTimestamp()]]);
        $this->assertEnrollmentLocked();
    }

    public function test_a_user_verified_passkey_sign_in_counts_as_a_confirmation(): void
    {
        $user = $this->passkeyOnlyUser();
        $passkey = $this->passkey($user);

        $options = $this->postJson(self::ORIGIN.'/api/passkeys/auth/options')->assertOk();
        $this->postJson(self::ORIGIN.'/api/passkeys/auth', [
            'credential' => $this->assertion($passkey, $user, $options->json('challenge'), self::PRESENT_AND_VERIFIED),
        ])->assertOk();

        $this->assertAuthenticatedAs($user);
        $this->postJson(self::ORIGIN.'/api/passkeys/register/options')->assertOk();
    }

    public function test_a_passkey_sign_in_without_user_verification_does_not_count(): void
    {
        $user = $this->passkeyOnlyUser();
        $passkey = $this->passkey($user);

        $options = $this->postJson(self::ORIGIN.'/api/passkeys/auth/options')->assertOk();
        $this->postJson(self::ORIGIN.'/api/passkeys/auth', [
            'credential' => $this->assertion($passkey, $user, $options->json('challenge'), self::PRESENT),
        ])->assertOk();

        $this->assertAuthenticatedAs($user);
        $this->assertEnrollmentLocked();
    }

    private function base64Url(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }
}
