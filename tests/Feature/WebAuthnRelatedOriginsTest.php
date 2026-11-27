<?php

namespace BWH\Auth\Tests\Feature;

use BWH\Auth\Models\PasskeyCredential;
use BWH\Auth\Tests\Fixtures\User;
use BWH\Auth\Tests\TestCase;
use OpenSSLAsymmetricKey;
use PHPUnit\Framework\Attributes\DataProvider;

class WebAuthnRelatedOriginsTest extends TestCase
{
    private const ORIGIN = 'https://id.example.test';

    private const LEGACY_RP = 'app.example.test';

    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);
        $app['config']->set('app.url', self::ORIGIN);
        $app['config']->set('session.driver', 'array');
        $app['config']->set('bherila-auth.passkeys.rp_id', 'example.test');
        $app['config']->set('bherila-auth.passkeys.related_origins', [self::LEGACY_RP => [self::ORIGIN]]);
    }

    /** @return array{user: User, credential: PasskeyCredential, key: OpenSSLAsymmetricKey} */
    private function passkey(?string $rp = self::LEGACY_RP): array
    {
        $user = User::create(['name' => 'Synthetic Person', 'email' => 'person@example.test', 'password' => bcrypt('unused-password')]);
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        $this->assertInstanceOf(OpenSSLAsymmetricKey::class, $key);
        $details = openssl_pkey_get_details($key);
        $this->assertIsArray($details);
        $publicKey = "\xa5\x01\x02\x03\x26\x20\x01\x21\x58\x20"
            .str_pad($details['ec']['x'], 32, "\0", STR_PAD_LEFT)."\x22\x58\x20"
            .str_pad($details['ec']['y'], 32, "\0", STR_PAD_LEFT);
        $credential = PasskeyCredential::create([
            'user_id' => $user->id, 'credential_id' => $this->base64Url(random_bytes(32)),
            'public_key' => base64_encode($publicKey), 'counter' => 0, 'rp_id' => $rp, 'name' => 'Synthetic device',
        ]);

        return compact('user', 'credential', 'key');
    }

    /** @param array{user: User, credential: PasskeyCredential, key: OpenSSLAsymmetricKey} $passkey */
    private function assertion(array $passkey, string $challenge, string $rp = self::LEGACY_RP, string $origin = self::ORIGIN): array
    {
        $clientData = json_encode(['type' => 'webauthn.get', 'challenge' => $challenge, 'origin' => $origin], JSON_THROW_ON_ERROR);
        $authenticatorData = hash('sha256', $rp, true)."\x05".pack('N', 1);
        $this->assertTrue(openssl_sign($authenticatorData.hash('sha256', $clientData, true), $signature, $passkey['key'], OPENSSL_ALGO_SHA256));

        return [
            'id' => $passkey['credential']->credential_id, 'rawId' => $passkey['credential']->credential_id, 'type' => 'public-key',
            'response' => [
                'clientDataJSON' => $this->base64Url($clientData), 'authenticatorData' => $this->base64Url($authenticatorData),
                'signature' => $this->base64Url($signature), 'userHandle' => $this->base64Url((string) $passkey['user']->id),
            ],
        ];
    }

    public function test_an_explicit_related_rp_accepts_a_real_assertion_without_relabeling_the_key(): void
    {
        $passkey = $this->passkey();
        $options = $this->postJson(self::ORIGIN.'/api/passkeys/auth/options', ['rp_id' => self::LEGACY_RP])
            ->assertOk()->assertJsonPath('rpId', self::LEGACY_RP);
        $this->postJson(self::ORIGIN.'/api/passkeys/auth', [
            'credential' => $this->assertion($passkey, $options->json('challenge')),
        ])->assertOk();
        $this->assertAuthenticatedAs($passkey['user']);
        $this->assertSame(self::LEGACY_RP, $passkey['credential']->fresh()->rp_id);
        $this->assertSame(1, $passkey['credential']->fresh()->counter);
    }

    public function test_related_origins_are_disabled_without_an_explicit_operator_mapping(): void
    {
        config(['bherila-auth.passkeys.related_origins' => []]);
        $this->postJson(self::ORIGIN.'/api/passkeys/auth/options', ['rp_id' => self::LEGACY_RP])->assertUnprocessable();
        $this->postJson(self::ORIGIN.'/api/passkeys/auth/options')->assertOk()->assertJsonPath('rpId', 'example.test');
    }

    public function test_a_mapping_for_another_origin_does_not_authorize_this_origin(): void
    {
        config(['bherila-auth.passkeys.related_origins' => [self::LEGACY_RP => ['https://other.example.test']]]);
        $this->postJson(self::ORIGIN.'/api/passkeys/auth/options', ['rp_id' => self::LEGACY_RP])->assertUnprocessable();
    }

    #[DataProvider('invalidRelyingParties')]
    public function test_request_data_cannot_select_an_arbitrary_or_malformed_rp(mixed $rp): void
    {
        $this->postJson(self::ORIGIN.'/api/passkeys/auth/options', ['rp_id' => $rp])->assertUnprocessable();
    }

    public static function invalidRelyingParties(): array
    {
        return [['attacker.example.test'], ['https://app.example.test'], ['*.example.test'], [['app.example.test']], [123]];
    }

    public function test_related_origin_authorization_is_exact_and_requires_https(): void
    {
        foreach (['http://id.example.test', 'https://sub.id.example.test', 'https://id.example.test:8443'] as $origin) {
            $this->postJson($origin.'/api/passkeys/auth/options', ['rp_id' => self::LEGACY_RP])->assertUnprocessable();
        }
    }

    public function test_registration_keeps_the_configured_rp_even_when_a_related_rp_is_requested(): void
    {
        config(['bherila-auth.passkeys.require_password_confirmation' => false]);
        $passkey = $this->passkey();
        $this->actingAs($passkey['user'])->postJson(self::ORIGIN.'/api/passkeys/register/options', ['rp_id' => self::LEGACY_RP])
            ->assertOk()->assertJsonPath('rp.id', 'example.test');
    }

    public function test_a_request_cannot_switch_the_rp_after_the_challenge_was_issued(): void
    {
        $passkey = $this->passkey();
        $options = $this->postJson(self::ORIGIN.'/api/passkeys/auth/options')->assertOk();
        $this->postJson(self::ORIGIN.'/api/passkeys/auth', [
            'rp_id' => self::LEGACY_RP, 'credential' => $this->assertion($passkey, $options->json('challenge')),
        ])->assertUnprocessable();
        $this->assertGuest();
        $this->assertSame(0, $passkey['credential']->fresh()->counter);
    }

    public function test_a_revoked_mapping_invalidates_an_outstanding_challenge(): void
    {
        $passkey = $this->passkey();
        $options = $this->postJson(self::ORIGIN.'/api/passkeys/auth/options', ['rp_id' => self::LEGACY_RP])->assertOk();
        config(['bherila-auth.passkeys.related_origins' => []]);
        $this->postJson(self::ORIGIN.'/api/passkeys/auth', [
            'credential' => $this->assertion($passkey, $options->json('challenge')),
        ])->assertUnprocessable();
        $this->assertSame(0, $passkey['credential']->fresh()->counter);
    }

    public function test_an_assertion_from_another_globally_allowed_origin_is_rejected(): void
    {
        $passkey = $this->passkey();
        config(['bherila-auth.passkeys.allowed_origins' => ['https://other.example.test']]);
        $options = $this->postJson(self::ORIGIN.'/api/passkeys/auth/options', ['rp_id' => self::LEGACY_RP])->assertOk();
        $this->postJson(self::ORIGIN.'/api/passkeys/auth', [
            'credential' => $this->assertion($passkey, $options->json('challenge'), origin: 'https://other.example.test'),
        ])->assertUnprocessable();
        $this->assertSame(0, $passkey['credential']->fresh()->counter);
    }

    public function test_a_null_historical_rp_is_recorded_only_after_valid_cryptographic_proof(): void
    {
        $passkey = $this->passkey(null);
        $options = $this->postJson(self::ORIGIN.'/api/passkeys/auth/options', ['rp_id' => self::LEGACY_RP])->assertOk();
        $invalid = $this->assertion($passkey, $options->json('challenge'));
        $invalid['response']['signature'] = $this->base64Url(random_bytes(64));
        $this->postJson(self::ORIGIN.'/api/passkeys/auth', ['credential' => $invalid])->assertUnprocessable();
        $this->assertNull($passkey['credential']->fresh()->rp_id);
        $this->assertSame(0, $passkey['credential']->fresh()->counter);
        $options = $this->postJson(self::ORIGIN.'/api/passkeys/auth/options', ['rp_id' => self::LEGACY_RP])->assertOk();
        $this->postJson(self::ORIGIN.'/api/passkeys/auth', [
            'credential' => $this->assertion($passkey, $options->json('challenge')),
        ])->assertOk();
        $this->assertSame(self::LEGACY_RP, $passkey['credential']->fresh()->rp_id);
    }

    public function test_a_recorded_rp_cannot_be_replaced_even_with_the_same_public_key(): void
    {
        $passkey = $this->passkey('example.test');
        $options = $this->postJson(self::ORIGIN.'/api/passkeys/auth/options', ['rp_id' => self::LEGACY_RP])->assertOk();
        $this->postJson(self::ORIGIN.'/api/passkeys/auth', [
            'credential' => $this->assertion($passkey, $options->json('challenge')),
        ])->assertUnprocessable();
        $this->assertSame('example.test', $passkey['credential']->fresh()->rp_id);
        $this->assertSame(0, $passkey['credential']->fresh()->counter);
    }

    public function test_related_rps_also_work_for_account_bound_confirmation(): void
    {
        $passkey = $this->passkey();
        $this->actingAs($passkey['user']);
        $options = $this->postJson(self::ORIGIN.'/api/passkeys/confirm/options', ['rp_id' => self::LEGACY_RP])
            ->assertOk()->assertJsonPath('rpId', self::LEGACY_RP)->assertJsonPath('userVerification', 'required');
        $this->postJson(self::ORIGIN.'/api/passkeys/confirm', [
            'credential' => $this->assertion($passkey, $options->json('challenge')),
        ])->assertOk();
        $this->postJson(self::ORIGIN.'/api/passkeys/register/options')->assertOk()->assertJsonPath('rp.id', 'example.test');
    }

    private function base64Url(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }
}
