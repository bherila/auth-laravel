<?php

namespace BWH\Auth\Tests\Feature;

use BWH\Auth\Models\PasskeyCredential;
use BWH\Auth\Tests\Fixtures\User;
use BWH\Auth\Tests\TestCase;
use Illuminate\Support\Facades\Route;
use OpenSSLAsymmetricKey;
use PHPUnit\Framework\Attributes\DataProvider;

class PasskeyRememberTest extends TestCase
{
    private const ORIGIN = 'https://id.example.test';

    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);
        $app['config']->set('app.url', self::ORIGIN);
        $app['config']->set('session.driver', 'array');
    }

    protected function defineRoutes($router): void
    {
        Route::middleware('web')->get('/session-user', fn () => response()->json([
            'id' => auth()->id(), 'remembered' => auth()->viaRemember(),
        ]));
    }

    /** @return array<string, array{array<string, bool>, bool}> */
    public static function rememberChoices(): array
    {
        return ['omitted' => [[], false], 'unchecked' => [['remember' => false], false], 'checked' => [['remember' => true], true]];
    }

    #[DataProvider('rememberChoices')]
    public function test_a_real_passkey_assertion_remembers_only_the_requested_login(array $choice, bool $remembered): void
    {
        $user = User::create(['name' => 'Synthetic Person', 'email' => 'person@example.test', 'password' => bcrypt('synthetic-password'), 'remember_token' => null]);
        $privateKey = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        $this->assertInstanceOf(OpenSSLAsymmetricKey::class, $privateKey);
        $details = openssl_pkey_get_details($privateKey);
        $this->assertIsArray($details);
        // COSE EC2 / ES256 / P-256: {1:2, 3:-7, -1:1, -2:x, -3:y}.
        $publicKey = "\xa5\x01\x02\x03\x26\x20\x01\x21\x58\x20".$details['ec']['x']."\x22\x58\x20".$details['ec']['y'];
        $credentialId = $this->base64Url(random_bytes(32));
        $key = PasskeyCredential::create([
            'user_id' => $user->id, 'credential_id' => $credentialId, 'public_key' => base64_encode($publicKey),
            'counter' => 0, 'rp_id' => 'id.example.test', 'name' => 'Synthetic device',
        ]);
        $options = $this->withCredentials()->postJson(self::ORIGIN.'/api/passkeys/auth/options')->assertOk();
        $clientData = json_encode([
            'type' => 'webauthn.get', 'challenge' => $options->json('challenge'), 'origin' => self::ORIGIN,
        ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        $authenticatorData = hash('sha256', 'id.example.test', true)."\x05".pack('N', 1);
        $this->assertTrue(openssl_sign($authenticatorData.hash('sha256', $clientData, true), $signature, $privateKey, OPENSSL_ALGO_SHA256));
        $response = $this->postJson(self::ORIGIN.'/api/passkeys/auth', $choice + ['credential' => [
            'id' => $credentialId, 'rawId' => $credentialId, 'type' => 'public-key',
            'response' => [
                'clientDataJSON' => $this->base64Url($clientData), 'authenticatorData' => $this->base64Url($authenticatorData),
                'signature' => $this->base64Url($signature), 'userHandle' => $this->base64Url((string) $user->id),
            ],
        ]])->assertOk()->assertJsonPath('success', true);

        $this->assertAuthenticatedAs($user);
        $this->assertSame(1, $key->fresh()->counter);
        $recallerName = auth()->guard()->getRecallerName();
        $cookie = $response->getCookie($recallerName);
        if (! $remembered) {
            $this->assertNull($cookie);
            $this->assertNull($user->fresh()->remember_token);

            return;
        }

        $this->assertNotNull($cookie);
        $this->assertGreaterThan(time(), $cookie->getExpiresTime());
        $this->assertNotEmpty($user->fresh()->remember_token);
        // Discard the authenticated session entirely. Only the actual recaller
        // cookie should restore the user on the next browser visit.
        $this->app['auth']->forgetGuards();
        $this->app['session']->forgetDrivers();
        $this->app->forgetInstance('session.store');
        $this->defaultCookies = [];
        $this->withCookie($recallerName, (string) $cookie->getValue())->get(self::ORIGIN.'/session-user')
            ->assertOk()->assertJsonPath('id', $user->id)->assertJsonPath('remembered', true);
    }

    public function test_non_boolean_remember_input_is_refused_before_authentication(): void
    {
        $this->postJson(self::ORIGIN.'/api/passkeys/auth', ['credential' => ['id' => 'synthetic'], 'remember' => 'yes'])
            ->assertUnprocessable()->assertJsonValidationErrors('remember');
        $this->assertGuest();
    }

    private function base64Url(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }
}
