<?php

namespace BWH\Auth\Services;

use BWH\Auth\Models\PasskeyCredential;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Algorithm\Signature\RSA\RS256;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use RuntimeException;
use Symfony\Component\Serializer\SerializerInterface;
use Symfony\Component\Uid\Uuid;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\CredentialRecord;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\TrustPath\EmptyTrustPath;

class WebAuthnService
{
    private const SESSION_REGISTER_OPTIONS = 'bherila_auth_webauthn_register_options';

    private const SESSION_LOGIN_OPTIONS = 'bherila_auth_webauthn_login_options';

    public function generateRegistrationOptions(Authenticatable $user, Request $request): array
    {
        $rpId = $this->getRpId($request);
        $rpEntity = PublicKeyCredentialRpEntity::create(
            config('bherila-auth.passkeys.rp_name', config('app.name', 'App')),
            $rpId,
        );
        $userEntity = PublicKeyCredentialUserEntity::create(
            $this->userAttribute($user, config('bherila-auth.users.email_attribute', 'email')),
            (string) $user->getAuthIdentifier(),
            $this->userAttribute($user, config('bherila-auth.users.name_attribute', 'name')),
        );

        $excludeCredentials = PasskeyCredential::query()
            ->where('user_id', $user->getAuthIdentifier())
            ->get()
            ->map(fn (PasskeyCredential $credential) => PublicKeyCredentialDescriptor::create(
                'public-key',
                $this->decodeCredentialId($credential->credential_id),
            ))
            ->toArray();

        $options = PublicKeyCredentialCreationOptions::create(
            rp: $rpEntity,
            user: $userEntity,
            challenge: random_bytes(32),
            pubKeyCredParams: [
                PublicKeyCredentialParameters::create('public-key', ES256::ID),
                PublicKeyCredentialParameters::create('public-key', RS256::ID),
            ],
            authenticatorSelection: AuthenticatorSelectionCriteria::create(
                userVerification: $this->userVerificationRequirement(),
                residentKey: $this->residentKeyRequirement(),
            ),
            attestation: 'none',
            excludeCredentials: $excludeCredentials,
            timeout: (int) config('bherila-auth.passkeys.timeout', 60000),
        );

        $request->session()->put(self::SESSION_REGISTER_OPTIONS, $this->encodeOptions($options));

        return $this->creationOptionsToArray($options);
    }

    public function verifyRegistrationResponse(Authenticatable $user, Request $request, array $credentialData, string $name): PasskeyCredential
    {
        $serializedOptions = $request->session()->pull(self::SESSION_REGISTER_OPTIONS);
        if (! $serializedOptions) {
            throw new RuntimeException('No pending registration options found.');
        }

        $options = $this->decodeOptions($serializedOptions);
        $credential = $this->deserializeCredential($credentialData);

        /** @var AuthenticatorAttestationResponse $response */
        $response = $credential->response;
        $source = $this->createAttestationValidator($request)->check(
            $response,
            $options,
            $this->getRpId($request),
        );

        $backupEligible = (new PasskeyCredential)->hasBackupEligibleColumn()
            ? ['backup_eligible' => $source->backupEligible]
            : [];

        return PasskeyCredential::query()->create($backupEligible + [
            'user_id' => $user->getAuthIdentifier(),
            'credential_id' => $this->encodeCredentialId($source->publicKeyCredentialId),
            'public_key' => base64_encode($source->credentialPublicKey),
            'counter' => $source->counter,
            'aaguid' => $source->aaguid->toRfc4122(),
            'name' => $name ?: 'Passkey',
            'transports' => $source->transports,
            'rp_id' => $this->getRpId($request),
        ]);
    }

    public function generateAuthenticationOptions(?Authenticatable $user, Request $request): array
    {
        $allowCredentials = [];
        if ($user) {
            $allowCredentials = PasskeyCredential::query()
                ->where('user_id', $user->getAuthIdentifier())
                ->get()
                ->map(fn (PasskeyCredential $credential) => PublicKeyCredentialDescriptor::create(
                    'public-key',
                    $this->decodeCredentialId($credential->credential_id),
                ))
                ->toArray();
        }

        $options = PublicKeyCredentialRequestOptions::create(
            challenge: random_bytes(32),
            rpId: $this->getRpId($request),
            allowCredentials: $allowCredentials,
            userVerification: $this->userVerificationRequirement(),
            timeout: (int) config('bherila-auth.passkeys.timeout', 60000),
        );

        $request->session()->put(self::SESSION_LOGIN_OPTIONS, $this->encodeOptions($options));

        return $this->requestOptionsToArray($options);
    }

    /**
     * @return array{0: Authenticatable, 1: PasskeyCredential}
     */
    public function verifyAuthenticationResponse(Request $request, array $credentialData): array
    {
        $serializedOptions = $request->session()->pull(self::SESSION_LOGIN_OPTIONS);
        if (! $serializedOptions) {
            throw new RuntimeException('No pending authentication options found.');
        }

        $options = $this->decodeOptions($serializedOptions);
        $credential = $this->deserializeCredential($credentialData);
        $storedCredential = $this->findStoredCredential($this->encodeCredentialId($credential->rawId));

        if (! $storedCredential) {
            throw new RuntimeException('Credential not found.');
        }

        $user = $storedCredential->user;
        if (! $user instanceof Authenticatable) {
            throw new RuntimeException('Credential user not found.');
        }

        /** @var AuthenticatorAssertionResponse $response */
        $response = $credential->response;
        $updatedSource = $this->createAssertionValidator($request)->check(
            $this->credentialToSource($storedCredential, $user),
            $response,
            $options,
            $this->getRpId($request),
            (string) $user->getAuthIdentifier(),
        );

        $this->reconcileBackupEligibility($storedCredential, $response->authenticatorData->isBackupEligible());

        $storedCredential->update([
            'counter' => $updatedSource->counter,
            'last_used_at' => now(),
        ]);

        return [$user, $storedCredential, $response->authenticatorData->isUserVerified()];
    }

    /**
     * The flag is fixed for a credential, so a change means this isn't the authenticator that
     * enrolled. A credential enrolled before the flag was recorded takes it from this
     * assertion. Call only after the assertion's signature has been verified.
     */
    public function reconcileBackupEligibility(PasskeyCredential $credential, bool $eligible): void
    {
        if (! $credential->hasBackupEligibleColumn()) {
            return;
        }

        if ($credential->backup_eligible === null) {
            $credential->backup_eligible = $eligible;

            return;
        }

        if ($credential->backup_eligible !== $eligible) {
            throw new RuntimeException('The passkey backup-eligible flag changed.');
        }
    }

    private function findStoredCredential(string $encodedCredentialId): ?PasskeyCredential
    {
        $credential = null;
        $probe = new PasskeyCredential();

        if ($probe->hasCredentialIdHashColumn()) {
            $credential = PasskeyCredential::query()
                ->where('credential_id_hash', PasskeyCredential::hashCredentialId($encodedCredentialId))
                ->first();
        }

        if (! $credential) {
            $credential = PasskeyCredential::query()
                ->where('credential_id', $encodedCredentialId)
                ->first();

            if (
                $credential
                && $credential->hasCredentialIdHashColumn()
                && ! $credential->credential_id_hash
            ) {
                $credential->credential_id_hash = PasskeyCredential::hashCredentialId($encodedCredentialId);
                $credential->save();
            }
        }

        return $credential;
    }

    /**
     * Encode pending ceremony options for storage in the session.
     *
     * The options carry a raw 32-byte random challenge, so their serialized form is
     * binary and is not valid UTF-8. Sessions are stored as JSON, and json_encode()
     * returns false on invalid UTF-8 — which does not fail loudly: the whole session
     * is written as the encoding of `false`, discarding every other key it held,
     * including the CSRF token and the authenticated user. The next request then
     * reports that no ceremony is pending, naming the wrong culprit entirely.
     *
     * Base64 keeps the value inside the character set JSON can carry.
     */
    private function encodeOptions(object $options): string
    {
        return base64_encode(serialize($options));
    }

    private function decodeOptions(string $stored): mixed
    {
        // Values written before this was encoded are raw serialized data. In practice
        // storing one destroyed the session, so none survive to be read — but decoding
        // defensively costs nothing and keeps a rolling deploy from erroring.
        $decoded = base64_decode($stored, true);

        return unserialize($decoded === false ? $stored : $decoded);
    }

    private function deserializeCredential(array $credentialData): PublicKeyCredential
    {
        return $this->createSerializer()->deserialize(
            json_encode($credentialData, JSON_THROW_ON_ERROR),
            PublicKeyCredential::class,
            'json',
        );
    }

    /**
     * The relying-party ID that credentials are bound to.
     *
     * A credential can only ever be used against the RP ID it was registered with, or a
     * host for which that RP ID is a registrable-domain suffix. Deriving it from the
     * request host therefore binds every credential to whichever hostname happened to
     * serve the registration page, so a later move to a sibling subdomain silently
     * invalidates every existing passkey with no way to detect it beforehand.
     *
     * Configuring the registrable domain instead (`bherila.net`) binds credentials once,
     * for every current and future subdomain. The configured value is only honoured when
     * it is actually usable for the requesting host — equal to it, or a suffix of it —
     * because a value the browser would reject produces credentials that can never
     * authenticate. Anything else falls back to the host and warns, so local development
     * on `localhost` keeps working against a production-shaped configuration.
     */
    private function getRpId(Request $request): string
    {
        $host = $request->getHost();
        $configured = config('bherila-auth.passkeys.rp_id');

        if (! is_string($configured) || $configured === '') {
            return $host;
        }

        if ($host === $configured || str_ends_with($host, '.'.$configured)) {
            return $configured;
        }

        Log::warning('Configured WebAuthn relying-party ID is not usable for this host; falling back to the request host.', [
            'configured_rp_id' => $configured,
            'request_host' => $host,
        ]);

        return $host;
    }

    private function createSerializer(): SerializerInterface
    {
        $attestationManager = new AttestationStatementSupportManager([
            new NoneAttestationStatementSupport(),
        ]);

        return (new WebauthnSerializerFactory($attestationManager))->create();
    }

    private function createAttestationValidator(Request $request): AuthenticatorAttestationResponseValidator
    {
        return AuthenticatorAttestationResponseValidator::create($this->ceremonyFactory($request)->creationCeremony());
    }

    private function createAssertionValidator(Request $request): AuthenticatorAssertionResponseValidator
    {
        return AuthenticatorAssertionResponseValidator::create($this->ceremonyFactory($request)->requestCeremony());
    }

    private function ceremonyFactory(Request $request): CeremonyStepManagerFactory
    {
        $factory = new CeremonyStepManagerFactory();
        $origins = array_values(array_unique(array_filter([
            $request->getSchemeAndHttpHost(),
            config('app.url'),
            ...config('bherila-auth.passkeys.allowed_origins', []),
        ])));

        $factory->setAllowedOrigins($origins);

        return $factory;
    }

    private function credentialToSource(PasskeyCredential $credential, Authenticatable $user): CredentialRecord
    {
        return CredentialRecord::create(
            publicKeyCredentialId: $this->decodeCredentialId($credential->credential_id),
            type: 'public-key',
            transports: $credential->transports ?? [],
            attestationType: 'none',
            trustPath: new EmptyTrustPath(),
            aaguid: $credential->aaguid
                ? Uuid::fromString($credential->aaguid)
                : Uuid::fromString('00000000-0000-0000-0000-000000000000'),
            credentialPublicKey: base64_decode($credential->public_key),
            userHandle: (string) $user->getAuthIdentifier(),
            counter: $credential->counter,
        );
    }

    private function creationOptionsToArray(PublicKeyCredentialCreationOptions $options): array
    {
        return [
            'challenge' => $this->encodeCredentialId($options->challenge),
            'rp' => [
                'name' => $options->rp->name,
                'id' => $options->rp->id,
            ],
            'user' => [
                'id' => $this->encodeCredentialId($options->user->id),
                'name' => $options->user->name,
                'displayName' => $options->user->displayName,
            ],
            'pubKeyCredParams' => array_map(fn ($parameter) => [
                'type' => $parameter->type,
                'alg' => $parameter->alg,
            ], $options->pubKeyCredParams),
            'timeout' => $options->timeout,
            'excludeCredentials' => array_map(fn ($credential) => [
                'type' => $credential->type,
                'id' => $this->encodeCredentialId($credential->id),
            ], $options->excludeCredentials),
            'authenticatorSelection' => [
                'residentKey' => $this->residentKeyRequirement(),
                'requireResidentKey' => $this->residentKeyRequirement() === AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_REQUIRED,
                'userVerification' => $this->userVerificationRequirement(),
            ],
            'attestation' => 'none',
        ];
    }

    private function requestOptionsToArray(PublicKeyCredentialRequestOptions $options): array
    {
        return [
            'challenge' => $this->encodeCredentialId($options->challenge),
            'rpId' => $options->rpId,
            'allowCredentials' => array_map(fn ($credential) => [
                'type' => $credential->type,
                'id' => $this->encodeCredentialId($credential->id),
            ], $options->allowCredentials),
            'userVerification' => $options->userVerification ?? 'preferred',
            'timeout' => $options->timeout,
        ];
    }

    private function encodeCredentialId(string $rawId): string
    {
        return rtrim(strtr(base64_encode($rawId), '+/', '-_'), '=');
    }

    private function decodeCredentialId(string $credentialId): string
    {
        return base64_decode(strtr($credentialId, '-_', '+/'));
    }

    private function userAttribute(Authenticatable $user, string $attribute): string
    {
        if ($user instanceof Model) {
            return (string) ($user->getAttribute($attribute) ?: $user->getAuthIdentifier());
        }

        return (string) ($user->{$attribute} ?? $user->getAuthIdentifier());
    }

    private function userVerificationRequirement(): string
    {
        $value = config('bherila-auth.passkeys.user_verification', AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_PREFERRED);

        return in_array($value, AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENTS, true)
            ? $value
            : AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_PREFERRED;
    }

    private function residentKeyRequirement(): ?string
    {
        $value = config('bherila-auth.passkeys.resident_key', AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_PREFERRED);

        return in_array($value, AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENTS, true)
            ? $value
            : AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_PREFERRED;
    }
}
