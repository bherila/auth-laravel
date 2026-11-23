<?php

namespace BWH\Auth\OAuth\Server;

use BWH\Auth\OAuth\Session\ProviderBindingResolver;
use BWH\Auth\OAuth\Session\ProviderIdentityEnforcement;
use BWH\Auth\OAuth\Session\ProviderIdentityPolicy;
use BWH\Auth\OAuth\Session\ProviderSession;
use BWH\Auth\OAuth\Session\ProviderSessionExpired;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use RuntimeException;

/**
 * Provider identity enforcement for OAuth credentials this application issues:
 * authorization codes, access tokens (agent and personal) and, through their access
 * token, refresh tokens.
 *
 * Each credential issued for a provider-bound account records the provider subject
 * and the credential generation of the browser session that authorized it. A token
 * minted by exchanging a code or a refresh token inherits the stamp of what it was
 * minted from, never a freshly fetched generation, so a reset at the provider can
 * never be adopted by an older grant.
 *
 * With enforcement enabled, a credential of a bound account is refused when its stamp
 * is missing (credentials issued before enforcement are retired, not upgraded), names
 * another subject, or no longer matches the provider's answer, including a recovery epoch the
 * provider has since raised after a restore. An unavailable provider
 * raises ProviderStatusUnavailable, which renders a retryable 503 and leaves a refresh
 * token unconsumed. Unbound accounts and client-credential tokens are left to the
 * application.
 */
final readonly class ProviderIdentityTokens
{
    public const SUBJECT_COLUMN = 'provider_subject';

    public const GENERATION_COLUMN = 'provider_generation';

    /** The provider's recovery epoch at issue; null when it reported none. */
    public const EPOCH_COLUMN = 'provider_epoch';

    /** On refresh tokens, which have no owner column of their own. */
    public const OWNER_COLUMN = 'provider_user_id';

    /**
     * The stamp recorded on a credential issued to an account with no provider binding. It
     * tells such credentials apart from ones issued before stamping existed, which stay
     * refused even if their account is later unbound.
     */
    public const UNBOUND_SUBJECT = '';

    /** The stamp carried from a code or refresh token to the access token minted from it. */
    public const REQUEST_ATTRIBUTE = 'bherila_auth.provider_identity_stamp';

    public function __construct(
        private ProviderSession $session,
        private ProviderBindingResolver $bindings,
        private ProviderIdentityPolicy $policy,
    ) {}

    public static function enabled(): bool
    {
        return app(ProviderIdentityEnforcement::class)->enabled();
    }

    /**
     * The stamp for a credential being issued to this user now.
     *
     * Inherited from the code or refresh token being exchanged when there is one;
     * otherwise taken from the authorizing browser session. With enforcement on, a bound
     * account without a verified session cannot be issued a credential. With it off,
     * the stamp is still recorded when available so enabling enforcement later does not
     * retire credentials issued in the meantime.
     *
     * @return array{subject: string, generation: int, epoch: int|null}|null
     */
    public function stampForIssue(?Request $request, string|int|null $userId): ?array
    {
        if ($userId === null || $userId === '') {
            return null;
        }
        $carried = $request?->attributes->get(self::REQUEST_ATTRIBUTE);
        if (is_array($carried) && is_string($carried['subject'] ?? null) && is_int($carried['generation'] ?? null)) {
            return ['subject' => $carried['subject'], 'generation' => $carried['generation'],
                'epoch' => is_int($carried['epoch'] ?? null) ? $carried['epoch'] : null];
        }

        try {
            return $this->stampFromSession($request, $userId);
        } catch (RuntimeException $exception) {
            if (self::enabled()) {
                throw $exception;
            }

            return null;
        }
    }

    /** Record a credential row's stamp so the token minted from it inherits it. */
    public function carry(?Request $request, Model $credential): void
    {
        $subject = $credential->getAttribute(self::SUBJECT_COLUMN);
        $generation = $credential->getAttribute(self::GENERATION_COLUMN);
        $request?->attributes->remove(self::REQUEST_ATTRIBUTE);
        if (is_string($subject) && is_numeric($generation) && (int) $generation >= 0) {
            $request?->attributes->set(self::REQUEST_ATTRIBUTE, ['subject' => $subject, 'generation' => (int) $generation,
                'epoch' => self::epochOf($credential)]);
        }
    }

    /**
     * The stamp's column values, empty when there is none. The epoch column is written only
     * where the table has it (`withEpoch`), so an application that has not yet run the
     * migration adding it keeps issuing credentials, without an epoch.
     *
     * @return array<string, string|int|null>
     */
    public static function attributes(?array $stamp, bool $withEpoch = false): array
    {
        if ($stamp === null) {
            return [];
        }
        $attributes = [
            self::SUBJECT_COLUMN => $stamp['subject'],
            self::GENERATION_COLUMN => $stamp['generation'],
        ];
        if ($withEpoch) {
            $attributes[self::EPOCH_COLUMN] = $stamp['epoch'] ?? null;
        }

        return $attributes;
    }

    /** The recovery epoch a stored credential was issued under; null when none is recorded. */
    public static function epochOf(Model $credential): ?int
    {
        $epoch = $credential->getAttribute(self::EPOCH_COLUMN);

        return is_numeric($epoch) && (int) $epoch >= 1 ? (int) $epoch : null;
    }

    /**
     * Whether a stored credential row (code or access token) must be refused.
     *
     * Use `fresh: true` for privileged operations and for renewal. `remote: false` checks
     * only the stamp against the account's binding; an authorization code uses it, since it
     * was just approved in a checked session, lives minutes, and every token minted from it
     * is checked on use.
     */
    public function revoked(Model $credential, bool $fresh = false, bool $remote = true): bool
    {
        if (! self::enabled()) {
            return false;
        }
        $userId = $credential->getAttribute('user_id') ?? $credential->getAttribute(self::OWNER_COLUMN);
        if ($userId === null || $userId === '') {
            return false;
        }

        $user = app(\BWH\Auth\OAuth\Credentials\OAuthCredentialOwners::class)->find($userId);
        if ($user === null) {
            return true;
        }
        try {
            $binding = $this->bindings->binding($user);
        } catch (ProviderSessionExpired) {
            return true;
        }
        $subject = $credential->getAttribute(self::SUBJECT_COLUMN);
        if ($binding === null) {
            // Exempt only credentials recorded as issued to an unbound account. One carrying a
            // provider stamp belongs to an identity the account has since lost, and one with
            // no stamp at all predates enforcement and may have been issued while it was bound.
            return $subject !== self::UNBOUND_SUBJECT;
        }

        $generation = $credential->getAttribute(self::GENERATION_COLUMN);
        if (! is_string($subject) || $subject !== $binding->subject || ! is_numeric($generation) || (int) $generation < 0) {
            return true;
        }

        if (! $remote) {
            return false;
        }
        try {
            $this->policy->verify($subject, (int) $generation, $fresh, self::epochOf($credential));
        } catch (ProviderSessionExpired) {
            return true;
        }

        return false;
    }

    /**
     * Enforce the identity of the person behind an authenticated bearer request, for an
     * application's privileged operations. Returns false when the credential must be refused.
     */
    public function verifyUser(Authenticatable $user, string $tokenId, bool $fresh = true): bool
    {
        $token = \Laravel\Passport\Passport::token()->newQuery()->whereKey($tokenId)->first();
        if ($token === null || (string) $token->getAttribute('user_id') !== (string) $user->getAuthIdentifier()) {
            return ! self::enabled();
        }

        return ! $this->revoked($token, $fresh);
    }

    /** @return array{subject: string, generation: int, epoch: int|null}|null */
    private function stampFromSession(?Request $request, string|int $userId): ?array
    {
        $user = $request?->user();
        if ($user === null || ! $request->hasSession()) {
            $user = app(\BWH\Auth\OAuth\Credentials\OAuthCredentialOwners::class)->find($userId);
            if ($user !== null && $this->bindings->binding($user) === null) {
                return self::unboundStamp();
            }
            throw new RuntimeException('Issuing a credential requires a verified provider session.');
        }
        if ((string) $user->getAuthIdentifier() !== (string) $userId) {
            throw new RuntimeException('The credential owner is not the authenticated person.');
        }

        $binding = $this->bindings->binding($user);
        if ($binding === null) {
            return self::unboundStamp();
        }
        if (! self::enabled()) {
            $generation = $this->session->baseline($request, $binding->provider, $binding->subject);

            return $generation === null ? null : ['subject' => $binding->subject, 'generation' => $generation,
                'epoch' => $this->session->epoch($request, $binding->provider, $binding->subject)];
        }
        // Issuing a credential is a privileged act: never rely on the session's freshness window.
        $identity = $this->session->assertActive($request, $binding->provider, $binding->subject, fresh: true);
        if ($identity->credentialVersion === null) {
            throw new RuntimeException('Issuing a credential requires a verified provider session.');
        }

        return ['subject' => $binding->subject, 'generation' => $identity->credentialVersion,
            'epoch' => $identity->recoveryEpoch];
    }

    /** @return array{subject: string, generation: int, epoch: null} */
    private static function unboundStamp(): array
    {
        return ['subject' => self::UNBOUND_SUBJECT, 'generation' => 0, 'epoch' => null];
    }

}
