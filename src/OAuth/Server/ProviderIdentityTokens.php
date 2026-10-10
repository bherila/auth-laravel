<?php

namespace BWH\Auth\OAuth\Server;

use BWH\Auth\OAuth\Session\ProviderBindingResolver;
use BWH\Auth\OAuth\Session\ProviderIdentityPolicy;
use BWH\Auth\OAuth\Session\ProviderSession;
use BWH\Auth\OAuth\Session\ProviderSessionExpired;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
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
 * another subject, or no longer matches the provider's answer. An unavailable provider
 * raises ProviderStatusUnavailable, which renders a retryable 503 and leaves a refresh
 * token unconsumed. Unbound accounts and client-credential tokens are left to the
 * application.
 */
final readonly class ProviderIdentityTokens
{
    public const SUBJECT_COLUMN = 'provider_subject';

    public const GENERATION_COLUMN = 'provider_generation';

    /** The stamp carried from a code or refresh token to the access token minted from it. */
    public const REQUEST_ATTRIBUTE = 'bherila_auth.provider_identity_stamp';

    public function __construct(
        private ProviderSession $session,
        private ProviderBindingResolver $bindings,
        private ProviderIdentityPolicy $policy,
    ) {}

    public static function enabled(): bool
    {
        return (bool) config('bherila-auth.provider_identity.enabled', false);
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
     * @return array{subject: string, generation: int}|null
     */
    public function stampForIssue(?Request $request, string|int|null $userId): ?array
    {
        if ($userId === null || $userId === '') {
            return null;
        }
        $carried = $request?->attributes->get(self::REQUEST_ATTRIBUTE);
        if (is_array($carried) && is_string($carried['subject'] ?? null) && is_int($carried['generation'] ?? null)) {
            return ['subject' => $carried['subject'], 'generation' => $carried['generation']];
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
            $request?->attributes->set(self::REQUEST_ATTRIBUTE, ['subject' => $subject, 'generation' => (int) $generation]);
        }
    }

    /** @return array<string, string|int> the stamp's column values, empty when there is none */
    public static function attributes(?array $stamp): array
    {
        return $stamp === null ? [] : [
            self::SUBJECT_COLUMN => $stamp['subject'],
            self::GENERATION_COLUMN => $stamp['generation'],
        ];
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
        $userId = $credential->getAttribute('user_id');
        if ($userId === null || $userId === '') {
            return false;
        }

        $user = $this->users()->retrieveById($userId);
        if ($user === null) {
            return true;
        }
        try {
            $binding = $this->bindings->binding($user);
        } catch (ProviderSessionExpired) {
            return true;
        }
        if ($binding === null) {
            return false;
        }

        $subject = $credential->getAttribute(self::SUBJECT_COLUMN);
        $generation = $credential->getAttribute(self::GENERATION_COLUMN);
        if (! is_string($subject) || $subject !== $binding->subject || ! is_numeric($generation) || (int) $generation < 0) {
            return true;
        }

        if (! $remote) {
            return false;
        }
        try {
            $this->policy->verify($subject, (int) $generation, $fresh);
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

    /** @return array{subject: string, generation: int}|null */
    private function stampFromSession(?Request $request, string|int $userId): ?array
    {
        $user = $request?->user();
        if ($user === null || ! $request->hasSession()) {
            $user = $this->users()->retrieveById($userId);
            if ($user !== null && $this->bindings->binding($user) === null) {
                return null;
            }
            throw new RuntimeException('Issuing a credential requires a verified provider session.');
        }
        if ((string) $user->getAuthIdentifier() !== (string) $userId) {
            throw new RuntimeException('The credential owner is not the authenticated person.');
        }

        $binding = $this->bindings->binding($user);
        if ($binding === null) {
            return null;
        }
        if (! self::enabled()) {
            $generation = $this->session->baseline($request, $binding->provider, $binding->subject);

            return $generation === null ? null : ['subject' => $binding->subject, 'generation' => $generation];
        }
        $identity = $this->session->assertActive($request, $binding->provider, $binding->subject);
        if ($identity->credentialVersion === null) {
            throw new RuntimeException('Issuing a credential requires a verified provider session.');
        }

        return ['subject' => $binding->subject, 'generation' => $identity->credentialVersion];
    }

    private function users(): UserProvider
    {
        $guard = (string) config('bherila-auth.provider_identity.bearer_guard', 'api');
        $provider = config("auth.guards.{$guard}.provider");
        $users = is_string($provider) ? auth()->createUserProvider($provider) : null;
        if ($users === null) {
            throw new RuntimeException('Provider identity enforcement needs the bearer guard\'s user provider.');
        }

        return $users;
    }
}
