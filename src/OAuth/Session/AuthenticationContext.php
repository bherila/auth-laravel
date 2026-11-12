<?php

namespace BWH\Auth\OAuth\Session;

use BWH\Auth\OAuth\AuthenticationRequirement;
use BWH\Auth\OAuth\IdentityNamespace;
use BWH\Auth\OAuth\OAuthIdentity;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;

/**
 * How the person in this session last authenticated at the provider.
 *
 * Replaced at every provider sign-in, including with nothing when the provider reports
 * nothing, and bound to the account it was reported for. A session with no values satisfies
 * no requirement, so a remembered login always has to authenticate again.
 */
final class AuthenticationContext
{
    public const string SESSION_KEY = 'bherila_auth.authentication_context';

    public const string PENDING_KEY = 'bherila_auth.authentication_requirement';

    public static function remember(Request $request, OAuthIdentity $identity, Authenticatable $account): void
    {
        if ($identity->authTime === null) {
            $request->session()->forget(self::SESSION_KEY);

            return;
        }

        $request->session()->put(self::SESSION_KEY, [
            'account' => (string) $account->getAuthIdentifier(),
            'identity_namespace' => IdentityNamespace::resolve($request, $account),
            'auth_time' => $identity->authTime,
            'amr' => $identity->amr,
            'acr' => $identity->acr,
        ]);
    }

    public static function satisfies(Request $request, Authenticatable $account, AuthenticationRequirement $requirement): bool
    {
        $context = $request->session()->get(self::SESSION_KEY);

        if (! is_array($context)
            || ($context['account'] ?? null) !== (string) $account->getAuthIdentifier()
            || ! is_int($context['auth_time'] ?? null)
            || ! is_array($context['amr'] ?? null)) {
            return false;
        }
        $namespace = array_key_exists('identity_namespace', $context) ? $context['identity_namespace'] : IdentityNamespace::LEGACY;
        if (! IdentityNamespace::valid($namespace) || $namespace !== IdentityNamespace::resolve($request, $account)) {
            return false;
        }

        return $requirement->satisfiedBy(
            $context['auth_time'],
            array_values(array_filter($context['amr'], 'is_string')),
            is_string($context['acr'] ?? null) ? $context['acr'] : null,
            Carbon::now()->getTimestamp(),
        );
    }

    /** Ask the next provider sign-in in this session to meet the requirement. */
    public static function requireNext(Request $request, AuthenticationRequirement $requirement): void
    {
        $request->session()->put(self::PENDING_KEY, $requirement->toArray());
    }

    public static function pullNext(Request $request): ?AuthenticationRequirement
    {
        return AuthenticationRequirement::fromArray($request->session()->pull(self::PENDING_KEY));
    }
}
