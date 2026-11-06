<?php

namespace BWH\Auth\Services;

use BWH\Auth\Contracts\AuthUserPolicy;
use BWH\Auth\Support\PasswordCredentialResult;
use Illuminate\Auth\SessionGuard;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Factory;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Http\Request;
use LogicException;

/** Password verification shared by callers that own their MFA and session flow. */
class PasswordCredentials
{
    public function __construct(
        private readonly Factory $auth,
        private readonly AuthUserPolicy $policy,
        private readonly Repository $config,
    ) {}

    /** @param array<string, mixed> $credentials */
    public function verify(Request $request, #[\SensitiveParameter] array $credentials, ?string $guard = null): PasswordCredentialResult
    {
        // Resolve per call: an embedded provider temporarily selects its own guard.
        $session = $this->auth->guard($guard);
        if (! $session instanceof SessionGuard) {
            throw new LogicException('Password preflight requires a session authentication guard.');
        }

        // validate() retains Laravel's timebox and Validated event, but never logs in,
        // regenerates a session, queues a recaller, or emits a Login/Failed event.
        if (! $session->validate($credentials)) {
            return PasswordCredentialResult::invalid($session->getLastAttempted());
        }

        $user = $session->getLastAttempted();
        if (! $user instanceof Authenticatable) {
            return PasswordCredentialResult::invalid();
        }
        if (! $this->policy->canLogin($user, $request)) {
            return PasswordCredentialResult::disabled($user);
        }

        if ($this->config->get('hashing.rehash_on_login', true)) {
            $session->getProvider()->rehashPasswordIfRequired($user, $credentials);
        }

        return PasswordCredentialResult::verified($user);
    }
}
