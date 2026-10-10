<?php

namespace BWH\Auth\OAuth\Session;

use BWH\Auth\OAuth\Reconciliation\ReconciliationFailure;
use BWH\Auth\OAuth\Reconciliation\ReconciliationTransport;
use Illuminate\Http\Client\Factory;

final readonly class ProviderIdentityStatusClient
{
    private ReconciliationTransport $transport;

    // The constructor keeps taking the HTTP factory so existing callers are unaffected.
    public function __construct(Factory $http)
    {
        $this->transport = new ReconciliationTransport($http);
    }

    /**
     * Null means definitively inactive; failures never become an active result.
     * An active result carries liveness and generation only. The request is
     * authenticated by this application's client credential, not by the person,
     * so profile fields are never read from it, even if a provider sends them.
     */
    public function status(string $subject): ?ProviderIdentityStatus
    {
        if ($subject === '' || strlen($subject) > 191) {
            throw new ProviderSessionExpired('The provider session binding is invalid.');
        }

        $data = $this->guard(fn (): array => $this->transport->send(
            'POST', '/api/reconciliation/identity-status', [], ['subject' => $subject], 16_384, 5,
        ));
        if (($data['contract_version'] ?? null) !== 1 || ! is_bool($data['active'] ?? null)) {
            throw new ProviderStatusUnavailable('The provider status response is invalid.');
        }
        // Inactive v1 responses intentionally omit identity fields. If a provider
        // nevertheless names a subject, it must not contradict this single-subject request.
        if (array_key_exists('subject', $data) && $data['subject'] !== $subject) {
            throw new ProviderStatusUnavailable('The provider status response is invalid.');
        }
        if (! $data['active']) {
            return null;
        }
        if (($data['subject'] ?? null) !== $subject
            || ! is_int($data['credential_version'] ?? null) || $data['credential_version'] < 0) {
            throw new ProviderStatusUnavailable('The provider status response is invalid.');
        }

        return new ProviderIdentityStatus($subject, $data['credential_version']);
    }

    /** Pin cached session verification to this configured provider and client. */
    public function context(): string
    {
        return $this->guard(fn (): string => $this->transport->context());
    }

    /**
     * Run a transport call, reporting its failure in this client's own terms.
     *
     * @template T
     *
     * @param  \Closure(): T  $call
     * @return T
     */
    private function guard(\Closure $call): mixed
    {
        try {
            return $call();
        } catch (ReconciliationFailure $failure) {
            throw new ProviderStatusUnavailable(match ($failure->reason) {
                ReconciliationFailure::NOT_CONFIGURED => 'Provider session verification is not configured.',
                ReconciliationFailure::UNTRUSTED_URL => 'Provider status requires a trusted HTTPS base URL.',
                ReconciliationFailure::INVALID => 'The provider status response is invalid.',
                default => 'Provider session verification is unavailable.',
            });
        }
    }
}
