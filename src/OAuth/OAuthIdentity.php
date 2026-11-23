<?php

namespace BWH\Auth\OAuth;

final readonly class OAuthIdentity
{
    /**
     * @param  list<array{key: string, name: string, url: string}>  $apps
     *   Applications this person can move between, as the provider reports them. Empty when
     *   the provider does not send a list, so an application built against an older provider
     *   simply has nothing to offer rather than failing.
     * @param  list<string>  $amr  how the person authenticated (RFC 8176), when the provider reports it
     * @param  bool|null  $emailVerified  the provider's `email_verified` claim: true when it sent
     *   true (or the string "true"), false when it sent anything else, null when it sent nothing.
     *   An application decides what an absent claim means; the package's sign-in refuses only false
     *   (`oauth_login.refuse_unverified_email`).
     * @param  bool  $emailVerifiedNative  true only when the claim was the JSON boolean `true`. The
     *   lenient `$emailVerified` also reads the string "true"; strict proof
     *   (`oauth_login.require_verified_email`) accepts only the native boolean.
     * @param  int|null  $recoveryEpoch  the provider's recovery epoch at sign-in, when it reports
     *   one. A provider raises it whenever it is restored from a backup; a session or credential
     *   captured under another epoch is treated as ended. Null from a provider that sends none.
     */
    public function __construct(
        public string $provider,
        public string $subject,
        public string $name,
        public string $email,
        public array $apps = [],
        public ?int $credentialVersion = null,
        public ?int $authTime = null,
        public array $amr = [],
        public ?string $acr = null,
        public ?bool $emailVerified = null,
        public bool $emailVerifiedNative = false,
        public ?int $recoveryEpoch = null,
    ) {}
}
