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
    ) {}
}
