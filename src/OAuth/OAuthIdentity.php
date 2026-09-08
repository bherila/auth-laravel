<?php

namespace BWH\Auth\OAuth;

final readonly class OAuthIdentity
{
    /**
     * @param  list<array{key: string, name: string, url: string}>  $apps
     *   Applications this person can move between, as the provider reports them. Empty when
     *   the provider does not send a list, so an application built against an older provider
     *   simply has nothing to offer rather than failing.
     */
    public function __construct(
        public string $provider,
        public string $subject,
        public string $name,
        public string $email,
        public array $apps = [],
        public ?int $credentialVersion = null,
    ) {}
}
