<?php

namespace BWH\Auth\OAuth\DelegatedAccess;

/**
 * The application-owned half of the delegated access endpoint.
 *
 * The package's controller verifies the actor assertion, consumes its nonce, validates the request
 * against contract version 2 and validates the answer before it leaves. Everything between is the
 * application's: resolving the verified actor to a local account, deciding whether that account may
 * manage access at all, which targets and workspaces it may see, what it may change, revisions,
 * provisioning, audit, and last-administrator rules. The provider's own administrators get nothing
 * from being administrators there.
 */
interface ApplicationAccessAdapter
{
    /**
     * @param  string  $actorSubject  The verified provider subject of the person acting. An identity, never an authority.
     * @param  array<string, mixed>  $payload  The request as {@see DelegatedContract::request()} returned it, without
     *                                         `contract_version` and `application`: `operation` plus that operation's fields.
     * @return array<string, mixed> That operation's response fields, without the envelope. The controller adds
     *                              `contract_version`, `application` and `operation`, then validates the whole answer.
     *
     * @throws DelegatedAccessException A refusal. Its outcome and status are sent to the provider as they are.
     */
    public function handle(string $actorSubject, array $payload): array;
}
