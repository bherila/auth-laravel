<?php

namespace BWH\Auth\OAuth\DelegatedAccess;

/**
 * The application-owned half of the delegated access endpoint.
 *
 * The package's controller verifies the actor assertion, consumes its nonce, validates the request
 * against contract version 3, answers a repeated write from its stored receipt, and validates the
 * answer before it leaves. Everything between is the application's: resolving the verified actor to
 * a local account, deciding whether that account may manage access at all, which targets and
 * workspaces it may see, what it may change, revisions, provisioning, removal, audit, and
 * last-administrator rules. The provider's own administrators get nothing from being
 * administrators there.
 *
 * One method takes every operation, so a new operation is a new payload rather than a new method.
 * Version 3 asks an adapter for:
 *
 *  - `capabilities` → `controls`; each `workspace_roles[]` entry may add a `description`.
 *  - `subjects`, `workspaces` → a page. The payload may carry `query`: match it case-insensitively
 *    as a substring of the label (and of the email, where the application stores one), only within
 *    what the actor may see, with the same cursor pagination ({@see DelegatedCursor}, passing the
 *    query to `encode()`).
 *  - `read`, `update` → a state. A state may add `provisioned_at`, `first_sign_in_at` and
 *    `last_seen_at`: ISO-8601 timestamps or null, observations only, never part of the revision.
 *  - `remove` → the state after removing every membership and the administrator flag in the actor's
 *    projection. The account and its history stay. Refuse rather than remove part of it.
 *
 * `update` and `remove` carry `operation_id`. The endpoint has already answered a repeat of an
 * operation from its receipt, so an adapter never sees the same write twice; it may record the id
 * with its own audit. `receipt` never reaches the adapter.
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
