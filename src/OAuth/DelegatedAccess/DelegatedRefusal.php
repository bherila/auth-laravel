<?php

namespace BWH\Auth\OAuth\DelegatedAccess;

/**
 * The refusals an adapter sends, each with the one status that carries it.
 *
 * A provider that does not know an outcome still acts on its status: 403 and 404 mean the actor may
 * not do this, 409 that the view it holds is stale, 422 that the application could not accept the
 * request. So a new outcome here always reuses one of those statuses, and a refusal never uses a
 * 5xx, which a provider treats as an unknown result of a write.
 */
final class DelegatedRefusal
{
    /** The actor may not manage access here at all, or may not see or change this target or workspace. */
    public const NOT_AUTHORIZED = 'not_authorized';

    /** A read of a subject this application has no account for, when it does not report one unprovisioned. */
    public const NOT_PROVISIONED = 'not_provisioned';

    /** The expected revision is not the current one, or a provisioning subject is already bound. */
    public const REVISION_CONFLICT = 'revision_conflict';

    /** The request is well formed but this application cannot apply it, for a reason not listed here. */
    public const INVALID_REQUEST = 'invalid_request';

    /** The update changes or omits a membership the read reported as not editable for this actor. */
    public const PROTECTED_MEMBERSHIP = 'protected_membership';

    /** The update names a role this actor may not grant, or that the application did not advertise. */
    public const ROLE_NOT_GRANTABLE = 'role_not_grantable';

    public const STATUSES = [
        self::NOT_AUTHORIZED => 403,
        self::NOT_PROVISIONED => 404,
        self::REVISION_CONFLICT => 409,
        self::INVALID_REQUEST => 422,
        self::PROTECTED_MEMBERSHIP => 403,
        self::ROLE_NOT_GRANTABLE => 403,
    ];

    public static function of(string $outcome): DelegatedAccessException
    {
        if (! isset(self::STATUSES[$outcome])) {
            throw new \InvalidArgumentException('Not a delegated access refusal: '.$outcome);
        }

        return new DelegatedAccessException($outcome, self::STATUSES[$outcome]);
    }
}
