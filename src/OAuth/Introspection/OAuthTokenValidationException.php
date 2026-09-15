<?php

namespace BWH\Auth\OAuth\Introspection;

/**
 * The authorization server recognized the token, but its active context is
 * invalid for this resource server.
 */
final class OAuthTokenValidationException extends OAuthIntrospectionException
{
}
