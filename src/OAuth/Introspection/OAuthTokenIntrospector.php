<?php

namespace BWH\Auth\OAuth\Introspection;

interface OAuthTokenIntrospector
{
    /**
     * Returns an inactive result without claims when the authorization server reports the token inactive.
     *
     * @throws OAuthTokenValidationException when an active token context is invalid for this resource server
     * @throws OAuthIntrospectionException when configuration, transport, client authentication, or the response envelope fails
     */
    public function introspect(string $token): IntrospectedToken;
}
