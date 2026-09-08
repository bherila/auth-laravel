<?php

namespace BWH\Auth\OAuth\Introspection;

interface OAuthTokenIntrospector
{
    /**
     * Returns an inactive result without claims when the token is invalid for this resource server.
     *
     * @throws OAuthIntrospectionException when configuration, transport, client authentication, or response schema fails
     */
    public function introspect(string $token): IntrospectedToken;
}
