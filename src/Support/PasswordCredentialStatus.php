<?php

namespace BWH\Auth\Support;

enum PasswordCredentialStatus: string
{
    case Verified = 'verified';
    case InvalidCredentials = 'invalid_credentials';
    case AccountDisabled = 'account_disabled';
}
