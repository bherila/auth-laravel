<?php

namespace BWH\Auth\OAuth;

/** Why {@see OAuthClient} refused an authorization response before exchanging its code. */
enum OAuthCallbackFailure: string
{
    /** No pending cache/session flow carries the response's `state`: missing, expired from cache, or replayed. */
    case StateMismatch = 'state_mismatch';

    /** The flow was started longer ago than `oauth_client.pending_flow_ttl` allows. */
    case Expired = 'expired';

    /** The flow was started for another authorization server, or that server's settings changed since. */
    case ServerMismatch = 'server_mismatch';

    /** The response reached a route that is not the server's configured callback. */
    case CallbackMismatch = 'callback_mismatch';

    /** The person signed in now is not the one who started the flow. */
    case UserMismatch = 'user_mismatch';

    /** The server sends RFC 9207 `iss` (by configuration or metadata) and this response has none. */
    case IssuerMissing = 'issuer_missing';

    /** The response's `iss` is not exactly the issuer the request was sent to. */
    case IssuerMismatch = 'issuer_mismatch';

    /** The server answered with an OAuth `error` instead of a code. */
    case AuthorizationDenied = 'authorization_denied';

    /** The response carries no authorization code. */
    case CodeMissing = 'code_missing';
}
