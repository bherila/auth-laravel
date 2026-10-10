<?php

return [
    'routes' => [
        'enabled' => true,
        'prefix' => 'api',
        'middleware' => ['web'],
        'passkeys' => true,
        'password_resets' => true,
        'change_password' => true,
        'two_factor' => true,
    ],

    // Which proxies may report the client's address (BWH\Auth\Http\TrustedProxies).
    // Off by default. When applied, `trusted` is `cloudflare` (Cloudflare's
    // published ranges), an explicit comma-separated list of addresses or CIDR
    // ranges, `*` only where a firewall admits the proxy alone, or empty to
    // trust nothing - right for a deployment with no proxy in front. Only
    // X-Forwarded-For and -Proto are honoured, never the forwarded port or host.
    'trusted_proxies' => [
        'apply' => (bool) env('BHERILA_AUTH_TRUSTED_PROXIES', false),
        'trusted' => env('TRUSTED_PROXIES', 'cloudflare'),
        // Null uses the ranges shipped with the package; set a list to pin your own.
        'cloudflare' => null,
    ],

    'oauth_client' => [
        // Shared OAuth authorization-code + PKCE client mechanics. Applications still
        // own local user provisioning and authorization policy after identity resolution.
        'provider' => env('OAUTH_PROVIDER', 'bherila'),
        'base_url' => env('OAUTH_PROVIDER_URL', 'https://bherila.net'),
        'client_id' => env('OAUTH_CLIENT_ID'),
        'client_secret' => env('OAUTH_CLIENT_SECRET'),
        'redirect_uri' => env('OAUTH_REDIRECT_URI', rtrim((string) env('APP_URL'), '/').'/oauth/callback'),
        'scope' => env('OAUTH_SCOPE', 'identity:read'),
        'authorize_path' => '/oauth/authorize',
        'token_path' => '/oauth/token',
        'identity_path' => '/api/oauth/user',
        // Relying-party initiated logout. Ending only the local session leaves the provider
        // still recognising the person, so the next sign-in returns them without a prompt.
        'end_session_path' => '/oauth/end-session',
    ],

    // Optional OAuth authorization-server helpers for applications exposing an
    // MCP or other protected API through Laravel Passport. Routes remain owned
    // by the application so this package never enables an authorization server
    // merely by being installed.
    'oauth_server' => [
        'enabled' => false,
        'issuer' => env('APP_URL', 'http://localhost'),
        'resource' => rtrim((string) env('APP_URL', 'http://localhost'), '/').'/api/v1',
        'authorization_endpoint' => rtrim((string) env('APP_URL', 'http://localhost'), '/').'/oauth/authorize',
        'token_endpoint' => rtrim((string) env('APP_URL', 'http://localhost'), '/').'/oauth/token',
        // This is intentionally null. Applications must expose and configure the
        // endpoint before it is advertised in authorization-server metadata.
        'registration_endpoint' => null,
        'scopes' => [],
        // Null means the protected-resource metadata helper uses the complete
        // application-owned scope catalog. Set a list when this resource exposes
        // only a subset of that catalog.
        'protected_resource_scopes' => null,
        'token_endpoint_auth_methods' => ['none'],
        // RFC 8707 has no discovery boolean. The resource parameter and the
        // protected-resource metadata document are the interoperable signals.
        'protected_resource_metadata_url' => null,
        'auth_code_resource_column' => 'resource_uri',
        'resource_column' => 'resource_uri',
        'refresh_token_resource_column' => 'resource_uri',
        'authorization_response_issuer' => [
            // RFC 9207 is opt-in because the authorization response middleware must
            // be installed on every authorization/consent route to make this true.
            'enabled' => false,
        ],
        // The application owns its scope policy. Keep the legacy scalar for
        // published-config compatibility, but do not assume a package scope.
        'resource_required_scope' => null,
        // Opt-in. When this authorization server protects exactly one resource,
        // bind a code or token whose request omits RFC 8707 `resource` to it,
        // so generic OAuth clients that never send the parameter still get an
        // audience-bound credential. A different explicit resource is refused.
        'assume_omitted_resource' => (bool) env('OAUTH_ASSUME_OMITTED_RESOURCE', false),
        'resource_required_scopes' => [],
        'dynamic_clients' => [
            'enabled' => true,
            'required_columns' => ['dynamically_registered_at', 'scopes'],
            'registered_at_column' => 'dynamically_registered_at',
            'last_used_at_column' => null,
            // bherila-auth:prune-dynamic-clients removes registrations unused this long.
            'retention_days' => (int) env('OAUTH_DYNAMIC_CLIENT_RETENTION_DAYS', 30),
            'scopes_column' => 'scopes',
            // Retained for published-config compatibility; registered scopes are
            // always enforced for dynamic clients in the resource middleware.
            'enforce_registered_scopes' => true,
        ],
        'authorization_state' => [
            // Uses Laravel's default cache repository. It must persist across
            // requests and be shared by every authorization-server node.
            'cache_prefix' => 'oauth-resource:',
            'ttl_seconds' => null,
        ],
        'consent' => [
            'app_name' => env('APP_NAME', 'Application'),
            'heading' => 'Connect :client to :app?',
            'intro' => 'This application is requesting access to your :app account.',
            'identity' => true,
            'trust_warning' => 'Only continue if you recognize and trust this application. You can disconnect it later.',
            'dynamic_client_warning' => 'This application registered automatically. After approval, your browser returns to:',
            'policy_notice' => 'Your current permissions still apply to every request.',
            'approve_label' => 'Authorize',
            'deny_label' => 'Cancel',
        ],
        // A person's own API tokens and OAuth apps (OAuth\Credentials). Opt-in;
        // routes are session routes under `prefix` with `middleware`.
        'credentials' => [
            'enabled' => false,
            'prefix' => 'account/api-credentials',
            'middleware' => ['web', 'auth'],
            // ISO-8601 durations offered for personal API tokens, e.g. PT4H for a
            // short quick-setup token.
            'token_lifetimes' => ['P30D', 'P90D', 'P365D'],
            'token_name_prefix' => 'api-token: ',
            'personal_client_name' => 'Personal access tokens',
            // Null uses the api guard's provider.
            'provider' => null,
            // Null: the signed-in user owns credentials. Set a model class (over the
            // same table, using HasApiTokens) when the API guard loads another model.
            'owner_model' => null,
            // Scopes never offered to a credential, beyond the MCP-connection scopes.
            'excluded_scopes' => [],
            // Opt-in, off by default: the MCP-connection scopes (entries of
            // `resource_required_scopes`, such as `mcp:use`) a personal API token
            // may carry, for agent clients that reach an MCP endpoint only with a
            // static bearer key. Each must also be in the scope catalog and not in
            // `excluded_scopes`; OAuth apps are never offered one.
            //
            // The tradeoff: such a token is a long-lived static key with
            // connection rights. Nobody sees a consent screen naming the client
            // that uses it, it works from anywhere until it expires or is
            // revoked, and anyone who copies it can connect as its owner. It is
            // still bound to this server's one protected resource (RFC 8707), so
            // it is accepted only on routes marked with ExpectOAuthResource.
            // Removing a scope here stops new tokens, not tokens already issued.
            'personal_token_connection_scopes' => [],
            // The longest lifetime (ISO-8601) a token carrying a connection scope
            // may have once the opt-in is on; only offered lifetimes no longer
            // than this are accepted for one. An invalid value offers none.
            'personal_token_connection_max_lifetime' => 'P30D',
        ],
        'introspection' => [
            // RFC 7662 is application-routed and opt-in. Each confidential
            // resource-server credential is pinned to one exact resource so an
            // introspector can never choose a broader audience at request time.
            // Store only a password_hash() result in each `secret_hash` value.
            'enabled' => false,
            'clients' => [],
        ],
    ],

    'oauth_resource_server' => [
        // Backchannel validation for a separately deployed authorization server.
        // Active responses are still checked locally against the exact issuer,
        // resource, audience, and temporal claims before they are trusted.
        'introspection_endpoint' => env('OAUTH_INTROSPECTION_ENDPOINT'),
        'client_id' => env('OAUTH_INTROSPECTION_CLIENT_ID'),
        'client_secret' => env('OAUTH_INTROSPECTION_CLIENT_SECRET'),
        'issuer' => env('OAUTH_RESOURCE_ISSUER'),
        'resource' => env('OAUTH_RESOURCE_URI'),
        'timeout_seconds' => (int) env('OAUTH_INTROSPECTION_TIMEOUT_SECONDS', 5),
    ],

    'delegated_access' => [
        // The endpoint an identity provider calls to manage people's access in this application
        // (delegated access contract version 3). Its route exists only when the application binds
        // BWH\Auth\OAuth\DelegatedAccess\ApplicationAccessAdapter, and answers 404 until enabled.
        'enabled' => env('DELEGATED_ACCESS_ENABLED', false),
        // Whether delegated changes (`update`, `remove`) are accepted. Off by default, independent of the
        // provider's own switch, so this application decides when it accepts writes.
        'writes_enabled' => env('DELEGATED_ACCESS_WRITES_ENABLED', false),
        // The provider's exact HTTPS issuer. Must be the sign-in provider (oauth_client.base_url):
        // subjects it asserts are resolved in that provider's binding namespace.
        'issuer' => env('DELEGATED_ACCESS_ISSUER', ''),
        // This endpoint's exact HTTPS URL, as the provider is configured to call it.
        'endpoint' => env('DELEGATED_ACCESS_ENDPOINT', ''),
        // This application's key in the provider's application registry.
        'application' => env('DELEGATED_ACCESS_APPLICATION', ''),
        // The provider's integration public keys: `key-id|/path/to/public.pem`, comma-separated.
        'public_keys' => env('DELEGATED_ACCESS_PUBLIC_KEYS', ''),
        // Must be set and equal oauth_client.provider: bindings are stored under that name.
        'oauth_provider' => env('OAUTH_PROVIDER'),
        // The nonce table's connection; null for the default. Must be durable and shared by every worker.
        'nonce_connection' => env('DELEGATED_ACCESS_NONCE_CONNECTION'),
        // The operation receipts table's connection; the nonce connection unless set. Durable and
        // shared by every worker, like the nonces: a lost receipt lets a repeated write run again.
        'receipt_connection' => env('DELEGATED_ACCESS_RECEIPT_CONNECTION', env('DELEGATED_ACCESS_NONCE_CONNECTION')),
        'path' => '/application-access',
        'per_minute' => 120,
    ],

    'migrations' => [
        'drop_tables_on_rollback' => false,
    ],

    'audit' => [
        // 'null' discards events (default); 'database' persists them to the audit table.
        'driver' => env('BHERILA_AUTH_AUDIT_DRIVER', 'null'),
        'table' => 'auth_audit_log',
        // Expose the package's read endpoints (own login history + admin list). Off by default.
        'routes_enabled' => env('BHERILA_AUTH_AUDIT_ROUTES', false),
        // null = retain forever (no pruning). Set a positive integer to enable `model:prune`.
        'retention_days' => env('BHERILA_AUTH_AUDIT_RETENTION_DAYS'),
        // Gate ability required for the cross-user admin endpoint; null disables that route.
        // IMPORTANT: the ability must verify that the user is active/approved AND is an admin.
        // The package enforces its own RequireActiveUser check on top of this gate, but the
        // gate should still verify account state independently so your Gate definition is
        // correct even when called from other locations. Example: check both ->is_admin and
        // ->approved_at, not just the role.
        'admin_ability' => env('BHERILA_AUTH_AUDIT_ADMIN_ABILITY'),
    ],

    'throttle' => [
        // Opt-in brute-force lockout backed by auth_audit_log rows. Disabled by default.
        'enabled' => env('BHERILA_AUTH_THROTTLE_ENABLED', false),
        'max_attempts' => env('BHERILA_AUTH_THROTTLE_MAX_ATTEMPTS', 5),
        'decay_minutes' => env('BHERILA_AUTH_THROTTLE_DECAY_MINUTES', 15),
        // How failed attempts are grouped into a lockout key:
        //   'email'    — per account: count an email's failures across all source IPs
        //   'ip'       — per source: count an IP's failures across all emails
        //   'email_ip' — per account+source pair (most conservative; default)
        // Any other value falls back to 'email_ip'.
        'key' => env('BHERILA_AUTH_THROTTLE_KEY', 'email_ip'),
        'record_blocked' => env('BHERILA_AUTH_THROTTLE_RECORD_BLOCKED', true),
    ],

    'password_resets' => [
        'reset_url' => env('BHERILA_AUTH_PASSWORD_RESET_URL', env('APP_URL', '').'/reset-password/{token}?email={email}'),
        'request_url' => env('BHERILA_AUTH_PASSWORD_REQUEST_URL', '/forgot-password'),
        'redirect_after_reset' => env('BHERILA_AUTH_PASSWORD_RESET_REDIRECT', '/'),
        'mail_subject' => env('BHERILA_AUTH_PASSWORD_RESET_MAIL_SUBJECT', 'Reset your :app password'),
        'notice_subject' => env('BHERILA_AUTH_PASSWORD_NOTICE_MAIL_SUBJECT', 'Your :app password was changed'),
        'verify_email_on_reset' => false,
    ],

    'two_factor' => [
        'table' => 'auth_two_factor_attempts',
        'expires_minutes' => 15,
        // Fixed-code bypass for automated tests and local development. Off by default,
        // and even when on it applies only to accounts explicitly flagged `is_test`
        // AND only in the environments listed below (an empty list means any).
        // All three conditions must hold, so turning this off really does turn it off.
        'allow_test_code' => env('BHERILA_AUTH_ALLOW_TEST_2FA_CODE', false),
        'test_code_environments' => ['local', 'testing'],
        'test_code' => '999999',
        'mail_subject' => env('BHERILA_AUTH_TWO_FACTOR_MAIL_SUBJECT', 'Verify your login - :app'),
        'login_url' => env('BHERILA_AUTH_LOGIN_URL', '/login'),
        'session_user_key' => 'bherila_auth_2fa_user_id',
        'session_remember_key' => 'bherila_auth_2fa_remember',
    ],

    'passkeys' => [
        'table' => 'auth_passkeys',
        'rp_name' => env('WEBAUTHN_RP_NAME', env('APP_NAME', 'App')),
        // The registrable domain credentials bind to. Set this once per deployment
        // (for example `example.com`) so credentials stay valid across every subdomain
        // rather than being pinned to whichever host served the registration page.
        // Leave unset in local development to derive it from the request host.
        'rp_id' => env('WEBAUTHN_RP_ID'),
        'allowed_origins' => array_filter(array_map('trim', explode(',', env('WEBAUTHN_ALLOWED_ORIGINS', '')))),
        'timeout' => 60000,
        'resident_key' => env('WEBAUTHN_RESIDENT_KEY', 'preferred'),
        'user_verification' => env('WEBAUTHN_USER_VERIFICATION', 'preferred'),
    ],

    'users' => [
        'model' => config('auth.providers.users.model', App\Models\User::class),
        'name_attribute' => 'name',
        'email_attribute' => 'email',
        'force_change_password_attribute' => null,
    ],
];
