<?php

namespace BWH\Auth\OAuth\Client;

use Illuminate\Support\Str;

/**
 * One authorization server this application is a client of, read from configuration.
 *
 * The sign-in provider is the top-level `oauth_client` settings, named `default`; every
 * other server is an entry of `oauth_client.servers`. Settings are checked when read, and a
 * missing or malformed one is a 503, as it always was for the sign-in provider: a
 * half-configured deploy is an outage, not something to guess around.
 *
 * Every endpoint is built from these settings. Nothing an authorization response or a
 * metadata document says changes where a code, token or person is sent.
 *
 * @internal
 */
final class AuthorizationServer
{
    public const string DEFAULT = 'default';

    public const string ISS_REQUIRED = 'required';

    public const string ISS_ADVERTISED = 'advertised';

    public const string ISS_WHEN_PRESENT = 'when_present';

    private const array NAMED_DEFAULTS = [
        'authorize_path' => '/oauth/authorize',
        'token_path' => '/oauth/token',
    ];

    /** @param  array<string, mixed>  $settings */
    private function __construct(
        public readonly string $name,
        private readonly array $settings,
    ) {}

    public static function resolve(?string $name): self
    {
        if ($name === null) {
            $settings = config('bherila-auth.oauth_client');

            return new self(self::DEFAULT, is_array($settings) ? $settings : []);
        }

        $settings = self::namedSettings($name);
        abort_unless($settings !== null, 503, 'OAuth is not configured.');

        $server = new self($name, $settings);
        $server->assertOwnCallback();

        return $server;
    }

    public static function isConfigured(?string $name): bool
    {
        $settings = $name === null ? config('bherila-auth.oauth_client') : self::namedSettings($name);
        if (! is_array($settings)) {
            return false;
        }

        $configured = static fn (string $key): bool => is_string($settings[$key] ?? null) && trim($settings[$key]) !== '';

        return $name === null
            ? $configured('client_id') && $configured('base_url')
            : $configured('client_id') && $configured('issuer');
    }

    /** @return array<string, mixed>|null */
    private static function namedSettings(string $name): ?array
    {
        // `default` is the sign-in provider's name; a server entry under it would be two
        // servers answering to one name.
        if ($name === self::DEFAULT || preg_match('/^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/', $name) !== 1) {
            return null;
        }

        $servers = config('bherila-auth.oauth_client.servers');
        $settings = is_array($servers) ? ($servers[$name] ?? null) : null;

        return is_array($settings) ? $settings : null;
    }

    public function isDefault(): bool
    {
        return $this->name === self::DEFAULT;
    }

    public function value(string $key): string
    {
        $value = $this->settings[$key] ?? null;
        if ($value === null && ! $this->isDefault()) {
            $value = match ($key) {
                'provider' => $this->name,
                'base_url' => $this->issuer(),
                default => self::NAMED_DEFAULTS[$key] ?? null,
            };
        }
        abort_unless(is_string($value) && $value !== '', 503, 'OAuth is not configured.');

        if ($key === 'base_url') {
            $value = rtrim($value, '/');
            abort_unless(filter_var($value, FILTER_VALIDATE_URL) !== false, 503, 'OAuth is not configured.');
        }

        if ($key === 'redirect_uri') {
            abort_unless(filter_var($value, FILTER_VALIDATE_URL) !== false, 503, 'OAuth is not configured.');
        }

        if ($key === 'provider') {
            abort_unless($value === trim($value) && Str::length($value) <= 64, 503, 'OAuth is not configured.');
        }

        return $value;
    }

    public function endpoint(string $pathKey): string
    {
        return $this->value('base_url').'/'.ltrim($this->value($pathKey), '/');
    }

    /**
     * The exact issuer identifier (RFC 8414) the server names itself by, compared byte for
     * byte with an authorization response's `iss`. The sign-in provider's defaults to its
     * base URL.
     */
    public function issuer(): string
    {
        $issuer = $this->settings['issuer'] ?? null;
        if ($this->isDefault() && ($issuer === null || $issuer === '')) {
            return $this->value('base_url');
        }

        abort_unless(is_string($issuer) && self::validIssuer($issuer), 503, 'OAuth is not configured.');

        return $issuer;
    }

    /** The RFC 8707 resource this server's tokens are requested for, if any. */
    public function resource(): ?string
    {
        $resource = $this->settings['resource'] ?? null;
        if ($resource === null || $resource === '') {
            return null;
        }

        abort_unless(is_string($resource) && self::isAbsoluteUri($resource), 503, 'OAuth is not configured.');

        return $resource;
    }

    /** How this server's RFC 9207 `iss` is expected: one of the ISS_* constants. */
    public function issuerParameter(): string
    {
        $mode = $this->settings['authorization_response_iss']
            ?? ($this->isDefault() ? self::ISS_WHEN_PRESENT : self::ISS_ADVERTISED);
        abort_unless(
            in_array($mode, [self::ISS_REQUIRED, self::ISS_ADVERTISED, self::ISS_WHEN_PRESENT], true),
            503,
            'OAuth is not configured.',
        );

        return $mode;
    }

    /** The path of this server's callback, which is where its responses must arrive. */
    public function callbackPath(): string
    {
        $path = parse_url($this->value('redirect_uri'), PHP_URL_PATH);

        return is_string($path) && $path !== '' ? $path : '/';
    }

    /**
     * RFC 8707 §2: an absolute URI (RFC 3986 §4.3, so a URN too) with no fragment.
     *
     * Checked by component: a scheme; then either `//` and an authority (optional userinfo,
     * a host that is an IP literal in brackets or a registered name, optional digits for a
     * port) followed by a path, or a path alone; then an optional query. Brackets are
     * accepted only around an IP literal host, and every `%` must start a percent-encoding.
     */
    private static function isAbsoluteUri(string $uri): bool
    {
        $unreserved = 'A-Za-z0-9\-._~';
        $subDelims = '!$&\'()*+,;=';
        $pct = '%[0-9A-Fa-f]{2}';
        $pchar = "(?:[{$unreserved}{$subDelims}:@]|{$pct})";

        if (preg_match('/^[A-Za-z][A-Za-z0-9+.-]*:(?<rest>.+)\z/s', $uri, $match) !== 1) {
            return false;
        }

        $rest = $match['rest'];
        if (str_starts_with($rest, '//')) {
            $authorityEnd = strcspn($rest, '/?', 2) + 2;
            if (! self::isAuthority(substr($rest, 2, $authorityEnd - 2), $unreserved, $subDelims, $pct)) {
                return false;
            }
            $rest = substr($rest, $authorityEnd);
        }

        return preg_match("/^(?:{$pchar}|\\/)*(?:\\?(?:{$pchar}|[\\/?])*)?\\z/", $rest) === 1;
    }

    private static function isAuthority(string $authority, string $unreserved, string $subDelims, string $pct): bool
    {
        $userinfo = "(?:[{$unreserved}{$subDelims}:]|{$pct})*@";
        $regName = "(?:[{$unreserved}{$subDelims}]|{$pct})*";
        if (preg_match("/^(?:{$userinfo})?(?:\\[(?<literal>[^\\]]*)\\]|{$regName})(?::[0-9]*)?\\z/", $authority, $match) !== 1) {
            return false;
        }

        $literal = $match['literal'] ?? '';

        return $literal === ''
            ? ! str_contains($authority, '[')
            : filter_var($literal, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false
                || preg_match("/^v[0-9A-Fa-f]+\\.[{$unreserved}{$subDelims}:]+\\z/", $literal) === 1;
    }

    private static function validIssuer(string $issuer): bool
    {
        return $issuer === trim($issuer)
            && filter_var($issuer, FILTER_VALIDATE_URL) !== false
            && in_array(parse_url($issuer, PHP_URL_SCHEME), ['https', 'http'], true)
            && parse_url($issuer, PHP_URL_USER) === null
            && parse_url($issuer, PHP_URL_QUERY) === null
            && parse_url($issuer, PHP_URL_FRAGMENT) === null;
    }

    /**
     * Each server gets a callback of its own. A response is then attributable to the server
     * it came from by where it arrives, independently of `iss`, which a server may not send.
     */
    private function assertOwnCallback(): void
    {
        $callback = $this->value('redirect_uri');
        $others = [config('bherila-auth.oauth_client.redirect_uri')];

        $servers = config('bherila-auth.oauth_client.servers');
        foreach (is_array($servers) ? $servers : [] as $name => $settings) {
            // A numeric name such as "1" is an integer array key.
            if ((string) $name !== $this->name && is_array($settings)) {
                $others[] = $settings['redirect_uri'] ?? null;
            }
        }

        foreach ($others as $other) {
            abort_if(is_string($other) && rtrim($other, '/') === rtrim($callback, '/'), 503, 'OAuth is not configured.');
        }
    }
}
