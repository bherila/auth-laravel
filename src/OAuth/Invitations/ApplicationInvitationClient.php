<?php

namespace BWH\Auth\OAuth\Invitations;

use DateTimeImmutable;
use DateTimeZone;
use Illuminate\Contracts\Cache\Factory as CacheFactory;
use Illuminate\Contracts\Encryption\Encrypter;
use Illuminate\Http\Client\Factory;
use Illuminate\Http\Client\PendingRequest;
use Illuminate\Http\Client\Response;
use Illuminate\Support\Facades\Date;
use Lcobucci\JWT\Encoding\ChainedFormatter;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token\Builder;
use Psr\Http\Message\StreamInterface;
use SensitiveParameter;

/**
 * Calls the identity provider's application-requested admission invitation endpoints.
 *
 * Each call carries two credentials: a client credentials access token for this application's
 * own sign-in client (`bherila-auth.oauth_client`) with exactly the `invitations:admit` scope, and
 * an actor assertion, an RS256 JWS signed with this application's invitation key that names the
 * person asking and binds the exact URL and the exact body bytes sent. The token is reused until
 * shortly before it expires; an assertion is new for every request.
 *
 * Every request goes to a trusted HTTPS issuer (loopback HTTP only in local and testing), never
 * follows a redirect, and is bounded in connect time, total time and response size. Nothing is
 * retried except once when the provider refuses a reused token as `invalid_token`, which it does
 * before reading the assertion or changing anything. No failure carries a credential, the address,
 * the link, a response body or the transport's exception.
 *
 * The contract is docs/application-invitations.md.
 */
final class ApplicationInvitationClient implements ApplicationInvitations
{
    /** The only scope the token is requested with, and the only one the provider accepts here. */
    public const SCOPE = 'invitations:admit';

    public const ASSERTION_HEADER = 'Actor-Assertion';

    public const ASSERTION_TYPE = 'application-invitation+jwt';

    /** Seconds from `iat` to `exp`: the provider's maximum. */
    public const ASSERTION_LIFETIME = 60;

    public const PATH = '/api/application-invitations';

    /** The provider's subject form: a decimal string with no leading zeros. */
    private const SUBJECT = '/^[1-9][0-9]{0,19}$/D';

    /** A large invitation answer or error is well under 4 KiB; anything past this is not the contract. */
    private const RESPONSE_BYTES = 16_384;

    private const MAX_EMAIL_LENGTH = 255;

    private const MAX_LINK_LENGTH = 2048;

    private const MAX_TOKEN_LENGTH = 8192;

    /** A token is not reused within this many seconds of its expiry. */
    private const TOKEN_MARGIN = 30;

    private const EXPIRES_AT = '/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/D';

    /** @var array{key: string, token: string, expires: int}|null this process's token */
    private ?array $token = null;

    public function __construct(
        private readonly Factory $http,
        private readonly CacheFactory $cache,
        private readonly Encrypter $encrypter,
    ) {}

    public function create(string $actorSubject, #[SensitiveParameter] string $email): IssuedInvitation
    {
        self::requireSubject($actorSubject);
        if ($email === '' || ! mb_check_encoding($email, 'UTF-8') || mb_strlen($email) > self::MAX_EMAIL_LENGTH) {
            // Refused here, so with no provider status.
            throw new ApplicationInvitationInvalid(ApplicationInvitationError::InvalidRequest,
                errors: ['email' => ['The email must be a valid address of at most '.self::MAX_EMAIL_LENGTH.' characters.']]);
        }
        $body = json_encode(['email' => $email], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

        return $this->issued($this->call(self::PATH, $body, $actorSubject, 201), null);
    }

    public function resend(string $actorSubject, int $invitationId): IssuedInvitation
    {
        self::requireSubject($actorSubject);
        self::requireId($invitationId);

        return $this->issued($this->call(self::PATH.'/'.$invitationId.'/resend', '{}', $actorSubject, 200), $invitationId);
    }

    public function revoke(string $actorSubject, int $invitationId): RevokedInvitation
    {
        self::requireSubject($actorSubject);
        self::requireId($invitationId);

        $data = $this->call(self::PATH.'/'.$invitationId.'/revoke', '{}', $actorSubject, 200);
        $invitation = $data['invitation'] ?? null;
        if (! is_array($invitation) || ($invitation['id'] ?? null) !== $invitationId || ($invitation['status'] ?? null) !== 'revoked') {
            throw self::invalidResponse();
        }

        return new RevokedInvitation($invitationId, 'revoked');
    }

    /**
     * POST one body to one path and return the decoded success answer.
     *
     * @return array<mixed>
     *
     * @throws ApplicationInvitationException
     */
    private function call(string $path, #[SensitiveParameter] string $body, string $actorSubject, int $expectedStatus): array
    {
        $settings = $this->settings();
        $url = $settings['issuer'].$path;

        [$token, $reused] = $this->token($settings);
        [$status, $data, $retryAfter] = $this->post($settings, $url, $body, $token, $this->sign($settings, $actorSubject, $url, $body));
        // A reused token the provider no longer accepts (revoked, or its keys rotated) is refused
        // before the assertion is read or anything changes, so one retry with a new token is safe.
        if ($reused && $status === 401 && ApplicationInvitationError::fromProvider($status, $data['error'] ?? null) === ApplicationInvitationError::InvalidToken) {
            $this->forgetToken($settings);
            [$token] = $this->token($settings);
            [$status, $data, $retryAfter] = $this->post($settings, $url, $body, $token, $this->sign($settings, $actorSubject, $url, $body));
        }

        if ($status >= 200 && $status < 300) {
            if ($status !== $expectedStatus || $data === null) {
                throw self::invalidResponse();
            }

            return $data;
        }

        throw self::refusal($status, $data, $retryAfter);
    }

    /**
     * @param  array<mixed>  $data
     *
     * @throws ApplicationInvitationUnavailable
     */
    private function issued(array $data, ?int $expectedId): IssuedInvitation
    {
        $invitation = $data['invitation'] ?? null;
        if (! is_array($invitation)
            || ! is_int($id = $invitation['id'] ?? null) || $id < 1 || ($expectedId !== null && $id !== $expectedId)
            || ($invitation['status'] ?? null) !== 'pending'
            || ($expiresAt = self::expiresAt($invitation['expires_at'] ?? null)) === null
            || ! is_string($link = $invitation['link'] ?? null) || ! self::isLink($link)
            || ! is_bool($sent = $invitation['email_sent'] ?? null)) {
            throw self::invalidResponse();
        }

        return new IssuedInvitation($id, 'pending', $expiresAt, $link, $sent);
    }

    /**
     * The exception for a non-2xx answer: the provider's code when it is the contract's code for
     * that status, otherwise by status alone.
     *
     * @param  array<mixed>|null  $data
     */
    private static function refusal(int $status, ?array $data, ?int $retryAfter): ApplicationInvitationException
    {
        $error = ApplicationInvitationError::fromProvider($status, $data['error'] ?? null);
        if ($error === null) {
            // The framework's coarse per-address throttle answers 429 without a code.
            return ApplicationInvitationException::for(
                $status === 429 ? ApplicationInvitationError::RateLimited : ApplicationInvitationError::Unavailable,
                $status, $retryAfter,
            );
        }

        return ApplicationInvitationException::for($error, $status, $retryAfter,
            limit: is_string($data['limit'] ?? null) ? $data['limit'] : null,
            errors: $error === ApplicationInvitationError::InvalidRequest ? self::fieldErrors($data['errors'] ?? null) : [],
        );
    }

    /**
     * The provider's messages by field, bounded; anything not in that shape is dropped.
     *
     * @return array<string, list<string>>
     */
    private static function fieldErrors(mixed $errors): array
    {
        if (! is_array($errors)) {
            return [];
        }
        $fields = [];
        foreach (array_slice($errors, 0, 10, true) as $field => $messages) {
            if (! is_string($field) || strlen($field) > 64 || ! is_array($messages)) {
                continue;
            }
            $kept = array_values(array_filter(array_slice($messages, 0, 10),
                fn (mixed $message): bool => is_string($message) && strlen($message) <= 500));
            if ($kept !== []) {
                $fields[$field] = $kept;
            }
        }

        return $fields;
    }

    /**
     * Send one invitation request: the exact body, the token, and the assertion.
     *
     * @return array{0: int, 1: array<mixed>|null, 2: int|null} status, decoded JSON object (null when the body is not one), Retry-After
     *
     * @throws ApplicationInvitationUnavailable
     */
    private function post(#[SensitiveParameter] array $settings, string $url, #[SensitiveParameter] string $body, #[SensitiveParameter] string $token, #[SensitiveParameter] string $assertion): array
    {
        return $this->send($settings, fn (PendingRequest $request): Response => $request->withToken($token)->acceptJson()
            ->withHeaders([self::ASSERTION_HEADER => $assertion])
            ->withBody($body, 'application/json')
            ->send('POST', $url));
    }

    /**
     * A client credentials token with exactly the invitation scope, and whether it was reused.
     *
     * @return array{0: string, 1: bool}
     *
     * @throws ApplicationInvitationException
     */
    private function token(#[SensitiveParameter] array $settings): array
    {
        $now = Date::now()->getTimestamp();
        $key = $settings['token_cache_key'];
        if ($this->token !== null && $this->token['key'] === $key && $now < $this->token['expires'] - self::TOKEN_MARGIN) {
            return [$this->token['token'], true];
        }
        $cached = $this->cachedToken($settings, $now);
        if ($cached !== null) {
            $this->token = $cached;

            return [$cached['token'], true];
        }

        [$status, $data] = $this->send($settings, fn (PendingRequest $request): Response => $request->asForm()->acceptJson()->post(
            $settings['issuer'].$settings['token_path'], [
                'grant_type' => 'client_credentials',
                'client_id' => $settings['client_id'],
                'client_secret' => $settings['client_secret'],
                'scope' => self::SCOPE,
            ]));
        if ($status === 400 || $status === 401) {
            throw ApplicationInvitationException::for(ApplicationInvitationError::TokenRefused, $status);
        }
        if ($status !== 200) {
            throw ApplicationInvitationException::for(ApplicationInvitationError::Unavailable, $status);
        }
        $token = $data['access_token'] ?? null;
        $expiresIn = $data['expires_in'] ?? null;
        if (! is_string($token) || $token === '' || strlen($token) > self::MAX_TOKEN_LENGTH
            || preg_match('/^[\x21-\x7E]+$/D', $token) !== 1
            || ! is_string($type = $data['token_type'] ?? null) || strcasecmp($type, 'Bearer') !== 0
            || ! is_int($expiresIn) || $expiresIn < 1) {
            throw self::invalidResponse();
        }

        $this->token = ['key' => $key, 'token' => $token, 'expires' => $now + $expiresIn];
        $this->storeToken($settings, $this->token, $expiresIn - self::TOKEN_MARGIN);

        return [$token, false];
    }

    /** @return array{key: string, token: string, expires: int}|null */
    private function cachedToken(array $settings, int $now): ?array
    {
        if ($settings['token_cache_store'] === false) {
            return null;
        }
        try {
            $stored = $this->cache->store($settings['token_cache_store'])->get($settings['token_cache_key']);
            $token = is_string($stored) ? $this->encrypter->decryptString($stored) : null;
            $value = is_string($token) ? json_decode($token, true) : null;
        } catch (\Throwable) {
            return null;
        }
        if (! is_array($value) || ($value['key'] ?? null) !== $settings['token_cache_key']
            || ! is_string($value['token'] ?? null) || ! is_int($value['expires'] ?? null)
            || $now >= $value['expires'] - self::TOKEN_MARGIN) {
            return null;
        }

        return ['key' => $value['key'], 'token' => $value['token'], 'expires' => $value['expires']];
    }

    /** @param  array{key: string, token: string, expires: int}  $token */
    private function storeToken(array $settings, #[SensitiveParameter] array $token, int $seconds): void
    {
        if ($settings['token_cache_store'] === false || $seconds < 1) {
            return;
        }
        try {
            $this->cache->store($settings['token_cache_store'])->put($settings['token_cache_key'],
                $this->encrypter->encryptString(json_encode($token, JSON_THROW_ON_ERROR)), $seconds);
        } catch (\Throwable) {
            // The cache is an optimization; this process keeps its own copy.
        }
    }

    private function forgetToken(array $settings): void
    {
        $this->token = null;
        if ($settings['token_cache_store'] === false) {
            return;
        }
        try {
            $this->cache->store($settings['token_cache_store'])->forget($settings['token_cache_key']);
        } catch (\Throwable) {
        }
    }

    private function sign(#[SensitiveParameter] array $settings, string $actorSubject, string $url, #[SensitiveParameter] string $body): string
    {
        $now = Date::now()->getTimestamp();
        $issuedAt = new DateTimeImmutable('@'.$now);

        try {
            return Builder::new(new JoseEncoder, ChainedFormatter::withUnixTimestampDates())
                ->withHeader('typ', self::ASSERTION_TYPE)
                ->withHeader('kid', $settings['key_id'])
                ->issuedBy($settings['client_id'])
                ->relatedTo($actorSubject)
                ->permittedFor($url)
                ->issuedAt($issuedAt)
                ->expiresAt($issuedAt->modify('+'.self::ASSERTION_LIFETIME.' seconds'))
                ->identifiedBy(bin2hex(random_bytes(32)))
                ->withClaim('method', 'POST')
                ->withClaim('body_sha256', hash('sha256', $body))
                ->getToken(new Sha256, $settings['private_key'])
                ->toString();
        } catch (\Throwable) {
            throw self::notConfigured();
        }
    }

    /**
     * Run one bounded HTTP exchange and read its answer.
     *
     * @param  \Closure(PendingRequest): Response  $request  sends on the bounded request it is given
     * @return array{0: int, 1: array<mixed>|null, 2: int|null} status, decoded JSON object (null when the body is not one), Retry-After
     *
     * @throws ApplicationInvitationUnavailable
     */
    private function send(#[SensitiveParameter] array $settings, \Closure $request): array
    {
        $timeout = $settings['timeout_seconds'];
        $deadline = hrtime(true) + $timeout * 1_000_000_000;
        try {
            $response = $request($this->http->withoutRedirecting()
                ->connectTimeout(min(3, $timeout))->timeout($timeout)
                ->withOptions(['stream' => true, 'read_timeout' => min(5, $timeout)]));
        } catch (\Throwable) {
            // Transport exceptions may contain credentials, the address or response bodies.
            throw ApplicationInvitationException::for(ApplicationInvitationError::Unavailable);
        }

        $status = $response->status();
        $retryAfter = self::retryAfter($response->header('Retry-After'));
        $bytes = self::readBounded($response->toPsrResponse()->getBody(), $deadline);
        $data = $bytes === '' ? null : json_decode($bytes, true, 16, JSON_BIGINT_AS_STRING);

        return [$status, is_array($data) && ($data === [] || ! array_is_list($data)) ? $data : null, $retryAfter];
    }

    /**
     * Every setting a call needs, read and checked before anything is sent.
     *
     * @return array{issuer: string, token_path: string, client_id: string, client_secret: string, key_id: string, private_key: InMemory, timeout_seconds: int, token_cache_store: string|false|null, token_cache_key: string}
     *
     * @throws ApplicationInvitationMisconfigured
     */
    private function settings(): array
    {
        $client = config('bherila-auth.oauth_client');
        $invitations = config('bherila-auth.application_invitations');
        if (! is_array($client) || ! is_array($invitations)) {
            throw self::notConfigured();
        }
        $issuer = self::issuer($invitations['issuer'] ?? null ?: ($client['base_url'] ?? null));
        $tokenPath = $client['token_path'] ?? '/oauth/token';
        $clientId = $client['client_id'] ?? null;
        $secret = $client['client_secret'] ?? null;
        $keyId = $invitations['key_id'] ?? null;
        if (! is_string($tokenPath) || preg_match('#^/[A-Za-z0-9._~/-]*$#D', $tokenPath) !== 1
            || ! is_string($clientId) || trim($clientId) === ''
            || ! is_string($secret) || trim($secret) === ''
            || ! is_string($keyId) || trim($keyId) === '' || strlen($keyId) > 255) {
            throw self::notConfigured();
        }
        $timeout = $invitations['timeout_seconds'] ?? 10;
        $timeout = is_numeric($timeout) ? max(1, min(30, (int) $timeout)) : 10;
        $store = $invitations['token_cache_store'] ?? null;
        $store = $store === '' ? null : $store;
        if (! ($store === null || $store === false || is_string($store))) {
            throw self::notConfigured();
        }

        return [
            'issuer' => $issuer,
            'token_path' => $tokenPath,
            'client_id' => $clientId,
            'client_secret' => $secret,
            'key_id' => $keyId,
            'private_key' => self::privateKey($invitations),
            'timeout_seconds' => $timeout,
            'token_cache_store' => $store,
            // A rotated secret or another client or provider never reuses a token.
            'token_cache_key' => 'bherila-auth:application-invitations:token:'.hash('sha256', json_encode(
                [$issuer, $tokenPath, $clientId, hash('sha256', $secret), self::SCOPE], JSON_THROW_ON_ERROR)),
        ];
    }

    /**
     * The provider's issuer exactly as configured, without a trailing slash: the assertion's
     * audience must equal the provider's issuer and path byte for byte, so nothing is normalized.
     *
     * @throws ApplicationInvitationMisconfigured
     */
    private static function issuer(mixed $value): string
    {
        if (! is_string($value)) {
            throw self::notConfigured();
        }
        $url = rtrim($value, '/');
        $parts = parse_url($url);
        $scheme = is_array($parts) ? ($parts['scheme'] ?? '') : '';
        $local = $scheme === 'http' && in_array(config('app.env'), ['local', 'testing'], true)
            && in_array(strtolower($parts['host'] ?? ''), ['localhost', '127.0.0.1', '[::1]'], true);
        if ($url === '' || filter_var($url, FILTER_VALIDATE_URL) === false || ! is_array($parts)
            || (! $local && $scheme !== 'https')
            || isset($parts['user']) || isset($parts['pass']) || isset($parts['path'])
            || isset($parts['query']) || isset($parts['fragment'])) {
            throw self::notConfigured();
        }

        return $url;
    }

    /**
     * The RSA private key (at least 2048 bits) from exactly one of `private_key_path` and
     * `private_key`.
     *
     * @param  array<mixed>  $settings
     *
     * @throws ApplicationInvitationMisconfigured
     */
    private static function privateKey(array $settings): InMemory
    {
        $path = $settings['private_key_path'] ?? null;
        $pem = $settings['private_key'] ?? null;
        $passphrase = $settings['private_key_passphrase'] ?? null;
        $hasPath = is_string($path) && $path !== '';
        $hasPem = is_string($pem) && $pem !== '';
        if ($hasPath === $hasPem || ! ($passphrase === null || is_string($passphrase))) {
            throw self::notConfigured();
        }
        if ($hasPath) {
            $pem = is_file($path) && is_readable($path) ? @file_get_contents($path) : false;
            if (! is_string($pem) || $pem === '') {
                throw self::notConfigured();
            }
        }
        // An environment value may carry escaped newlines.
        $pem = str_contains($pem, '\n') && ! str_contains($pem, "\n") ? str_replace('\n', "\n", $pem) : $pem;
        $key = @openssl_pkey_get_private($pem, $passphrase ?? '');
        $details = $key === false ? false : openssl_pkey_get_details($key);
        if ($details === false || ($details['type'] ?? null) !== OPENSSL_KEYTYPE_RSA || ($details['bits'] ?? 0) < 2048) {
            throw self::notConfigured();
        }

        return InMemory::plainText($pem, $passphrase ?? '');
    }

    /** @throws \InvalidArgumentException */
    private static function requireSubject(string $subject): void
    {
        if (preg_match(self::SUBJECT, $subject) !== 1) {
            throw new \InvalidArgumentException('The actor subject must be a provider subject: a decimal string with no leading zeros.');
        }
    }

    /** @throws \InvalidArgumentException */
    private static function requireId(int $id): void
    {
        if ($id < 1) {
            throw new \InvalidArgumentException('The invitation id must be a positive integer.');
        }
    }

    private static function expiresAt(mixed $value): ?DateTimeImmutable
    {
        if (! is_string($value) || preg_match(self::EXPIRES_AT, $value) !== 1) {
            return null;
        }
        $parsed = DateTimeImmutable::createFromFormat('!Y-m-d\TH:i:s\Z', $value, new DateTimeZone('UTC'));
        // Rolled-over dates (2026-02-30) parse with a warning; they are not the provider's.
        $errors = DateTimeImmutable::getLastErrors();
        if ($parsed === false || ($errors !== false && ($errors['warning_count'] > 0 || $errors['error_count'] > 0))) {
            return null;
        }

        return $parsed;
    }

    /** An absolute HTTPS (or loopback HTTP, when the issuer is) URL with no credentials. */
    private static function isLink(string $link): bool
    {
        if ($link === '' || strlen($link) > self::MAX_LINK_LENGTH || filter_var($link, FILTER_VALIDATE_URL) === false) {
            return false;
        }
        $parts = parse_url($link);
        if (! is_array($parts) || isset($parts['user']) || isset($parts['pass']) || ! isset($parts['host'])) {
            return false;
        }

        return ($parts['scheme'] ?? null) === 'https'
            || (($parts['scheme'] ?? null) === 'http' && in_array(config('app.env'), ['local', 'testing'], true)
                && in_array(strtolower($parts['host']), ['localhost', '127.0.0.1', '[::1]'], true));
    }

    /** Delay-seconds only; an HTTP date or anything unreasonable is ignored. */
    private static function retryAfter(string $value): ?int
    {
        $value = trim($value);

        return $value !== '' && strlen($value) <= 5 && ctype_digit($value) ? (int) $value : null;
    }

    /**
     * Read at most one byte past the limit, and never past the deadline. The stream is always closed.
     *
     * @throws ApplicationInvitationUnavailable
     */
    private static function readBounded(StreamInterface $stream, int $deadline): string
    {
        try {
            $bytes = '';
            while (! $stream->eof() && strlen($bytes) <= self::RESPONSE_BYTES) {
                if (hrtime(true) >= $deadline) {
                    throw self::invalidResponse();
                }
                $chunk = $stream->read(min(4096, self::RESPONSE_BYTES + 1 - strlen($bytes)));
                if ($chunk === '' && ! $stream->eof()) {
                    throw self::invalidResponse();
                }
                $bytes .= $chunk;
            }
            if (hrtime(true) >= $deadline || strlen($bytes) > self::RESPONSE_BYTES) {
                throw self::invalidResponse();
            }
        } catch (\Throwable) {
            throw self::invalidResponse();
        } finally {
            $stream->close();
        }

        return $bytes;
    }

    private static function invalidResponse(): ApplicationInvitationException
    {
        return ApplicationInvitationException::for(ApplicationInvitationError::InvalidResponse);
    }

    private static function notConfigured(): ApplicationInvitationException
    {
        return ApplicationInvitationException::for(ApplicationInvitationError::NotConfigured);
    }
}
