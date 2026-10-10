<?php

namespace BWH\Auth\OAuth\Reconciliation;

use Illuminate\Http\Client\Factory;

/**
 * One request to the identity provider's reconciliation API, authenticated with this
 * application's static OAuth client credential.
 *
 * Shared by every client of that API so they cannot drift apart on the parts that
 * protect the credential: the endpoint is fixed beneath a trusted HTTPS base URL
 * (loopback HTTP only in local/testing), redirects are never followed, connect and
 * total time are bounded, the body is streamed and abandoned past a size limit, and
 * no failure carries transport details. Callers own the shape of what they accept.
 *
 * @internal
 */
final readonly class ReconciliationTransport
{
    public function __construct(private Factory $http) {}

    /**
     * Send one request and return its decoded JSON value, unvalidated beyond being an array.
     *
     * Settings are read in a fixed order (base URL, client id, client secret, provider) so a
     * misconfiguration always reports the same failure, and before anything is sent.
     *
     * @param  'GET'|'POST'|'PUT'  $method
     * @param  string  $path  a fixed path beneath the base URL, beginning with `/`
     * @param  array<string, scalar>  $query
     * @param  array<string, mixed>|null  $json  a JSON body, or null to send none
     * @return array<mixed>
     *
     * @throws ReconciliationFailure
     */
    public function send(string $method, string $path, array $query, ?array $json, int $maxBytes, int $timeoutSeconds): array
    {
        $base = $this->baseUrl();
        $client = $this->setting('client_id');
        $secret = $this->setting('client_secret');
        $this->setting('provider');
        $deadline = hrtime(true) + $timeoutSeconds * 1_000_000_000;

        $options = [];
        if ($json !== null) {
            $options['json'] = $json;
        } elseif ($query !== []) {
            $options['query'] = $query;
        }

        try {
            $pending = $this->http->acceptJson()
                ->withBasicAuth($client, $secret)
                ->withoutRedirecting()->connectTimeout(min(3, $timeoutSeconds))->timeout($timeoutSeconds)
                ->withOptions(['stream' => true, 'read_timeout' => 1]);
            $response = ($json !== null ? $pending->asJson() : $pending)->send($method, $base.$path, $options);
        } catch (\Throwable) {
            // Transport exceptions may contain credentials or response bodies.
            throw new ReconciliationFailure(ReconciliationFailure::UNAVAILABLE);
        }

        if (! $response->successful()) {
            $status = $response->status();
            $retryAfter = self::retryAfter($response->header('Retry-After'));
            $response->close();
            throw new ReconciliationFailure(ReconciliationFailure::UNAVAILABLE, $status, $retryAfter);
        }

        $bytes = self::readBounded($response->toPsrResponse()->getBody(), $maxBytes, $deadline);
        $data = json_decode($bytes, true, 16, JSON_BIGINT_AS_STRING);
        if (! is_array($data)) {
            throw new ReconciliationFailure(ReconciliationFailure::INVALID);
        }

        return $data;
    }

    /**
     * The configured provider base URL without a trailing slash, its scheme lower-cased.
     *
     * @throws ReconciliationFailure
     */
    public function baseUrl(): string
    {
        $url = rtrim($this->setting('base_url'), '/');
        $parts = parse_url($url);
        $scheme = strtolower($parts['scheme'] ?? '');
        $local = is_array($parts) && $scheme === 'http'
            && in_array(config('app.env'), ['local', 'testing'], true)
            && in_array(strtolower($parts['host'] ?? ''), ['localhost', '127.0.0.1', '[::1]'], true);
        if (filter_var($url, FILTER_VALIDATE_URL) === false || ! is_array($parts)
            || (! $local && $scheme !== 'https')
            || isset($parts['user']) || isset($parts['pass'])
            || isset($parts['query']) || isset($parts['fragment'])) {
            throw new ReconciliationFailure(ReconciliationFailure::UNTRUSTED_URL);
        }

        return $scheme.substr($url, strlen($parts['scheme']));
    }

    /**
     * A non-empty `bherila-auth.oauth_client.*` string.
     *
     * @throws ReconciliationFailure
     */
    public function setting(string $key): string
    {
        $value = config('bherila-auth.oauth_client.'.$key);
        if (! is_string($value) || trim($value) === '') {
            throw new ReconciliationFailure(ReconciliationFailure::NOT_CONFIGURED);
        }

        return $value;
    }

    /**
     * A digest of the configured provider and client, for pinning state (cached checks,
     * stored cursors) to the credential that produced it.
     *
     * @throws ReconciliationFailure
     */
    public function context(): string
    {
        return hash('sha256', json_encode([
            $this->baseUrl(), $this->setting('provider'), $this->setting('client_id'),
        ], JSON_THROW_ON_ERROR));
    }

    /**
     * Read at most one byte past the limit, and never past the deadline, so neither an
     * oversized nor a trickling body is ever materialized. The stream is always closed.
     */
    private static function readBounded(\Psr\Http\Message\StreamInterface $stream, int $maxBytes, int $deadline): string
    {
        try {
            $bytes = '';
            while (! $stream->eof() && strlen($bytes) <= $maxBytes) {
                if (hrtime(true) >= $deadline) {
                    throw new ReconciliationFailure(ReconciliationFailure::INVALID);
                }
                $chunk = $stream->read(min(4096, $maxBytes + 1 - strlen($bytes)));
                if ($chunk === '' && ! $stream->eof()) {
                    throw new ReconciliationFailure(ReconciliationFailure::INVALID);
                }
                $bytes .= $chunk;
            }
            if (hrtime(true) >= $deadline || strlen($bytes) > $maxBytes) {
                throw new ReconciliationFailure(ReconciliationFailure::INVALID);
            }
        } catch (\Throwable) {
            throw new ReconciliationFailure(ReconciliationFailure::INVALID);
        } finally {
            $stream->close();
        }

        return $bytes;
    }

    /** Delay-seconds only; an HTTP date or anything unreasonable is ignored. */
    private static function retryAfter(string $value): ?int
    {
        $value = trim($value);

        return $value !== '' && strlen($value) <= 5 && ctype_digit($value) ? (int) $value : null;
    }
}
