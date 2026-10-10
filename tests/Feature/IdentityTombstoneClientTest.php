<?php

namespace BWH\Auth\Tests\Feature;

use BWH\Auth\OAuth\Lifecycle\IdentityTombstone;
use BWH\Auth\OAuth\Lifecycle\IdentityTombstoneClient;
use BWH\Auth\OAuth\Lifecycle\IdentityTombstoneFeedUnavailable;
use BWH\Auth\Tests\TestCase;
use DateTimeImmutable;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;
use PHPUnit\Framework\Attributes\DataProvider;

class IdentityTombstoneClientTest extends TestCase
{
    private const ID = '648b1f85-9192-4eb2-943d-734c5f5fd817';

    protected function setUp(): void
    {
        parent::setUp();
        config(['app.env' => 'testing']);
        config(['bherila-auth.oauth_client' => [
            'provider' => 'example-provider',
            'base_url' => 'https://identity.example.test',
            'client_id' => 'example-client',
            'client_secret' => 'example-secret',
        ]]);
        Http::preventStrayRequests();
    }

    public static function item(array $override = []): array
    {
        return array_replace([
            'id' => self::ID,
            'subject' => '42',
            'tombstoned_at' => '2026-08-26T12:00:00.000000Z',
            'purge_after' => '2026-09-25T12:00:00.000000Z',
            'provider_purged_at' => null,
        ], $override);
    }

    public static function page(array $override = []): array
    {
        return array_replace(['contract_version' => 1, 'data' => [self::item()], 'has_more' => false, 'next_cursor' => null], $override);
    }

    private function client(): IdentityTombstoneClient
    {
        return app(IdentityTombstoneClient::class);
    }

    public function test_a_page_is_read_with_basic_auth_and_the_cursor_passed_unchanged(): void
    {
        $sent = [];
        Http::fake(function (Request $request, array $options) use (&$sent) {
            $sent[] = [$request, $options];

            return Http::response(self::page(['data' => [self::item(['provider_purged_at' => '2026-09-25T13:00:00+02:00'])], 'has_more' => true, 'next_cursor' => 'opaque+/=']));
        });

        $page = $this->client()->page('cursor a/b+c', 25);

        [$request, $options] = $sent[0];
        $this->assertSame('GET', $request->method());
        $this->assertSame('https://identity.example.test/api/reconciliation/identity-tombstones?limit=25&cursor=cursor%20a%2Fb%2Bc', $request->url());
        $this->assertSame(['Basic '.base64_encode('example-client:example-secret')], $request->header('Authorization'));
        $this->assertFalse($options['allow_redirects']);
        $this->assertTrue($options['stream']);
        $this->assertTrue($page->hasMore);
        $this->assertSame('opaque+/=', $page->nextCursor);
        $tombstone = $page->tombstones[0];
        $this->assertSame([self::ID, 'example-provider', '42'], [$tombstone->id, $tombstone->provider, $tombstone->subject]);
        $this->assertSame('2026-08-26T12:00:00+00:00', $tombstone->tombstonedAt->format(DATE_ATOM));
        $this->assertSame('2026-09-25T11:00:00+00:00', $tombstone->providerPurgedAt?->format(DATE_ATOM));
    }

    public function test_the_first_page_carries_no_cursor(): void
    {
        Http::fake(['*' => Http::response(self::page(['data' => []]))]);

        $this->assertSame([], $this->client()->page()->tombstones);

        Http::assertSent(fn (Request $request): bool => $request->url() === 'https://identity.example.test/api/reconciliation/identity-tombstones?limit=100');
    }

    #[DataProvider('malformedPages')]
    public function test_malformed_pages_are_refused_whole(array $payload): void
    {
        Http::fake(['*' => Http::response($payload)]);

        $this->expectExceptionObject(new IdentityTombstoneFeedUnavailable(IdentityTombstoneFeedUnavailable::INVALID, 'The identity tombstone response is invalid.'));
        $this->client()->page(null, 2);
    }

    public static function malformedPages(): array
    {
        return [
            'wrong version' => [self::page(['contract_version' => 2])],
            'string version' => [self::page(['contract_version' => '1'])],
            'data not a list' => [self::page(['data' => ['a' => self::item()]])],
            'data missing' => [array_diff_key(self::page(), ['data' => true])],
            'data null' => [self::page(['data' => null])],
            'data scalar' => [self::page(['data' => 'none'])],
            'more items than asked for' => [self::page(['data' => [self::item(), self::item(['id' => 'a48b1f85-9192-4eb2-943d-734c5f5fd817']), self::item(['id' => 'b48b1f85-9192-4eb2-943d-734c5f5fd817'])]])],
            'has_more missing' => [array_diff_key(self::page(), ['has_more' => true])],
            'next_cursor missing' => [array_diff_key(self::page(), ['next_cursor' => true])],
            'more without a cursor' => [self::page(['has_more' => true])],
            'empty cursor' => [self::page(['has_more' => true, 'next_cursor' => ''])],
            'oversized cursor' => [self::page(['has_more' => true, 'next_cursor' => str_repeat('c', 513)])],
            'cursor without more' => [self::page(['next_cursor' => 'opaque'])],
            'duplicate ids' => [self::page(['data' => [self::item(), self::item(['id' => strtoupper(self::ID)])]])],
            'id not a uuid' => [self::page(['data' => [self::item(['id' => '../../oauth/token'])]])],
            'numeric subject' => [self::page(['data' => [self::item(['subject' => 42])]])],
            'empty subject' => [self::page(['data' => [self::item(['subject' => ''])]])],
            'oversized subject' => [self::page(['data' => [self::item(['subject' => str_repeat('s', 256)])]])],
            'date without offset' => [self::page(['data' => [self::item(['tombstoned_at' => '2026-08-26 12:00:00'])]])],
            'impossible date' => [self::page(['data' => [self::item(['purge_after' => '2026-02-30T12:00:00Z'])]])],
            'purged_at missing' => [self::page(['data' => [array_diff_key(self::item(), ['provider_purged_at' => true])]])],
            'purged_at not a date' => [self::page(['data' => [self::item(['provider_purged_at' => 'yesterday'])]])],
            'item not an object' => [self::page(['data' => ['42']])],
            'not an object' => [['contract_version', 1]],
        ];
    }

    public function test_a_body_that_is_not_json_is_invalid(): void
    {
        Http::fake(['*' => Http::response('<html>example-secret</html>')]);

        try {
            $this->client()->page();
            $this->fail('A non-JSON page must be refused.');
        } catch (IdentityTombstoneFeedUnavailable $exception) {
            $this->assertSame(IdentityTombstoneFeedUnavailable::INVALID, $exception->reason);
            $this->assertStringNotContainsString('example-secret', $exception->getMessage());
        }
    }

    public function test_an_oversized_page_is_abandoned_after_its_limit(): void
    {
        $stream = new class(\GuzzleHttp\Psr7\Utils::streamFor(str_repeat(' ', 1_000_000))) implements \Psr\Http\Message\StreamInterface {
            use \GuzzleHttp\Psr7\StreamDecoratorTrait;

            public int $bytesRead = 0;

            public bool $closed = false;

            public function read(int $length): string
            {
                $bytes = $this->stream->read($length);
                $this->bytesRead += strlen($bytes);

                return $bytes;
            }

            public function getContents(): string
            {
                throw new \LogicException('The entire body must not be materialized.');
            }

            public function close(): void
            {
                $this->closed = true;
                $this->stream->close();
            }
        };
        Http::fake(fn () => Http::response($stream));

        try {
            $this->client()->page();
            $this->fail('An oversized page must be refused.');
        } catch (IdentityTombstoneFeedUnavailable $exception) {
            $this->assertSame(IdentityTombstoneFeedUnavailable::INVALID, $exception->reason);
            $this->assertSame(262_145, $stream->bytesRead);
            $this->assertTrue($stream->closed);
        }
    }

    public function test_a_redirect_is_not_followed(): void
    {
        Http::fake(['*' => Http::response('', 302, ['Location' => 'https://other.example.test/collect'])]);

        try {
            $this->client()->page();
            $this->fail('A redirect must not be followed.');
        } catch (IdentityTombstoneFeedUnavailable $exception) {
            $this->assertSame(IdentityTombstoneFeedUnavailable::UNAVAILABLE, $exception->reason);
        }
        Http::assertSentCount(1);
    }

    #[DataProvider('untrustedBaseUrls')]
    public function test_untrusted_base_urls_never_receive_the_credential(string $url): void
    {
        Http::fake();
        config(['bherila-auth.oauth_client.base_url' => $url]);

        try {
            $this->client()->page();
            $this->fail('An untrusted base URL must be refused.');
        } catch (IdentityTombstoneFeedUnavailable $exception) {
            $this->assertSame(IdentityTombstoneFeedUnavailable::UNTRUSTED_URL, $exception->reason);
        }
        Http::assertNothingSent();
    }

    public static function untrustedBaseUrls(): array
    {
        return [['http://identity.example.test'], ['https://user:pass@identity.example.test'],
            ['https://identity.example.test?x=1'], ['https://identity.example.test#f'], ['ftp://identity.example.test']];
    }

    public function test_loopback_http_is_refused_outside_local_and_testing(): void
    {
        Http::fake();
        config(['app.env' => 'production', 'bherila-auth.oauth_client.base_url' => 'http://localhost']);

        $this->expectException(IdentityTombstoneFeedUnavailable::class);
        try {
            $this->client()->page();
        } finally {
            Http::assertNothingSent();
        }
    }

    public function test_a_missing_secret_is_not_configured_and_sends_nothing(): void
    {
        Http::fake();
        config(['bherila-auth.oauth_client.client_secret' => null]);

        try {
            $this->client()->page();
            $this->fail('A missing secret must be refused.');
        } catch (IdentityTombstoneFeedUnavailable $exception) {
            $this->assertSame(IdentityTombstoneFeedUnavailable::NOT_CONFIGURED, $exception->reason);
        }
        Http::assertNothingSent();
    }

    public function test_transport_failures_do_not_carry_details(): void
    {
        Http::fake(['*' => Http::failedConnection('example-secret')]);

        try {
            $this->client()->page();
            $this->fail('A transport failure must be unavailable.');
        } catch (IdentityTombstoneFeedUnavailable $exception) {
            $this->assertSame(IdentityTombstoneFeedUnavailable::UNAVAILABLE, $exception->reason);
            $this->assertStringNotContainsString('example-secret', $exception->getMessage());
            $this->assertStringNotContainsString('example-client', $exception->getMessage());
            $this->assertNull($exception->getPrevious());
        }
    }

    public function test_throttling_carries_the_providers_delay(): void
    {
        Http::fake(['*' => Http::response(['message' => 'Too Many Attempts.'], 429, ['Retry-After' => '17'])]);

        try {
            $this->client()->page();
            $this->fail('A throttled read must fail.');
        } catch (IdentityTombstoneFeedUnavailable $exception) {
            $this->assertSame(IdentityTombstoneFeedUnavailable::THROTTLED, $exception->reason);
            $this->assertSame(17, $exception->retryAfter);
        }
    }

    public function test_a_refused_cursor_is_distinguished_from_other_validation_failures(): void
    {
        Http::fake(['*' => Http::response(['message' => 'The cursor is invalid.'], 422)]);

        try {
            $this->client()->page('stale');
            $this->fail('A refused cursor must fail.');
        } catch (IdentityTombstoneFeedUnavailable $exception) {
            $this->assertSame(IdentityTombstoneFeedUnavailable::CURSOR_REJECTED, $exception->reason);
        }

        try {
            $this->client()->page();
            $this->fail('A 422 without a cursor must fail.');
        } catch (IdentityTombstoneFeedUnavailable $exception) {
            $this->assertSame(IdentityTombstoneFeedUnavailable::UNAVAILABLE, $exception->reason);
        }
    }

    public function test_acknowledgement_is_a_put_beneath_the_tombstone_and_validated(): void
    {
        Http::fake(['*' => Http::response(['contract_version' => 1, 'acknowledgement' => ['tombstone_id' => self::ID, 'acknowledged_at' => '2026-08-27T00:00:00.000000Z']])]);

        $this->client()->acknowledge($this->tombstone());

        Http::assertSent(fn (Request $request): bool => $request->method() === 'PUT'
            && $request->url() === 'https://identity.example.test/api/reconciliation/identity-tombstones/'.self::ID.'/acknowledgement'
            && $request->header('Authorization') === ['Basic '.base64_encode('example-client:example-secret')]);
    }

    public function test_an_acknowledgement_naming_the_same_tombstone_in_another_case_is_accepted(): void
    {
        Http::fake(['*' => Http::response(['contract_version' => 1, 'acknowledgement' => ['tombstone_id' => self::ID, 'acknowledged_at' => '2026-08-27T00:00:00Z']])]);

        $this->client()->acknowledge($this->tombstone(strtoupper(self::ID)));

        Http::assertSentCount(1);
    }

    #[DataProvider('malformedAcknowledgements')]
    public function test_an_unconfirmed_acknowledgement_fails(array $payload): void
    {
        Http::fake(['*' => Http::response($payload)]);

        $this->expectException(IdentityTombstoneFeedUnavailable::class);
        $this->client()->acknowledge($this->tombstone());
    }

    public static function malformedAcknowledgements(): array
    {
        return [
            'wrong version' => [['contract_version' => 2, 'acknowledgement' => ['tombstone_id' => self::ID, 'acknowledged_at' => '2026-08-27T00:00:00Z']]],
            'no acknowledgement' => [['contract_version' => 1]],
            'no time' => [['contract_version' => 1, 'acknowledgement' => ['tombstone_id' => self::ID, 'acknowledged_at' => null]]],
            'another tombstone' => [['contract_version' => 1, 'acknowledgement' => ['tombstone_id' => 'a48b1f85-9192-4eb2-943d-734c5f5fd817', 'acknowledged_at' => '2026-08-27T00:00:00Z']]],
        ];
    }

    public function test_an_acknowledgement_for_a_tombstone_no_longer_assigned_is_gone(): void
    {
        Http::fake(['*' => Http::response(['message' => 'Not Found.'], 404)]);

        try {
            $this->client()->acknowledge($this->tombstone());
            $this->fail('A 404 acknowledgement must fail.');
        } catch (IdentityTombstoneFeedUnavailable $exception) {
            $this->assertSame(IdentityTombstoneFeedUnavailable::GONE, $exception->reason);
        }

        try {
            $this->client()->page();
            $this->fail('A 404 read must fail.');
        } catch (IdentityTombstoneFeedUnavailable $exception) {
            $this->assertSame(IdentityTombstoneFeedUnavailable::UNAVAILABLE, $exception->reason, 'Only an acknowledgement can be gone');
        }
    }

    public function test_an_id_that_is_not_a_uuid_is_never_sent(): void
    {
        Http::fake();

        $this->expectException(\InvalidArgumentException::class);
        try {
            $this->client()->acknowledge($this->tombstone('x/../../oauth/token'));
        } finally {
            Http::assertNothingSent();
        }
    }

    public function test_context_matches_the_status_clients(): void
    {
        $this->assertSame(app(\BWH\Auth\OAuth\Session\ProviderIdentityStatusClient::class)->context(), $this->client()->context());
    }

    private function tombstone(string $id = self::ID): IdentityTombstone
    {
        $at = new DateTimeImmutable('2026-08-26T12:00:00Z');

        return new IdentityTombstone($id, 'example-provider', '42', $at, $at, null);
    }
}
