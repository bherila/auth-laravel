<?php

namespace BWH\Auth\Tests\Feature;

use BWH\Auth\OAuth\AuthenticationRequirement;
use BWH\Auth\OAuth\IdentityNamespaceResolver;
use BWH\Auth\OAuth\OAuthCallbackFailure;
use BWH\Auth\OAuth\OAuthCallbackRejected;
use BWH\Auth\OAuth\OAuthClient;
use BWH\Auth\OAuth\OAuthIdentity;
use BWH\Auth\OAuth\Session\AuthenticationContext;
use BWH\Auth\Tests\TestCase;
use Illuminate\Auth\GenericUser;
use Illuminate\Cache\FileStore;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Cache\Store as CacheStore;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use Mockery;
use PHPUnit\Framework\Attributes\DataProvider;
use RuntimeException;
use Symfony\Component\HttpKernel\Exception\HttpExceptionInterface;
use Throwable;

/** Real file/database cache semantics; file-cache races use independent OS processes. */
class OAuthPendingFlowAdmissionTest extends TestCase
{
    private string $directory;

    protected function setUp(): void
    {
        parent::setUp();
        $this->directory = sys_get_temp_dir().'/oauth-admission-'.bin2hex(random_bytes(8));
        mkdir($this->directory, 0700);
        config([
            'cache.stores.named-flows' => ['driver' => 'file', 'path' => $this->directory.'/cache', 'lock_path' => $this->directory.'/locks'],
            'bherila-auth.oauth_client.pending_flow_cache_store' => 'named-flows',
            'bherila-auth.oauth_client.pending_flow_ttl' => 60,
            'bherila-auth.oauth_client.servers.records' => [
                'issuer' => 'https://authorization.example.test', 'client_id' => 'synthetic-client',
                'client_secret' => 'synthetic-secret', 'redirect_uri' => 'https://client.example.test/connect/records/callback',
                'scope' => 'records:read', 'authorization_response_iss' => 'required',
            ],
        ]);
        Http::fake(['https://authorization.example.test/oauth/token' => Http::response(['token_type' => 'Bearer', 'access_token' => 'synthetic-access'])]);
    }

    protected function tearDown(): void
    {
        $this->app['files']->deleteDirectory($this->directory);
        parent::tearDown();
    }

    public static function cacheDrivers(): array
    {
        return [['file'], ['database']];
    }

    #[DataProvider('cacheDrivers')]
    public function test_ten_across_sessions_refuses_without_evicting_and_consumption_frees_one_slot(string $driver): void
    {
        $this->driver($driver);
        $states = [];
        for ($i = 0; $i < 10; $i++) {
            $states[] = $this->start(); // A different browser session every time.
        }
        $this->assertHttp(429, fn () => $this->start());
        foreach ($states as $state) {
            $this->assertIsArray(Cache::store('named-flows')->get($this->stateKey($state)));
        }
        $this->assertSame('synthetic-access', $this->consume($states[0]));
        $replacement = $this->start();
        $this->assertHttp(429, fn () => $this->start());
        // A different user and named server have independent finite budgets.
        $this->assertIsString($this->start(user: 8));
        config(['bherila-auth.oauth_client.servers.other' => [
            ...config('bherila-auth.oauth_client.servers.records'),
            'redirect_uri' => 'https://client.example.test/connect/other/callback',
        ]]);
        $this->assertIsString($this->start(server: 'other'));
        foreach ([...array_slice($states, 1), $replacement] as $state) {
            $this->assertSame('synthetic-access', $this->consume($state));
        }
        Http::assertSentCount(11);
    }

    #[DataProvider('cacheDrivers')]
    public function test_expired_or_lost_reservations_never_reacquire_or_release_a_reused_slot(string $driver): void
    {
        $this->driver($driver);
        config(['bherila-auth.oauth_client.pending_flow_max_active' => 1, 'bherila-auth.oauth_client.pending_flow_ttl' => 2]);
        $old = $this->start();
        $binding = Cache::store('named-flows')->get($this->stateKey($old));
        Cache::store('named-flows')->put($this->stateKey($old), $binding, 120);
        $this->travel(3)->seconds();
        $current = $this->start(); // Reuses the expired slot under another owner.
        $this->assertRejected($old, OAuthCallbackFailure::StateMismatch);
        $this->assertHttp(429, fn () => $this->start());
        $this->assertSame('synthetic-access', $this->consume($current));
        $lost = $this->start();
        $binding = Cache::store('named-flows')->get($this->stateKey($lost));
        Cache::store('named-flows')->getStore()->restoreLock($this->slotKey($binding), hash('sha256', $lost))->forceRelease();
        $this->assertRejected($lost, OAuthCallbackFailure::StateMismatch);
        $this->assertNull(Cache::store('named-flows')->get($this->stateKey($lost)));
        Http::assertSentCount(1);
    }

    public function test_parallel_file_cache_starts_cannot_exceed_the_limit(): void
    {
        config(['bherila-auth.oauth_client.pending_flow_max_active' => 2]);
        $results = $this->parallel(8, fn (): string => $this->start());
        $this->assertSame(2, count(array_filter($results, static fn (array $result): bool => $result['status'] === 200)));
        $this->assertSame(6, count(array_filter($results, static fn (array $result): bool => $result['status'] === 429)));
        foreach ($results as $result) {
            if ($result['status'] === 200) {
                $this->assertSame('synthetic-access', $this->consume($result['value']));
            }
        }
        Http::assertSentCount(2);
    }

    public function test_parallel_file_cache_callbacks_exchange_only_once(): void
    {
        $state = $this->start();
        $audit = $this->directory.'/exchanges';
        Http::fake(function () use ($audit) {
            file_put_contents($audit, "exchange\n", FILE_APPEND | LOCK_EX);

            return Http::response(['token_type' => 'Bearer', 'access_token' => 'synthetic-access']);
        });
        $results = $this->parallel(6, fn (): string => $this->consume($state));
        $this->assertSame(1, count(array_filter($results, static fn (array $result): bool => $result['status'] === 200)));
        $this->assertSame(5, count(array_filter($results, static fn (array $result): bool => $result['status'] === 403)));
        $this->assertSame("exchange\n", file_get_contents($audit));
    }

    public function test_equal_ids_in_configured_realms_have_separate_admission_and_cannot_complete_each_others_flow(): void
    {
        $this->realms();
        config(['bherila-auth.oauth_client.pending_flow_max_active' => 1]);
        $a = $this->start(realm: 'guard:web:tenant:a');
        $b = $this->start(realm: 'guard:admin:tenant:b');
        $this->assertHttp(429, fn () => $this->start(realm: 'guard:web:tenant:a'));
        $this->assertRejected($a, OAuthCallbackFailure::UserMismatch, realm: 'guard:admin:tenant:b');
        $this->assertRejected($a, OAuthCallbackFailure::StateMismatch, realm: 'guard:web:tenant:a');
        $this->assertSame('synthetic-access', $this->consume($b, realm: 'guard:admin:tenant:b'));
        Http::assertSentCount(1);
    }

    public function test_legacy_pending_flows_are_accepted_only_in_the_explicit_legacy_realm(): void
    {
        $legacy = $this->legacyFlow();
        $this->assertSame('synthetic-access', $this->consume($legacy));
        $other = $this->legacyFlow();
        config(['bherila-auth.oauth_client.identity_namespace' => 'guard:web:tenant:a']);
        $this->assertRejected($other, OAuthCallbackFailure::UserMismatch);
        $this->assertRejected($other, OAuthCallbackFailure::StateMismatch);
        Http::assertSentCount(1);
    }

    public function test_recent_authentication_cannot_cross_realms_with_the_same_local_id(): void
    {
        $this->realms();
        $request = $this->request(realm: 'guard:web:tenant:a');
        $identity = new OAuthIdentity('synthetic', 'subject', 'Synthetic', 'user@example.test', authTime: now()->getTimestamp(), amr: ['pwd']);
        $account = $request->user();
        $requirement = new AuthenticationRequirement(maxAge: 60);
        AuthenticationContext::remember($request, $identity, $account);
        $this->assertTrue(AuthenticationContext::satisfies($request, $account, $requirement));
        $request->attributes->set('trusted_realm', 'guard:admin:tenant:b');
        $this->assertFalse(AuthenticationContext::satisfies($request, $account, $requirement));
        $legacy = $request->session()->get(AuthenticationContext::SESSION_KEY);
        unset($legacy['identity_namespace']);
        $request->session()->put(AuthenticationContext::SESSION_KEY, $legacy);
        $this->assertFalse(AuthenticationContext::satisfies($request, $account, $requirement));
        $request->attributes->set('trusted_realm', 'legacy');
        $this->assertTrue(AuthenticationContext::satisfies($request, $account, $requirement));
    }

    public function test_unsupported_store_and_invalid_configuration_fail_with_fixed_outages(): void
    {
        $store = Mockery::mock(CacheStore::class);
        $store->shouldNotReceive('put', 'get', 'forever');
        Cache::extend('unlocked', fn () => Cache::repository($store));
        config(['cache.stores.unlocked' => ['driver' => 'unlocked'], 'bherila-auth.oauth_client.pending_flow_cache_store' => 'unlocked']);
        $this->assertHttp(503, fn () => $this->start());
        config(['bherila-auth.oauth_client.pending_flow_cache_store' => 'named-flows']);
        foreach ([0, -1, '10', false] as $limit) {
            config(['bherila-auth.oauth_client.pending_flow_max_active' => $limit]);
            $this->assertHttp(503, fn () => $this->start());
        }
        config(['bherila-auth.oauth_client.pending_flow_max_active' => 10, 'bherila-auth.oauth_client.identity_namespace' => 'untrusted realm']);
        $this->assertHttp(503, fn () => $this->start());
        Http::assertNothingSent();
    }

    public function test_a_cache_failure_after_state_consumption_cannot_replay_or_exchange(): void
    {
        $store = new class($this->app['files'], $this->directory.'/failing') extends FileStore
        {
            public function restoreLock($name, $owner)
            {
                throw new RuntimeException('synthetic-private-cache-key');
            }
        };
        Cache::extend('failing-file', fn () => Cache::repository($store));
        config(['cache.stores.failing-file' => ['driver' => 'failing-file'], 'bherila-auth.oauth_client.pending_flow_cache_store' => 'failing-file']);
        $state = $this->start();
        $this->assertHttp(503, fn () => $this->consume($state));
        $this->assertRejected($state, OAuthCallbackFailure::StateMismatch);
        Http::assertNothingSent();
    }

    public static function ambiguousPublicationFailures(): array
    {
        return [['throw'], ['false']];
    }

    #[DataProvider('ambiguousPublicationFailures')]
    public function test_ambiguous_publication_keeps_its_reservation_until_expiry(string $failure): void
    {
        $store = new class($this->app['files'], $this->directory.'/ambiguous') extends FileStore
        {
            public array $published = [];

            public bool $returnFalse = false;

            public function add($key, $value, $seconds)
            {
                $stored = parent::add($key, $value, $seconds);
                if ($stored && str_starts_with($key, 'bherila-auth:oauth-client:pending-flow:') && ! str_ends_with($key, ':consume')) {
                    $this->published[] = $key;
                    if ($this->returnFalse) {
                        return false;
                    }
                    throw new RuntimeException('synthetic-private-publication-error');
                }

                return $stored;
            }

            public function forget($key)
            {
                if (str_starts_with($key, 'bherila-auth:oauth-client:pending-flow:') && ! str_ends_with($key, ':consume')) {
                    return false;
                }

                return parent::forget($key);
            }
        };
        $store->returnFalse = $failure === 'false';
        Cache::extend('ambiguous-file', fn () => Cache::repository($store));
        config([
            'cache.stores.ambiguous-file' => ['driver' => 'ambiguous-file'],
            'bherila-auth.oauth_client.pending_flow_cache_store' => 'ambiguous-file',
            'bherila-auth.oauth_client.pending_flow_max_active' => 1,
        ]);
        $this->assertHttp(503, fn () => $this->start());
        $this->assertHttp(429, fn () => $this->start());
        $this->assertCount(1, $store->published);
        $this->travel(61)->seconds();
        $this->assertHttp(503, fn () => $this->start());
        $this->assertCount(2, $store->published);
        Http::assertNothingSent();
    }

    public function test_an_add_collision_never_evicts_the_existing_valid_flow(): void
    {
        config(['bherila-auth.oauth_client.pending_flow_max_active' => 2]);
        $state = $this->start();
        $original = Cache::store('named-flows')->get($this->stateKey($state));
        Str::createRandomStringsUsing(static fn (int $length): string => $length === 40 ? $state : str_repeat('x', $length));
        try {
            $this->assertHttp(503, fn () => $this->start());
        } finally {
            Str::createRandomStringsNormally();
        }
        $this->assertTrue($original === Cache::store('named-flows')->get($this->stateKey($state)));
        $this->assertSame('synthetic-access', $this->consume($state));
        Http::assertSentCount(1);
    }

    public static function transactionalCacheConnections(): array
    {
        return [['state'], ['lock']];
    }

    #[DataProvider('transactionalCacheConnections')]
    public function test_database_cache_cannot_participate_in_an_application_transaction(string $part): void
    {
        $this->driver('database');
        $connection = DB::connection('testing');
        if ($part === 'lock') {
            config(['database.connections.pending-locks' => ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '']]);
            Schema::connection('pending-locks')->create('synthetic_pending_locks', function (Blueprint $table): void {
                $table->string('key')->primary();
                $table->string('owner');
                $table->integer('expiration');
            });
            config(['cache.stores.named-flows.lock_connection' => 'pending-locks']);
            Cache::purge('named-flows');
            $connection = DB::connection('pending-locks');
        }
        $state = $this->start();
        $connection->beginTransaction();
        try {
            $this->assertHttp(503, fn () => $this->start());
            $this->assertHttp(503, fn () => $this->consume($state));
            Http::assertNothingSent();
        } finally {
            $connection->rollBack();
        }
        // The refusal happened before a durable claim, so the caller can finish
        // outside the transaction exactly once; a rollback cannot revive it.
        $this->assertSame('synthetic-access', $this->consume($state));
        $this->assertRejected($state, OAuthCallbackFailure::StateMismatch);
        Http::assertSentCount(1);
    }

    private function driver(string $driver): void
    {
        if ($driver !== 'database') {
            return;
        }
        foreach (['synthetic_pending_cache', 'synthetic_pending_locks'] as $table) {
            Schema::create($table, function (Blueprint $blueprint) use ($table): void {
                $blueprint->string('key')->primary();
                if ($table === 'synthetic_pending_cache') {
                    $blueprint->text('value');
                } else {
                    $blueprint->string('owner');
                }
                $blueprint->integer('expiration');
            });
        }
        config(['cache.stores.named-flows' => [
            'driver' => 'database', 'connection' => 'testing', 'table' => 'synthetic_pending_cache',
            'lock_connection' => 'testing', 'lock_table' => 'synthetic_pending_locks',
        ]]);
        Cache::purge('named-flows');
    }

    private function realms(): void
    {
        $this->app->instance(IdentityNamespaceResolver::class, new class implements IdentityNamespaceResolver
        {
            public function resolve(Request $request, Authenticatable $account): string
            {
                return $request->attributes->get('trusted_realm');
            }
        });
    }

    private function request(int $user = 7, string $realm = 'legacy', string $server = 'records', ?string $state = null): Request
    {
        $request = Request::create('https://client.example.test/connect/'.$server.($state === null ? '' : '/callback'), 'GET', $state === null ? [] : [
            'state' => $state, 'code' => 'synthetic-code', 'iss' => 'https://authorization.example.test',
        ]);
        $session = new Store('synthetic-session', new ArraySessionHandler(120));
        $session->start();
        $request->setLaravelSession($session);
        $request->setUserResolver(fn () => new GenericUser(['id' => $user]));
        $request->attributes->set('trusted_realm', $realm);

        return $request;
    }

    private function start(int $user = 7, string $realm = 'legacy', string $server = 'records'): string
    {
        $response = app(OAuthClient::class)->forServer($server)->redirect($this->request($user, $realm, $server));
        parse_str(parse_url($response->getTargetUrl(), PHP_URL_QUERY), $query);

        return $query['state'];
    }

    private function consume(string $state, string $realm = 'legacy'): string
    {
        return app(OAuthClient::class)->forServer('records')->tokensFromCallback($this->request(realm: $realm, state: $state))->accessToken;
    }

    private function legacyFlow(): string
    {
        $state = $this->start();
        $cache = Cache::store('named-flows');
        $binding = $cache->get($this->stateKey($state));
        $this->assertTrue($cache->getStore()->restoreLock($this->slotKey($binding), hash('sha256', $state))->release());
        unset($binding['identity_namespace'], $binding['admission_slot'], $binding['expires_at']);
        $cache->put($this->stateKey($state), $binding, 60);

        return $state;
    }

    private function assertRejected(string $state, OAuthCallbackFailure $reason, string $realm = 'legacy'): void
    {
        try {
            $this->consume($state, $realm);
            $this->fail('A rejected named flow was accepted.');
        } catch (OAuthCallbackRejected $rejected) {
            $this->assertSame($reason, $rejected->reason);
        }
    }

    private function assertHttp(int $status, callable $operation): void
    {
        try {
            $operation();
            $this->fail('The named flow was not refused.');
        } catch (HttpExceptionInterface $failure) {
            $this->assertSame($status, $failure->getStatusCode());
            $this->assertStringNotContainsString('synthetic-private', $failure->getMessage());
        }
    }

    private function stateKey(string $state): string
    {
        return 'bherila-auth:oauth-client:pending-flow:'.hash('sha256', $state);
    }

    private function slotKey(array $binding): string
    {
        return 'bherila-auth:oauth-client:pending-slot:'.hash('sha256', serialize([
            $binding['identity_namespace'], $binding['user'], $binding['server'],
        ])).':'.$binding['admission_slot'];
    }

    /** @return list<array{status: int|string, value?: string}> */
    private function parallel(int $count, callable $operation): array
    {
        $this->assertTrue(function_exists('pcntl_fork'), 'This cache race regression requires pcntl (installed in CI).');
        $barrier = $this->directory.'/barrier-'.bin2hex(random_bytes(4));
        $children = [];
        for ($i = 0; $i < $count; $i++) {
            $pair = stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, STREAM_IPPROTO_IP);
            $pid = pcntl_fork();
            if ($pid === 0) {
                fclose($pair[0]);
                while (! is_file($barrier)) {
                    usleep(1000);
                }
                try {
                    $result = ['status' => 200, 'value' => $operation()];
                } catch (HttpExceptionInterface $failure) {
                    $result = ['status' => $failure->getStatusCode()];
                } catch (Throwable) {
                    $result = ['status' => 'unexpected'];
                }
                fwrite($pair[1], json_encode($result, JSON_THROW_ON_ERROR));
                fclose($pair[1]);
                exit(0);
            }
            $this->assertGreaterThan(0, $pid);
            fclose($pair[1]);
            stream_set_timeout($pair[0], 10);
            $children[] = [$pid, $pair[0]];
        }
        file_put_contents($barrier, 'go');
        $results = [];
        foreach ($children as [$pid, $stream]) {
            $results[] = json_decode(stream_get_contents($stream), true, flags: JSON_THROW_ON_ERROR);
            fclose($stream);
            pcntl_waitpid($pid, $status);
            $this->assertSame(0, pcntl_wexitstatus($status));
        }

        return $results;
    }
}
