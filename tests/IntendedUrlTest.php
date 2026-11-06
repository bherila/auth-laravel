<?php

namespace BWH\Auth\Tests;

use BWH\Auth\Services\DefaultAuthUserPolicy;
use BWH\Auth\Support\IntendedUrl;
use Illuminate\Auth\GenericUser;
use Illuminate\Http\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

class IntendedUrlTest extends TestCase
{
    #[DataProvider('destinations')]
    public function test_same_origin_validation_preserves_paths_queries_and_fragments(string $origin, string $value, ?string $local, ?string $strictLocal): void
    {
        $request = Request::create($origin.'/login');
        $this->assertSame($local, IntendedUrl::sameSite($request, $value, absolute: false));
        $this->assertSame($local === null ? null : $origin.$local, IntendedUrl::sameSite($request, $value));
        $this->assertSame($strictLocal, IntendedUrl::sameSite($request, $value, absolute: false, rejectEncodedUnsafe: true));
    }

    /** @return iterable<string, array{string, string, ?string, ?string}> */
    public static function destinations(): iterable
    {
        $origin = 'https://app.example.test';
        foreach ([
            '/' => '/',
            '/events/12?tab=people#attendees' => '/events/12?tab=people#attendees',
            '/media/a%2Fb?return=%2Fevents#part%2Ftwo' => '/media/a%2Fb?return=%2Fevents#part%2Ftwo',
            '/search?q=a+b&nested=https%3A%2F%2Fother.example.test' => '/search?q=a+b&nested=https%3A%2F%2Fother.example.test',
            '/people/%E2%98%83' => '/people/%E2%98%83',
            $origin => '/',
            $origin.'?view=grid#first' => '/?view=grid#first',
            $origin.'#first' => '/#first',
            'HTTPS://APP.EXAMPLE.TEST:443/events?x=1#second' => '/events?x=1#second',
            $origin.'/feed' => '/feed',
            'https://other.example.test/' => null,
            'http://app.example.test/' => null,
            'https://app.example.test:444/' => null,
            'https://app.example.test.evil.example/' => null,
            'https://app.example.test@other.example.test/' => null,
            'https://someone@app.example.test/' => null,
            'https://:password@app.example.test/' => null,
            '//app.example.test/path' => null,
            '//other.example.test/' => null,
            '/\\other.example.test/' => null,
            "/safe\ttail" => null,
            ' /feed' => null,
            '/feed ' => null,
            'feed' => null,
            '?view=grid' => '/?view=grid',
            '#first' => '/#first',
            'javascript:alert(1)' => null,
            'https:/app.example.test/' => null,
            'https://app.example.test:99999/' => null,
            '' => null,
            '/'.str_repeat('a', 2048) => null,
        ] as $value => $local) {
            yield $value === '' ? 'empty' : $value => [$origin, $value, $local, $local];
        }
        // Existing callers permit encoded characters, including multi-scope OAuth queries.
        // Consumers with a stricter stored-destination policy can opt into one-decode checks.
        foreach (['/%2fother.example.test/', '/%2F%2fother.example.test/', '/%5cother.example.test/',
            '/safe%0d%0aLocation%3Aother', '/safe%00tail', '/safe%7Ftail', '/hello%20world',
            '/search?q=hello%20world', '/oauth/authorize?scope=identity%3Aread%20profile%3Aread', '/feed#hello%20world'] as $value) {
            yield $value => [$origin, $value, $value, null];
        }
        yield 'http explicit default port' => ['http://app.example.test', 'HTTP://APP.EXAMPLE.TEST:80/events', '/events', '/events'];
        yield 'nondefault port matches' => ['https://app.example.test:8443', 'https://APP.EXAMPLE.TEST:8443/events', '/events', '/events'];
        yield 'nondefault port omitted' => ['https://app.example.test:8443', 'https://app.example.test/events', null, null];
        yield 'ipv6 same origin' => ['http://[::1]:8000', 'http://[::1]:8000/events', '/events', '/events'];
    }

    public function test_consume_revalidates_and_removes_every_stored_value_once(): void
    {
        $request = $this->request();
        foreach (['https://other.example.test/', '/%2Fother.example.test', ['unexpected'], null] as $value) {
            $request->session()->put('url.intended', $value);
            $this->assertNull(IntendedUrl::consume($request, rejectEncodedUnsafe: true));
            $this->assertFalse($request->session()->exists('url.intended'));
        }
        $request->session()->put('url.intended', 'https://APP.EXAMPLE.TEST:443/events#details');
        $this->assertSame('/events#details', IntendedUrl::consume($request, absolute: false));
        $this->assertNull(IntendedUrl::consume($request));
    }

    public function test_remember_and_default_policy_share_validation_and_consume_the_result(): void
    {
        $request = $this->request();
        $request->query->set('redirect', '/events?tab=people');
        IntendedUrl::remember($request);
        $this->assertSame('https://app.example.test/events?tab=people', $request->session()->get('url.intended'));
        $policy = new DefaultAuthUserPolicy;
        $user = new GenericUser(['id' => 1]);
        $this->assertSame('https://app.example.test/events?tab=people', $policy->redirectAfterLogin($user, $request));
        $this->assertSame('/', $policy->redirectAfterLogin($user, $request));

        $request->session()->put('url.intended', '/events');
        $request->query->set('redirect', '//other.example.test');
        IntendedUrl::remember($request);
        $this->assertSame('/events', $request->session()->get('url.intended'));
        $request->session()->put('url.intended', 'https://other.example.test/');
        $this->assertSame('/', $policy->redirectAfterLogin($user, $request));
    }

    private function request(): Request
    {
        $request = Request::create('https://app.example.test/login');
        $request->setLaravelSession(new Store('test', new ArraySessionHandler(120)));

        return $request;
    }
}
