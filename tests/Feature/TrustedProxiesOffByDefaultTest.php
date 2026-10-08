<?php

namespace BWH\Auth\Tests\Feature;

use BWH\Auth\Tests\TestCase;
use Illuminate\Http\Middleware\TrustProxies;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

/** Upgrading the package changes nothing until an application opts in. */
class TrustedProxiesOffByDefaultTest extends TestCase
{
    protected function tearDown(): void
    {
        TrustProxies::flushState();
        parent::tearDown();
    }

    public function test_forwarded_headers_are_ignored_until_the_application_opts_in(): void
    {
        Route::get('/whoami', fn (Request $request) => response()->json(['ip' => $request->ip()]));

        $this->withServerVariables(['REMOTE_ADDR' => '104.16.1.2', 'HTTP_X_FORWARDED_FOR' => '198.51.100.7'])
            ->getJson('/whoami')->assertOk()->assertJsonPath('ip', '104.16.1.2');
    }
}
