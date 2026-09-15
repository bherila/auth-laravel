<?php

use BWH\Auth\Http\Controllers\DelegatedAccessController;
use Illuminate\Support\Facades\Route;

// Called by the identity provider's server, never by a browser: no `web` group, so no session,
// CSRF or cookies, and no API-token fallback. The controller answers 404 until
// `bherila-auth.delegated_access.enabled`, then applies its rate limit and verifies the signed,
// single-use actor assertion before anything else. The limit lives in the controller, not in
// throttle middleware, so a disabled endpoint never answers 429.
Route::post(config('bherila-auth.delegated_access.path', '/application-access'), DelegatedAccessController::class)
    ->name('bherila-auth.delegated-access');
