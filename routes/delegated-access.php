<?php

use BWH\Auth\Http\Controllers\DelegatedAccessController;
use Illuminate\Support\Facades\Route;

// Called by the identity provider's server, never by a browser: no `web` group, so no session,
// CSRF or cookies, and no API-token fallback. The controller verifies the signed, single-use actor
// assertion before anything else, and answers 404 until `bherila-auth.delegated_access.enabled`.
Route::post(config('bherila-auth.delegated_access.path', '/application-access'), DelegatedAccessController::class)
    ->middleware('throttle:bherila-auth-delegated-access')
    ->name('bherila-auth.delegated-access');
