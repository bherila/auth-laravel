<?php

use BWH\Auth\Http\Controllers\ApiCredentialController;
use BWH\Auth\Http\Middleware\EnsureOAuthServerEnabled;
use BWH\Auth\Support\RateLimits;
use Illuminate\Support\Facades\Route;

// A signed-in person's REST credentials. Session routes only: no OAuth
// credential can mint another. Issuing answers to the OAuth server's kill
// switch; listing and revoking stay available during an incident. Issuing has its own
// named limiter, so it no longer shares one unprefixed bucket with the application's throttles.
Route::get('/', [ApiCredentialController::class, 'index'])->name('bherila-auth.credentials.index');
Route::post('/tokens', [ApiCredentialController::class, 'storeToken'])
    ->middleware([EnsureOAuthServerEnabled::class, RateLimits::middleware(RateLimits::CREDENTIALS)])->name('bherila-auth.credentials.tokens.store');
Route::delete('/tokens/{token}', [ApiCredentialController::class, 'destroyToken'])->name('bherila-auth.credentials.tokens.destroy');
Route::post('/apps', [ApiCredentialController::class, 'storeApp'])
    ->middleware([EnsureOAuthServerEnabled::class, RateLimits::middleware(RateLimits::CREDENTIALS)])->name('bherila-auth.credentials.apps.store');
Route::delete('/apps/{client}', [ApiCredentialController::class, 'destroyApp'])->name('bherila-auth.credentials.apps.destroy');
// The OAuth clients holding the person's live grants, dynamic clients included.
Route::get('/connections', [ApiCredentialController::class, 'connections'])->name('bherila-auth.credentials.connections.index');
Route::delete('/connections/{client}', [ApiCredentialController::class, 'destroyConnection'])->name('bherila-auth.credentials.connections.destroy');
