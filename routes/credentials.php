<?php

use BWH\Auth\Http\Controllers\ApiCredentialController;
use BWH\Auth\Http\Middleware\EnsureOAuthServerEnabled;
use Illuminate\Support\Facades\Route;

// A signed-in person's REST credentials. Session routes only: no OAuth
// credential can mint another. Issuing answers to the OAuth server's kill
// switch; listing and revoking stay available during an incident.
Route::get('/', [ApiCredentialController::class, 'index'])->name('bherila-auth.credentials.index');
Route::post('/tokens', [ApiCredentialController::class, 'storeToken'])
    ->middleware([EnsureOAuthServerEnabled::class, 'throttle:10,1'])->name('bherila-auth.credentials.tokens.store');
Route::delete('/tokens/{token}', [ApiCredentialController::class, 'destroyToken'])->name('bherila-auth.credentials.tokens.destroy');
Route::post('/apps', [ApiCredentialController::class, 'storeApp'])
    ->middleware([EnsureOAuthServerEnabled::class, 'throttle:10,1'])->name('bherila-auth.credentials.apps.store');
Route::delete('/apps/{client}', [ApiCredentialController::class, 'destroyApp'])->name('bherila-auth.credentials.apps.destroy');
