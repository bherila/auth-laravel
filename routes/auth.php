<?php

use BWH\Auth\Http\Controllers\AuthenticatedPasswordController;
use BWH\Auth\Http\Controllers\PasswordResetController;
use BWH\Auth\Http\Controllers\TwoFactorController;
use BWH\Auth\Http\Middleware\RequireActiveUser;
use BWH\Auth\Support\TwoFactorRoutes;
use Illuminate\Support\Facades\Route;

if (config('bherila-auth.routes.password_resets', true)) {
    Route::post('/auth/forgot-password', [PasswordResetController::class, 'sendResetLink']);
    Route::post('/auth/reset-password', [PasswordResetController::class, 'reset']);
}

if (config('bherila-auth.routes.change_password', true)) {
    // RequireActiveUser as well as `auth`: changing the credential that grants access is
    // a login-adjacent action, so it answers to the same canLogin() gate every login does.
    Route::middleware(['auth', RequireActiveUser::class])->post('/change-password', [AuthenticatedPasswordController::class, 'update']);
}

if (config('bherila-auth.routes.two_factor', true)) {
    Route::post('/auth/two-factor/verify', [TwoFactorController::class, 'verify']);
    Route::post('/auth/two-factor/resend', [TwoFactorController::class, 'resend']);
    Route::get('/auth/two-factor/confirm/{token}', [TwoFactorController::class, 'confirm'])->name(TwoFactorRoutes::name('confirm'));
    Route::post('/auth/two-factor/confirm/{token}', [TwoFactorController::class, 'confirmSubmit'])->name(TwoFactorRoutes::name('confirm.submit'));
    Route::get('/auth/two-factor/report/{token}', [TwoFactorController::class, 'report'])->name(TwoFactorRoutes::name('report'));
    Route::post('/auth/two-factor/report/{token}', [TwoFactorController::class, 'reportSubmit'])->name(TwoFactorRoutes::name('report.submit'));
}
