<?php

namespace BWH\Auth\Http\Controllers;

use BWH\Auth\Contracts\LocalCredentialPolicy;
use BWH\Auth\Http\Middleware\RequirePasswordConfirmation;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\ValidationException;
use RuntimeException;

/**
 * `POST {prefix}/auth/confirm-password`: records a fresh password confirmation for this
 * session, which {@see RequirePasswordConfirmation} checks (passkey enrollment, by default).
 *
 * Writes Laravel's standard `auth.password_confirmed_at`, so `password.confirm` middleware on
 * the application's own routes accepts the same confirmation.
 */
class PasswordConfirmationController extends Controller
{
    public function store(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'password' => ['required', 'string', 'max:1024'],
        ]);

        $user = $request->user();

        if (! $user instanceof Authenticatable) {
            return response()->json(['message' => 'Unauthenticated.'], 401);
        }

        // An account that may not use a local password cannot prove anything with one.
        if (! app(LocalCredentialPolicy::class)->mayUseLocalCredentials($user, $request)) {
            return response()->json(['message' => __('This account signs in through single sign-on.')], 403);
        }

        if (! $this->matches($validated['password'], $user->getAuthPassword())) {
            throw ValidationException::withMessages([
                'password' => [__('The provided password is incorrect.')],
            ]);
        }

        $request->session()->passwordConfirmed();

        return response()->json([
            'success' => true,
            'message' => 'Password confirmed.',
            'expires_in' => RequirePasswordConfirmation::timeout(),
        ]);
    }

    private function matches(string $password, mixed $hash): bool
    {
        if (! is_string($hash) || $hash === '') {
            return false;
        }

        try {
            return Hash::check($password, $hash);
        } catch (RuntimeException) {
            // A stored hash from another algorithm, with hashing.verify on.
            return false;
        }
    }
}
