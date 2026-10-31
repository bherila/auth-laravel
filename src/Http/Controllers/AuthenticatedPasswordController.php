<?php

namespace BWH\Auth\Http\Controllers;

use BWH\Auth\Contracts\AuthAuditLogger;
use BWH\Auth\Contracts\LocalCredentialPolicy;
use BWH\Auth\Mail\PasswordResetNoticeMail;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Mail;
use Illuminate\Validation\Rules\Password as PasswordRule;

class AuthenticatedPasswordController extends Controller
{
    public function __construct(private readonly AuthAuditLogger $auditLogger) {}

    public function update(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'current_password' => ['required', 'string'],
            'password' => ['required', 'confirmed', PasswordRule::defaults()],
        ]);

        $user = $request->user();

        if (! $user instanceof Authenticatable) {
            return response()->json(['message' => 'Unauthenticated.'], 401);
        }

        if (! app(LocalCredentialPolicy::class)->mayUseLocalCredentials($user, $request)) {
            return response()->json(['message' => __('This account signs in through single sign-on.')], 403);
        }

        if (! Hash::check($validated['current_password'], $user->getAuthPassword())) {
            return response()->json([
                'message' => 'The current password is incorrect.',
                'errors' => [
                    'current_password' => ['The current password is incorrect.'],
                ],
            ], 422);
        }

        $attributes = [
            'password' => Hash::make($validated['password']),
        ];

        $forceChangeAttribute = config('bherila-auth.users.force_change_password_attribute');
        if (is_string($forceChangeAttribute) && $forceChangeAttribute !== '' && $this->modelHasColumn($user, $forceChangeAttribute)) {
            $attributes[$forceChangeAttribute] = false;
        }

        $user->forceFill($attributes)->save();

        $appName = config('app.name', 'Application');
        $emailAttribute = config('bherila-auth.users.email_attribute', 'email');
        $email = data_get($user, $emailAttribute);

        if ($email) {
            Mail::to($email)->send(new PasswordResetNoticeMail($user, $appName));
        }

        $this->auditLogger->passwordChanged($request, $user);

        return response()->json([
            'success' => true,
            'message' => 'Password changed successfully.',
        ]);
    }

    private function modelHasColumn(Authenticatable $user, string $column): bool
    {
        return $user instanceof Model
            && $user->getConnection()->getSchemaBuilder()->hasColumn($user->getTable(), $column);
    }
}
