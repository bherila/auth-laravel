<?php

namespace BWH\Auth\Http\Controllers;

use BWH\Auth\OAuth\Credentials\ApiCredentialService;
use DomainException;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Validation\Rule;
use Illuminate\Validation\ValidationException;

/**
 * The signed-in person's API tokens and OAuth apps, as JSON for the
 * credentials UI.
 *
 * Browser routes on purpose (session + CSRF), never API operations, so no
 * OAuth credential can mint another. Each new secret travels once, in the
 * body of the response that created it, marked no-store - never flashed to the
 * session (a readable row in the session store) nor put in page props
 * (persisted in browser history).
 */
final class ApiCredentialController extends Controller
{
    public function index(Request $request, ApiCredentialService $credentials): JsonResponse
    {
        $user = $this->user($request);
        $issuing = (bool) config('bherila-auth.oauth_server.enabled', false);
        // Only once the application opts personal tokens in to connection
        // scopes; until then the payload is exactly what it always was.
        $connections = $credentials->connectionScopesEnabled();

        return $this->noStore([
            'data' => [
                'scopes' => array_map(
                    static fn (string $id, string $description): array => ['id' => $id, 'description' => $description],
                    array_keys($credentials->grantableScopes()),
                    array_values($credentials->grantableScopes()),
                ),
                'token_lifetimes' => $credentials->lifetimes(),
                ...($connections ? [
                    // Offered to personal API tokens only, never to OAuth apps.
                    'token_connection_scopes' => array_map(
                        static fn (string $id, string $description): array => ['id' => $id, 'description' => $description],
                        array_keys($credentials->connectionScopes()),
                        array_values($credentials->connectionScopes()),
                    ),
                    // The lifetimes a token carrying one of those may have.
                    'connection_token_lifetimes' => $credentials->connectionLifetimes(),
                ] : []),
                // Null while the OAuth server is switched off: revocation stays available.
                'issue_token_href' => $issuing ? route('bherila-auth.credentials.tokens.store', absolute: false) : null,
                'register_app_href' => $issuing ? route('bherila-auth.credentials.apps.store', absolute: false) : null,
                'tokens' => array_map(static fn (array $token): array => [
                    ...$token,
                    ...($connections ? ['connection' => $credentials->carriesConnectionScope($token['scopes'])] : []),
                    'revoke_href' => route('bherila-auth.credentials.tokens.destroy', ['token' => $token['id']], absolute: false),
                ], $credentials->tokens($user)),
                'apps' => array_map(static fn (array $app): array => [
                    ...$app,
                    'delete_href' => route('bherila-auth.credentials.apps.destroy', ['client' => $app['id']], absolute: false),
                ], $credentials->apps($user)),
            ],
        ]);
    }

    public function storeToken(Request $request, ApiCredentialService $credentials): JsonResponse
    {
        $data = $request->validate([
            'name' => ['required', 'string', 'max:120'],
            'scopes' => ['required', 'array', 'min:1'],
            'scopes.*' => ['string', 'distinct', Rule::in(array_keys($credentials->tokenScopes()))],
            'lifetime' => ['required', 'string', Rule::in($credentials->lifetimes())],
        ]);
        $issued = $this->refusable(fn (): array => $credentials->issueToken(
            $this->user($request),
            (string) $data['name'],
            array_values($data['scopes']),
            (string) $data['lifetime'],
        ));

        return $this->noStore(['data' => [
            'kind' => 'token',
            'name' => trim((string) $data['name']),
            'token' => $issued['token'],
            'expires_at' => $issued['expires_at'],
        ]], 201);
    }

    public function destroyToken(Request $request, string $token, ApiCredentialService $credentials): JsonResponse
    {
        $credentials->revokeToken($this->user($request), $token);

        return $this->noStore(['data' => ['revoked' => true]]);
    }

    public function storeApp(Request $request, ApiCredentialService $credentials): JsonResponse
    {
        $data = $request->validate([
            'name' => ['required', 'string', 'max:120'],
            'redirect_uris' => ['required', 'array', 'min:1', 'max:10'],
            'redirect_uris.*' => ['required', 'string', 'max:2048', 'distinct'],
            'confidential' => ['required', 'boolean'],
            'scopes' => ['required', 'array', 'min:1'],
            'scopes.*' => ['string', 'distinct', Rule::in(array_keys($credentials->grantableScopes()))],
        ]);
        $registered = $this->refusable(fn (): array => $credentials->registerApp(
            $this->user($request),
            (string) $data['name'],
            array_values($data['redirect_uris']),
            (bool) $data['confidential'],
            array_values($data['scopes']),
        ));

        return $this->noStore(['data' => [
            'kind' => 'app',
            'name' => trim((string) $data['name']),
            'client_id' => (string) $registered['client']->getKey(),
            'client_secret' => $registered['secret'],
        ]], 201);
    }

    public function destroyApp(Request $request, string $client, ApiCredentialService $credentials): JsonResponse
    {
        $credentials->deleteApp($this->user($request), $client);

        return $this->noStore(['data' => ['deleted' => true]]);
    }

    private function user(Request $request): Authenticatable
    {
        $user = $request->user();
        abort_unless($user instanceof Authenticatable, 401);

        return $user;
    }

    /**
     * @template T
     *
     * @param  callable(): T  $action
     * @return T
     */
    private function refusable(callable $action): mixed
    {
        try {
            return $action();
        } catch (DomainException $refused) {
            throw ValidationException::withMessages(['credential' => $refused->getMessage()]);
        }
    }

    /** @param array<string, mixed> $payload */
    private function noStore(array $payload, int $status = 200): JsonResponse
    {
        return response()->json($payload, $status, ['Cache-Control' => 'no-store', 'Pragma' => 'no-cache']);
    }
}
