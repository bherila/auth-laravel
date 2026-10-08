<?php

namespace BWH\Auth\Http\Middleware;

use BWH\Auth\OAuth\Server\DynamicClientRegistrationValidator;
use BWH\Auth\OAuth\Server\OAuthAuthorizationStateStore;
use BWH\Auth\OAuth\Server\OAuthAuthorizationResponseIssuer;
use BWH\Auth\OAuth\Server\OAuthResourceIndicator;
use Closure;
use Illuminate\Http\Exceptions\HttpResponseException;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Collection;
use Laravel\Passport\Passport;
use Symfony\Component\HttpFoundation\Response;

final class EnforceOAuthResourceIndicator
{
    public function __construct(
        private readonly OAuthAuthorizationStateStore $authorizationState,
    ) {}

    public function handle(Request $request, Closure $next): Response
    {
        if ($request->isMethod('GET') && $request->routeIs('passport.authorizations.authorize')) {
            return $this->authorizationRequest($request, $next);
        }

        if ($request->routeIs('passport.authorizations.approve', 'passport.authorizations.deny')) {
            return $this->consentSubmission($request, $next);
        }

        if ($request->routeIs('passport.token') && OAuthResourceIndicator::requestNamesResource($request)) {
            if (! OAuthResourceIndicator::isConfiguredResource(OAuthResourceIndicator::requestResource($request))) {
                return $this->invalidResource();
            }
            $request->attributes->set(
                OAuthResourceIndicator::REQUEST_ATTRIBUTE,
                OAuthResourceIndicator::configuredCanonical(),
            );
        }

        return $next($request);
    }

    private function authorizationRequest(Request $request, Closure $next): Response
    {
        $scopeInput = $request->query('scope');
        if ($scopeInput === null) {
            $scopes = Passport::defaultScopes();
        } elseif (is_string($scopeInput)) {
            $scopes = DynamicClientRegistrationValidator::parseScopes($scopeInput);
            if ($scopes === []) {
                // Passport treats an empty query value as if the parameter were
                // omitted and silently applies its default scopes. Reject it so
                // the application has an explicit, predictable empty-scope
                // policy instead of accidentally issuing a protected token.
                return $this->invalidScope($request);
            }
        } else {
            return $this->invalidScope($request);
        }
        $knownScopes = $this->configuredScopes();
        if (array_diff($scopes, $knownScopes) !== []) {
            return $this->invalidScope($request);
        }
        if (! $this->clientAllows($request->query('client_id'), $scopes)) {
            return $this->invalidScope($request);
        }

        // An omitted resource stands for the configured one only when the
        // application opted in; otherwise it stays omitted.
        $hasResource = $request->query->has('resource') || OAuthResourceIndicator::assumesOmittedResource();
        $resource = $request->query->has('resource')
            ? $request->query('resource')
            : ($hasResource ? OAuthResourceIndicator::configuredCanonical() : null);
        if (($hasResource && ! OAuthResourceIndicator::isConfiguredResource($resource))
            || (! $hasResource && OAuthResourceIndicator::scopesRequireResource($scopes))) {
            return $this->invalidResource($request);
        }
        if ($hasResource) {
            $request->attributes->set(
                OAuthResourceIndicator::REQUEST_ATTRIBUTE,
                OAuthResourceIndicator::configuredCanonical(),
            );
        }

        $previousAuthToken = $this->authorizationState->currentApprovalToken();
        try {
            $response = $next($request);
        } catch (HttpResponseException $exception) {
            $currentAuthToken = $this->authorizationState->currentApprovalToken();
            if ($currentAuthToken !== null
                && ($previousAuthToken === null || ! hash_equals($previousAuthToken, $currentAuthToken))) {
                $this->authorizationState->forgetResource($currentAuthToken);
            }

            return OAuthAuthorizationResponseIssuer::decorate(
                $this->noStore($exception->getResponse()),
            );
        }
        $authToken = $this->authorizationState->currentApprovalToken();
        if (is_string($authToken)
            && ($previousAuthToken === null || ! hash_equals($previousAuthToken, $authToken))
            && $resource !== null) {
            $this->authorizationState->rememberResource(
                $authToken,
                OAuthResourceIndicator::configuredCanonical(),
            );
        }
        if ($previousAuthToken !== null
            && ($authToken === null || ! hash_equals($previousAuthToken, $authToken))) {
            $this->authorizationState->forgetResource($previousAuthToken);
        }

        return OAuthAuthorizationResponseIssuer::decorate($this->noStore($response));
    }

    private function consentSubmission(Request $request, Closure $next): Response
    {
        $authToken = $request->input('auth_token');
        $resource = is_string($authToken) ? $this->authorizationState->resourceFor($authToken) : null;
        if (is_string($resource)) {
            $request->attributes->set(OAuthResourceIndicator::REQUEST_ATTRIBUTE, $resource);
        }

        try {
            return OAuthAuthorizationResponseIssuer::decorate(
                $this->noStore($next($request)),
            );
        } catch (HttpResponseException $exception) {
            return OAuthAuthorizationResponseIssuer::decorate(
                $this->noStore($exception->getResponse()),
            );
        } finally {
            if (is_string($authToken)
                && $this->authorizationState->currentApprovalToken() !== $authToken) {
                $this->authorizationState->forgetResource($authToken);
            }
        }
    }

    /** @param list<string> $scopes */
    private function clientAllows(mixed $clientId, array $scopes): bool
    {
        if (! is_string($clientId)) {
            return true;
        }

        $client = Passport::client()->newQuery()->find($clientId);
        if ($client === null) {
            return true;
        }
        $registeredAtColumn = config('bherila-auth.oauth_server.dynamic_clients.registered_at_column');
        $dynamic = is_string($registeredAtColumn) && $client->getAttribute($registeredAtColumn) !== null;
        $scopesColumn = config('bherila-auth.oauth_server.dynamic_clients.scopes_column');
        $hasScopesColumn = is_string($scopesColumn) && $scopesColumn !== '';
        $registeredScopes = $hasScopesColumn ? $client->getAttribute($scopesColumn) : null;

        if (! $dynamic) {
            // A client a person or the application registered. When it was
            // given a scope ceiling, consent is held to it too: otherwise the
            // person is asked to approve permissions the client was never
            // registered for, even though Passport later drops them from the
            // token. A client without stored scopes keeps the whole catalog.
            if ($registeredScopes === null) {
                return true;
            }
        } elseif (! $hasScopesColumn || $registeredScopes === null) {
            // Self-registrations created before scope persistence was enabled
            // are ambiguous; fail closed instead of treating them as unrestricted.
            return false;
        }
        if (is_string($registeredScopes)) {
            $decoded = json_decode($registeredScopes, true);
            $registeredScopes = is_array($decoded)
                ? $decoded
                : DynamicClientRegistrationValidator::parseScopes($registeredScopes);
        }
        if ($registeredScopes instanceof Collection) {
            $registeredScopes = $registeredScopes->all();
        }
        if (! is_array($registeredScopes)) {
            return false;
        }
        $allowedScopes = OAuthResourceIndicator::scopeIdentifiers($registeredScopes);

        return array_diff($scopes, $allowedScopes) === [];
    }

    /** @return list<string> */
    private function configuredScopes(): array
    {
        $scopes = config('bherila-auth.oauth_server.scopes', []);
        if (! is_array($scopes)) {
            return [];
        }

        return OAuthResourceIndicator::scopeIdentifiers(
            array_is_list($scopes) ? $scopes : array_keys($scopes),
        );
    }

    private function invalidResource(?Request $request = null): Response
    {
        if ($request !== null) {
            return $this->authorizationError(
                $request,
                'invalid_target',
                'The requested resource is invalid.',
            );
        }

        return new JsonResponse([
            'error' => 'invalid_target',
            'error_description' => 'The requested resource is invalid.',
        ], 400, [
            'Cache-Control' => 'no-store',
            'Pragma' => 'no-cache',
        ]);
    }

    private function invalidScope(?Request $request = null): Response
    {
        if ($request !== null) {
            return $this->authorizationError(
                $request,
                'invalid_scope',
                'The requested scope is invalid for this client.',
            );
        }

        return new JsonResponse([
            'error' => 'invalid_scope',
            'error_description' => 'The requested scope is invalid for this client.',
        ], 400, [
            'Cache-Control' => 'no-store',
            'Pragma' => 'no-cache',
        ]);
    }

    private function authorizationError(Request $request, string $error, string $description): Response
    {
        $redirectUri = $this->validatedRedirectUri($request);
        if ($redirectUri === null) {
            // Never redirect an error until the client and redirect URI have been
            // checked against Passport's stored registration.
            return $this->jsonAuthorizationError($error, $description);
        }

        $parameters = [
            'error' => $error,
            'error_description' => $description,
        ];
        $state = $request->query('state');
        if (is_string($state) && strlen($state) <= 2048) {
            $parameters['state'] = $state;
        }

        $separator = str_contains($redirectUri, '?') ? '&' : '?';
        $response = $this->noStore(
            redirect()->away($redirectUri.$separator.http_build_query($parameters)),
        );

        return OAuthAuthorizationResponseIssuer::decorate($response);
    }

    private function jsonAuthorizationError(string $error, string $description): JsonResponse
    {
        return new JsonResponse([
            'error' => $error,
            'error_description' => $description,
        ], 400, [
            'Cache-Control' => 'no-store',
            'Pragma' => 'no-cache',
        ]);
    }

    private function validatedRedirectUri(Request $request): ?string
    {
        $clientId = $request->query('client_id');
        if (! is_string($clientId)
            || $clientId === '') {
            return null;
        }

        $client = Passport::client()->newQuery()->find($clientId);
        if ($client === null || (bool) $client->getAttribute('revoked')) {
            return null;
        }

        $registeredUris = $client->getAttribute('redirect_uris');
        if (is_string($registeredUris)) {
            $decoded = json_decode($registeredUris, true);
            $registeredUris = is_array($decoded) ? $decoded : [];
        }
        if (! is_array($registeredUris)) {
            return null;
        }
        $registeredUris = array_values(array_filter(
            $registeredUris,
            static fn (mixed $uri): bool => is_string($uri) && $uri !== '',
        ));

        if ($request->query->has('redirect_uri')) {
            $redirectUri = $request->query('redirect_uri');
            if (! is_string($redirectUri) || ! $this->safeRedirectUri($redirectUri)) {
                return null;
            }
        } else {
            if (count($registeredUris) !== 1) {
                return null;
            }
            $redirectUri = $registeredUris[0];
            if (! $this->safeRedirectUri($redirectUri)) {
                return null;
            }
        }

        foreach ($registeredUris as $registeredUri) {
            if ($registeredUri === $redirectUri) {
                return $redirectUri;
            }
        }

        return null;
    }

    private function safeRedirectUri(string $redirectUri): bool
    {
        if ($redirectUri === ''
            || strlen($redirectUri) > 2048
            || preg_match('/[\x00-\x1F\x7F]/', $redirectUri) === 1) {
            return false;
        }
        try {
            $parts = parse_url($redirectUri);
        } catch (\ValueError) {
            return false;
        }

        return is_array($parts) && ! isset($parts['fragment']);
    }

    private function noStore(Response $response): Response
    {
        $response->headers->set('Cache-Control', 'no-store');
        $response->headers->set('Pragma', 'no-cache');

        return $response;
    }
}
