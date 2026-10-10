<?php

namespace BWH\Auth\Http\Controllers;

use BWH\Auth\OAuth\Introspection\OAuthIntrospectionClientRegistry;
use BWH\Auth\OAuth\Introspection\OAuthIntrospectionValidationContext;
use BWH\Auth\OAuth\Server\OAuthResourceIndicator;
use GuzzleHttp\Psr7\ServerRequest;
use InvalidArgumentException;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\ResourceServer;
use Psr\Http\Message\ServerRequestInterface;

final readonly class OAuthTokenIntrospectionController
{
    public function __construct(
        private OAuthIntrospectionClientRegistry $clients,
        private OAuthIntrospectionValidationContext $context,
        private ResourceServer $resourceServer,
    ) {}

    public function __invoke(Request $request): JsonResponse
    {
        abort_unless((bool) config('bherila-auth.oauth_server.introspection.enabled', false), 404);

        $resource = $this->clients->resourceFor($request);
        if ($resource === null) {
            return response()->json(['error' => 'invalid_client'], 401)->withHeaders([
                'Cache-Control' => 'no-store',
                'Pragma' => 'no-cache',
                'WWW-Authenticate' => 'Basic realm="oauth-introspection"',
            ]);
        }

        $canonicalResource = OAuthResourceIndicator::canonicalize($resource);
        if ($canonicalResource === null || ! OAuthResourceIndicator::isConfiguredResource($canonicalResource)) {
            return $this->inactive();
        }

        $token = $request->input('token');
        if (! is_string($token) || $token === '' || strlen($token) > 32_768) {
            return $this->inactive();
        }

        try {
            $validated = $this->context->run($token, $canonicalResource, function () use ($token): ServerRequestInterface {
                return $this->resourceServer->validateAuthenticatedRequest(
                    (new ServerRequest('POST', '/oauth/introspect'))
                        ->withHeader('Authorization', 'Bearer '.$token),
                );
            });
        } catch (OAuthServerException|InvalidArgumentException) {
            return $this->inactive();
        }

        $claims = OAuthResourceIndicator::tokenClaims($token);
        $subject = $validated->getAttribute('oauth_user_id');
        $clientId = $validated->getAttribute('oauth_client_id');
        $scopes = OAuthResourceIndicator::scopeIdentifiers($validated->getAttribute('oauth_scopes'));
        $expiresAt = $this->timestamp($claims['exp'] ?? null);
        $issuedAt = array_key_exists('iat', $claims ?? [])
            ? $this->timestamp($claims['iat'])
            : null;
        $notBefore = array_key_exists('nbf', $claims ?? [])
            ? $this->timestamp($claims['nbf'], roundTowardFuture: true)
            : null;
        if ((! is_string($subject) && ! is_int($subject))
            || (string) $subject === ''
            || (! is_string($clientId) && ! is_int($clientId))
            || (string) $clientId === ''
            || $expiresAt === null
            || (array_key_exists('iat', $claims ?? []) && $issuedAt === null)
            || (array_key_exists('nbf', $claims ?? []) && $notBefore === null)) {
            return $this->inactive();
        }

        $response = [
            'active' => true,
            'iss' => $claims['iss'] ?? null,
            'sub' => (string) $subject,
            'client_id' => (string) $clientId,
            'scope' => implode(' ', $scopes),
            'exp' => $expiresAt,
            'aud' => $claims['aud'] ?? null,
            'resource' => $claims['resource'] ?? null,
        ];
        if ($issuedAt !== null) {
            $response['iat'] = $issuedAt;
        }
        if ($notBefore !== null) {
            $response['nbf'] = $notBefore;
        }

        return response()->json($response)->withHeaders($this->nonCacheableHeaders());
    }

    private function inactive(): JsonResponse
    {
        return response()->json(['active' => false])->withHeaders($this->nonCacheableHeaders());
    }

    /** @return array<string, string> */
    private function nonCacheableHeaders(): array
    {
        return [
            'Cache-Control' => 'no-store',
            'Pragma' => 'no-cache',
        ];
    }

    private function timestamp(mixed $value, bool $roundTowardFuture = false): ?int
    {
        if (is_int($value)) {
            return $value;
        }

        // Passport's NumericDate claims include sub-second precision. RFC 7662
        // consumers commonly decode these claims as integral timestamps, so
        // normalize finite values to whole seconds at this response boundary.
        // The direction narrows the validity window rather than widening it:
        // `exp` and `iat` floor, `nbf` ceils. Publishing a floored `nbf` would
        // advertise the token as valid up to a second early to every consumer.
        if (! is_float($value)
            || ! is_finite($value)
            || ! $this->withinIntegerRange($value)) {
            return null;
        }

        return (int) ($roundTowardFuture ? ceil($value) : floor($value));
    }

    /**
     * Doubles cannot represent every integer near the 64-bit bounds, so an
     * out-of-range value that rounds to exactly PHP_INT_MIN must not be
     * emitted as a whole-second claim. Both bounds are therefore exclusive
     * there. A 32-bit int range is represented exactly by a double, so those
     * bounds stay inclusive.
     */
    private function withinIntegerRange(float $value): bool
    {
        if (PHP_INT_SIZE >= 8) {
            return $value > -(2 ** 63) && $value < 2 ** 63;
        }

        return $value >= (float) PHP_INT_MIN && $value <= (float) PHP_INT_MAX;
    }
}
