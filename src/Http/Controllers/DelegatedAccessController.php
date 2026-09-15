<?php

namespace BWH\Auth\Http\Controllers;

use BWH\Auth\OAuth\DelegatedAccess\ApplicationAccessAdapter;
use BWH\Auth\OAuth\DelegatedAccess\DelegatedAccessException;
use BWH\Auth\OAuth\DelegatedAccess\DelegatedAccessSettings;
use BWH\Auth\OAuth\DelegatedAccess\DelegatedContract;
use BWH\Auth\OAuth\DelegatedAccess\NonceStore;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\RateLimiter;
use JsonException;

/**
 * POST /application-access: the identity provider's delegated access requests, contract version 2.
 *
 * The order is the contract's. The signed actor assertion is verified first, bound to the exact
 * request body, and its single-use nonce consumed. Only then is the body parsed, validated, and
 * handed to the application's {@see ApplicationAccessAdapter}. The answer is validated again before
 * it leaves, so an application cannot send the provider a shape it would refuse, a field the
 * contract does not define, or more than the provider will read. There is no fallback to any
 * other kind of authentication.
 */
final class DelegatedAccessController extends Controller
{
    /** The top-level fields each operation's answer carries besides the envelope, exactly. */
    private const RESPONSE_FIELDS = [
        'capabilities' => ['controls'],
        'subjects' => ['subjects', 'next_cursor'],
        'workspaces' => ['workspaces', 'next_cursor'],
        'read' => ['subject', 'provisioned', 'revision', 'access', 'allowed_edits'],
        'update' => ['subject', 'provisioned', 'revision', 'access', 'allowed_edits'],
    ];

    public function __invoke(Request $request, DelegatedAccessSettings $settings, Container $container, Repository $config): JsonResponse
    {
        // Nothing before this reveals the route or counts against the limit, so a disabled endpoint
        // answers exactly like an absent one, and requests made before enabling cannot throttle the
        // provider once it is.
        if (! $settings->enabled()) {
            return self::error('not_found', 404);
        }

        if (! $container->bound(ApplicationAccessAdapter::class)) {
            report(new DelegatedAccessException('invalid_adapter_configuration', 500));

            return self::error('internal_error', 500);
        }

        $limiterKey = 'bherila-auth-delegated-access:'.$request->ip();
        if (RateLimiter::tooManyAttempts($limiterKey, max(1, (int) $config->get('bherila-auth.delegated_access.per_minute', 120)))) {
            return self::error('rate_limited', 429);
        }
        RateLimiter::hit($limiterKey, 60);

        // A declared oversize body is refused before it is read. Laravel's global middleware may read
        // a JSON body before any controller runs, so the web server in front should bound this route's
        // body to the same ceiling; this covers servers without that rule.
        $declared = $request->headers->get('Content-Length');
        if ($declared !== null && (! ctype_digit($declared) || (int) $declared > DelegatedContract::MAX_REQUEST_BYTES)) {
            return self::error('invalid_request', 422);
        }

        $body = $request->getContent();

        if (strlen($body) > DelegatedContract::MAX_REQUEST_BYTES) {
            return self::error('invalid_request', 422);
        }

        // Authentication scheme names are case-insensitive (RFC 9110 section 11.1).
        if (preg_match('/^Bearer +(\S+)$/Di', (string) $request->header('Authorization', ''), $credentials) !== 1) {
            return self::error('invalid_actor_assertion', 401);
        }

        $contract = new DelegatedContract;
        $application = $settings->application();

        try {
            $actorSubject = $settings->verifier($container->make(NonceStore::class))
                ->verify($credentials[1], $request->method(), $body);

            try {
                $input = json_decode($body, true, 32, JSON_THROW_ON_ERROR);
            } catch (JsonException) {
                throw new DelegatedAccessException('invalid_request', 422);
            }

            if (! is_array($input) || ($input['contract_version'] ?? null) !== DelegatedContract::VERSION_2
                || ($input['application'] ?? null) !== $application) {
                throw new DelegatedAccessException('invalid_request', 422);
            }

            unset($input['contract_version'], $input['application']);
            $payload = $contract->request($application, $input, DelegatedContract::VERSION_2);
            $operation = (string) $payload['operation'];
            unset($payload['contract_version'], $payload['application']);

            $fields = $container->make(ApplicationAccessAdapter::class)->handle($actorSubject, $payload);
        } catch (DelegatedAccessException $failure) {
            return self::error($failure->outcome, $failure->status);
        }

        try {
            $keys = array_map('strval', array_keys($fields));
            $expected = self::RESPONSE_FIELDS[$operation] ?? [];
            sort($keys);
            sort($expected);
            if ($keys !== $expected) {
                throw new DelegatedAccessException('invalid_response');
            }

            $response = ['contract_version' => DelegatedContract::VERSION_2, 'application' => $application, 'operation' => $operation] + $fields;
            $contract->response($response, $application, $operation, $payload['subject'] ?? null, DelegatedContract::VERSION_2);

            try {
                $json = json_encode($response, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
            } catch (JsonException) {
                throw new DelegatedAccessException('invalid_response');
            }

            // With the exact-fields check above, a contract-valid answer stays far below this bound
            // today (pages of 50, bounded strings). It is kept so a future contract field cannot
            // make this side send more than the provider reads.
            if (strlen($json) > DelegatedContract::MAX_RESPONSE_BYTES) {
                throw new DelegatedAccessException('invalid_response');
            }
        } catch (DelegatedAccessException $invalid) {
            report($invalid);

            return self::error('internal_error', 500);
        }

        return JsonResponse::fromJsonString($json)->header('Cache-Control', 'no-store');
    }

    private static function error(string $outcome, int $status): JsonResponse
    {
        return response()->json(['error' => $outcome], $status)->header('Cache-Control', 'no-store');
    }
}
