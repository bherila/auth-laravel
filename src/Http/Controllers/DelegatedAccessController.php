<?php

namespace BWH\Auth\Http\Controllers;

use BWH\Auth\OAuth\DelegatedAccess\ApplicationAccessAdapter;
use BWH\Auth\OAuth\DelegatedAccess\DelegatedAccessException;
use BWH\Auth\OAuth\DelegatedAccess\DelegatedAccessSettings;
use BWH\Auth\OAuth\DelegatedAccess\DelegatedContract;
use BWH\Auth\OAuth\DelegatedAccess\NonceStore;
use Illuminate\Contracts\Container\Container;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use JsonException;

/**
 * POST /application-access: the identity provider's delegated access requests, contract version 2.
 *
 * The order is the contract's. The signed actor assertion is verified first, bound to the exact
 * request body, and its single-use nonce consumed. Only then is the body parsed, validated, and
 * handed to the application's {@see ApplicationAccessAdapter}. The answer is validated again before
 * it leaves, so an application cannot send the provider a shape it would refuse. There is no
 * fallback to any other kind of authentication.
 */
final class DelegatedAccessController extends Controller
{
    public function __invoke(Request $request, DelegatedAccessSettings $settings, Container $container): JsonResponse
    {
        if (! $settings->enabled()) {
            return self::error('not_found', 404);
        }

        if (! $container->bound(ApplicationAccessAdapter::class)) {
            report(new DelegatedAccessException('invalid_adapter_configuration', 500));

            return self::error('internal_error', 500);
        }

        // A declared oversize body is refused before it is read. Laravel's global middleware may read
        // a JSON body before any controller runs, so the web server in front should bound this route's
        // body to the same ceiling; this covers servers without that rule.
        $declared = $request->headers->get('Content-Length');
        if ($declared !== null && (! ctype_digit($declared) || (int) $declared > DelegatedContract::MAX_REQUEST_BYTES)) {
            return self::error('invalid_request', 422);
        }

        $body = $request->getContent();
        $authorization = (string) $request->header('Authorization', '');

        if (strlen($body) > DelegatedContract::MAX_REQUEST_BYTES) {
            return self::error('invalid_request', 422);
        }

        if (! str_starts_with($authorization, 'Bearer ') || strlen($authorization) <= 7) {
            return self::error('invalid_actor_assertion', 401);
        }

        $contract = new DelegatedContract;
        $application = $settings->application();

        try {
            $actorSubject = $settings->verifier($container->make(NonceStore::class))
                ->verify(substr($authorization, 7), $request->method(), $body);

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

        $response = ['contract_version' => DelegatedContract::VERSION_2, 'application' => $application, 'operation' => $operation] + $fields;

        try {
            $contract->response($response, $application, $operation, $payload['subject'] ?? null, DelegatedContract::VERSION_2);
        } catch (DelegatedAccessException $invalid) {
            report($invalid);

            return self::error('internal_error', 500);
        }

        return response()->json($response)->header('Cache-Control', 'no-store');
    }

    private static function error(string $outcome, int $status): JsonResponse
    {
        return response()->json(['error' => $outcome], $status)->header('Cache-Control', 'no-store');
    }
}
