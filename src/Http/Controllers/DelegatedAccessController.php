<?php

namespace BWH\Auth\Http\Controllers;

use BWH\Auth\OAuth\DelegatedAccess\ApplicationAccessAdapter;
use BWH\Auth\OAuth\DelegatedAccess\DatabaseReceiptStore;
use BWH\Auth\OAuth\DelegatedAccess\DelegatedAccessException;
use BWH\Auth\OAuth\DelegatedAccess\DelegatedAccessSettings;
use BWH\Auth\OAuth\DelegatedAccess\DelegatedContract;
use BWH\Auth\OAuth\DelegatedAccess\DelegatedReceipt;
use BWH\Auth\OAuth\DelegatedAccess\DelegatedRequestContext;
use BWH\Auth\OAuth\DelegatedAccess\NonceStore;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\RateLimiter;
use JsonException;
use Throwable;

/**
 * POST /application-access: the identity provider's delegated access requests, contract version 3.
 *
 * The order is the contract's. The signed actor assertion is verified first, bound to the exact
 * request body, and its single-use nonce consumed. Only then is the body parsed, validated, and
 * handed to the application's {@see ApplicationAccessAdapter}. The answer is validated again before
 * it leaves, so an application cannot send the provider a shape it would refuse, a field the
 * contract does not define, or more than the provider will read. There is no fallback to any
 * other kind of authentication.
 *
 * Writes (`update`, `remove`) are idempotent by `operation_id` through {@see DatabaseReceiptStore}:
 * claimed before the adapter runs, answered from the receipt when repeated, and readable through
 * the `receipt` operation, which the package answers itself.
 */
final class DelegatedAccessController extends Controller
{
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
        $claimed = null;

        try {
            $verified = $settings->verifier($container->make(NonceStore::class))
                ->verifyContext($credentials[1], $request->method(), $body);

            try {
                $input = json_decode($body, true, 32, JSON_THROW_ON_ERROR);
            } catch (JsonException) {
                throw new DelegatedAccessException('invalid_request', 422);
            }

            // Version 3 only. An earlier version is refused, not translated: its rules are not these.
            if (! is_array($input) || ($input['contract_version'] ?? null) !== DelegatedContract::VERSION_3
                || ($input['application'] ?? null) !== $application) {
                throw new DelegatedAccessException('invalid_request', 422);
            }

            unset($input['contract_version'], $input['application']);
            $payload = $contract->request($application, $input, DelegatedContract::VERSION_3);
            $operation = (string) $payload['operation'];
            unset($payload['contract_version'], $payload['application']);

            // The package's own read: what was answered to one of this actor's writes, if anything.
            if ($operation === 'receipt') {
                return self::receipt($contract, $container->make(DatabaseReceiptStore::class), $application, $verified->subject, (string) $payload['operation_id']);
            }

            $write = in_array($operation, DelegatedContract::WRITE_OPERATIONS, true);
            $operationId = $write ? (string) $payload['operation_id'] : null;

            // The operation id names the action across retries; the jti names this one request. A
            // provider that reuses one as the other would have every retry refused as a replay.
            if ($operationId !== null && hash_equals($verified->jti, $operationId)) {
                throw new DelegatedAccessException('invalid_request', 422);
            }
            // An application that has not switched writes on refuses them here, before its adapter runs.
            // A repeat of a write already answered is not a new write: it gets its stored answer, so
            // switching writes off never changes what a retry reports about a change already made.
            if ($operationId !== null && ! $settings->writesEnabled()) {
                $hash = DatabaseReceiptStore::requestHash($verified->subject, $payload);
                $held = $container->make(DatabaseReceiptStore::class)->find($application, $operationId);
                if ($held !== null && ! $held->pending() && hash_equals($held->requestHash, $hash)) {
                    return self::replay($held, $hash);
                }

                throw new DelegatedAccessException('not_authorized', 403);
            }

            // A write runs once per operation id. The claim is taken before the adapter, so a repeat,
            // concurrent or later, is answered from the receipt and never reaches the adapter.
            if ($operationId !== null) {
                $receipts = $container->make(DatabaseReceiptStore::class);
                $hash = DatabaseReceiptStore::requestHash($verified->subject, $payload);
                $at = DatabaseReceiptStore::now();
                $held = $receipts->claim($application, $operationId, DatabaseReceiptStore::actor($verified->subject), $hash, $at);
                if ($held !== null) {
                    return self::replay($held, $hash);
                }
                $claimed = [$receipts, $operationId, $at];
            }

            $context = $verified->withOperation($operation, $operationId);
            $container->instance(DelegatedRequestContext::class, $context);
            try {
                $fields = $container->make(ApplicationAccessAdapter::class)->handle($context->subject, $payload);
            } finally {
                $container->forgetInstance(DelegatedRequestContext::class);
            }
        } catch (DelegatedAccessException $failure) {
            // A refusal is the write's outcome, stored like a success. A 5xx is not: nothing vouches
            // for what happened, so the claim is given up and the provider's receipt check sees unknown.
            if ($claimed !== null && $failure->status >= 400 && $failure->status < 500) {
                return self::stored($claimed, $application, $failure->status, self::errorBody($failure->outcome));
            }
            self::release($claimed, $application);

            return self::error($failure->outcome, $failure->status);
        } catch (Throwable $unexpected) {
            self::release($claimed, $application);

            throw $unexpected;
        }

        try {
            $response = $contract->adapterAnswer($fields, $application, $operation, $payload['subject'] ?? null);
            $json = self::encode($response);
        } catch (DelegatedAccessException $invalid) {
            report($invalid);
            self::release($claimed, $application);

            return self::error('internal_error', 500);
        }

        return $claimed === null ? self::json($json, 200) : self::stored($claimed, $application, 200, $json);
    }

    /**
     * Answer a repeat of a write from its receipt: the exact status and body sent the first time.
     *
     * The same operation id on a different request (another payload, or another actor) is refused,
     * and so is one still being decided: its outcome is not known yet, which is what a 503 tells a
     * provider. A claim interrupted before its answer was stored blocks repeats for
     * {@see DatabaseReceiptStore::PENDING_LEASE_SECONDS}; then the store lets a repeat take it over,
     * so it never arrives here.
     */
    private static function replay(DelegatedReceipt $held, string $hash): JsonResponse
    {
        if (! hash_equals($held->requestHash, $hash)) {
            return self::error('invalid_request', 422);
        }
        if ($held->pending()) {
            return self::error('operation_in_progress', 503);
        }

        return self::json((string) $held->response, (int) $held->status);
    }

    /**
     * Store a claimed write's answer and send it. The answer is true whether or not it could be
     * stored, so it is sent either way; a failure to store leaves the claim pending, which a repeat
     * and a receipt report as not known, and is reported.
     *
     * @param  array{DatabaseReceiptStore, string, int}  $claimed
     */
    private static function stored(array $claimed, string $application, int $status, string $json): JsonResponse
    {
        try {
            $claimed[0]->complete($application, $claimed[1], $claimed[2], $status, $json);
        } catch (Throwable $failure) {
            report($failure);
        }

        return self::json($json, $status);
    }

    /**
     * @param  array{DatabaseReceiptStore, string, int}|null  $claimed
     */
    private static function release(?array $claimed, string $application): void
    {
        if ($claimed === null) {
            return;
        }

        try {
            $claimed[0]->release($application, $claimed[1], $claimed[2]);
        } catch (Throwable $failure) {
            // Left pending: a repeat and a receipt then say the outcome is not known, which is true.
            report($failure);
        }
    }

    /**
     * `receipt`: the stored answer to one of this actor's writes, or `unknown`. A write still being
     * decided, one that was never sent, one pruned after 30 days and another actor's are all unknown.
     */
    private static function receipt(DelegatedContract $contract, DatabaseReceiptStore $receipts, string $application, string $actor, string $operationId): JsonResponse
    {
        $held = $receipts->find($application, $operationId);
        $fields = ['operation_id' => $operationId, 'status' => 'unknown'];
        if ($held !== null && ! $held->pending() && hash_equals($held->actor, DatabaseReceiptStore::actor($actor))) {
            try {
                $stored = json_decode((string) $held->response, true, 64, JSON_THROW_ON_ERROR);
                $fields = ['operation_id' => $operationId, 'status' => 'known', 'response_status' => $held->status, 'response' => $stored];
            } catch (JsonException $unreadable) {
                report($unreadable);
            }
        }

        try {
            $response = $contract->response(['contract_version' => DelegatedContract::VERSION_3, 'application' => $application, 'operation' => 'receipt', ...$fields],
                $application, 'receipt', null, DelegatedContract::VERSION_3);

            return self::json(self::encode($response), 200);
        } catch (DelegatedAccessException $invalid) {
            report($invalid);

            return self::error('internal_error', 500);
        }
    }

    /**
     * @param  array<string, mixed>  $response
     *
     * @throws DelegatedAccessException `invalid_response`
     */
    private static function encode(array $response): string
    {
        try {
            $json = json_encode($response, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        } catch (JsonException) {
            throw new DelegatedAccessException('invalid_response');
        }

        // With the exact-fields check, a contract-valid answer stays far below this bound today
        // (pages of 50, bounded strings). It is kept so a future contract field cannot make this
        // side send more than the provider reads.
        if (strlen($json) > DelegatedContract::MAX_RESPONSE_BYTES) {
            throw new DelegatedAccessException('invalid_response');
        }

        return $json;
    }

    private static function json(string $json, int $status): JsonResponse
    {
        return JsonResponse::fromJsonString($json, $status)->header('Cache-Control', 'no-store');
    }

    private static function errorBody(string $outcome): string
    {
        return (string) json_encode(['error' => $outcome], JSON_UNESCAPED_SLASHES);
    }

    private static function error(string $outcome, int $status): JsonResponse
    {
        return self::json(self::errorBody($outcome), $status);
    }
}
