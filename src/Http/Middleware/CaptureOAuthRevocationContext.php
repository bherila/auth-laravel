<?php

namespace BWH\Auth\Http\Middleware;

use BWH\Auth\OAuth\Server\CredentialLineages;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

final class CaptureOAuthRevocationContext
{
    public function __construct(private readonly CredentialLineages $lineages) {}

    public function handle(Request $request, Closure $next): Response
    {
        $this->lineages->begin($request);

        return $next($request);
    }
}
