<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="robots" content="noindex, nofollow">
    @php
        $consentConfig = config('bherila-auth.oauth_server.consent', []);
        $appName = (string) ($consentConfig['app_name'] ?? config('app.name', 'Application'));
        $clientName = (string) $client->name;
        $copy = static fn (string $key, string $fallback): string => strtr(
            (string) ($consentConfig[$key] ?? $fallback),
            [':app' => $appName, ':client' => $clientName],
        );
        // Every requested scope must reach the page. If any cannot be placed by id, show the
        // flat list rather than a grouped one that silently leaves it out.
        $requested = [];
        $everyScopeHasId = true;
        foreach ($scopes as $requestedScope) {
            if (isset($requestedScope->id)) {
                $requested[(string) $requestedScope->id] = (string) ($requestedScope->description ?? '');
            } else {
                $everyScopeHasId = false;
            }
        }
        $scopeGroups = $everyScopeHasId
            ? app(\BWH\Auth\OAuth\Credentials\ScopePresentationResolver::class)->groups($requested)
            : [];
    @endphp
    <title>{{ $copy('heading', 'Connect :client to :app?') }}</title>
    <style>
        :root { color-scheme: light dark; font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
        * { box-sizing: border-box; }
        body { align-items: center; background: #f4f1eb; color: #1f2937; display: flex; justify-content: center; margin: 0; min-height: 100vh; padding: 1.5rem; }
        main { background: #fff; border: 1px solid #d6d3d1; border-radius: 1rem; box-shadow: 0 1rem 3rem rgb(15 23 42 / .08); max-width: 38rem; padding: 2rem; width: 100%; }
        h1 { font-size: 1.5rem; line-height: 1.25; margin: 0 0 .75rem; }
        h2 { font-size: 1rem; margin: 1.5rem 0 .5rem; }
        p { line-height: 1.5; }
        ul { background: #f8fafc; border-radius: .75rem; margin: .5rem 0; padding: 1rem 1rem 1rem 2rem; }
        li + li { margin-top: .5rem; }
        .identity, .policy { color: #57534e; font-size: .9rem; }
        .warning { background: #fff8db; border-left: 4px solid #c99700; border-radius: .25rem; padding: .8rem; }
        .redirect { display: block; overflow-wrap: anywhere; padding-top: .35rem; }
        .actions { display: flex; gap: .75rem; justify-content: flex-end; margin-top: 1.5rem; }
        button { border: 0; border-radius: .6rem; cursor: pointer; font: inherit; font-weight: 650; padding: .7rem 1rem; }
        button:focus-visible { outline: 3px solid #38bdf8; outline-offset: 2px; }
        .approve { background: #0f766e; color: #fff; }
        .deny { background: #e7e5e4; color: #292524; }
        @media (prefers-color-scheme: dark) {
            body { background: #111827; color: #e5e7eb; }
            main { background: #1f2937; border-color: #374151; }
            ul { background: #111827; }
            .identity, .policy { color: #d6d3d1; }
            .warning { background: #3f3412; border-color: #eab308; }
            .deny { background: #374151; color: #e5e7eb; }
        }
    </style>
@if ($scopeGroups !== [])
    <style>
        .scope-group h3 { font-size: .95rem; margin: 1rem 0 .25rem; }
        .scope-group.sensitive ul { border-left: 4px solid #c99700; }
    </style>
@endif
</head>
<body>
@inject('consent', 'BWH\Auth\OAuth\Server\OAuthConsentPresenter')
<main>
    <h1>{{ $copy('heading', 'Connect :client to :app?') }}</h1>
    <p>{{ $copy('intro', 'This application is requesting access to your :app account.') }}</p>
    @if (($consentConfig['identity'] ?? true) && isset($user) && is_string($user->name ?? null))
        <p class="identity">Signed in as {{ $user->name }}.</p>
    @endif
    @if (is_string($consentConfig['trust_warning'] ?? null) && $consentConfig['trust_warning'] !== '')
        <p class="warning">{{ $copy('trust_warning', '') }}</p>
    @endif
    @if ($consent->isDynamicClient($client) && is_string($consentConfig['dynamic_client_warning'] ?? null))
        <p class="warning">
            {{ $copy('dynamic_client_warning', '') }}
            @if ($redirectUri = $consent->redirectUri($request, $client))
                <strong class="redirect">{{ $redirectUri }}</strong>
            @endif
        </p>
    @endif
    <h2>Requested permissions</h2>
@if ($scopeGroups !== [])
        @foreach ($scopeGroups as $group)
            <section class="{{ $group['sensitive'] ? 'scope-group sensitive' : 'scope-group' }}">
                <h3>{{ $group['label'] }}</h3>
                @if (is_string($group['description']) && $group['description'] !== '')
                    <p>{{ $group['description'] }}</p>
                @endif
                @if ($group['sensitive'])
                    <p class="warning">{{ $copy('sensitive_notice', 'These permissions allow sensitive actions. Only approve them if you need them.') }}</p>
                @endif
                <ul>
                    @foreach ($group['scopes'] as $scopeId)
                        <li>{{ $requested[$scopeId] }}</li>
                    @endforeach
                </ul>
            </section>
        @endforeach
@else
    <ul>
        @forelse ($scopes as $scope)
            <li>{{ $scope->description }}</li>
        @empty
            <li>No additional permissions requested.</li>
        @endforelse
    </ul>
@endif
    @if (is_string($consentConfig['policy_notice'] ?? null) && $consentConfig['policy_notice'] !== '')
        <p class="policy">{{ $copy('policy_notice', '') }}</p>
    @endif
    <div class="actions">
        <form method="post" action="{{ route('passport.authorizations.deny') }}">
            @csrf
            @method('DELETE')
            <input type="hidden" name="auth_token" value="{{ $authToken }}">
            <button class="deny" type="submit">{{ $copy('deny_label', 'Cancel') }}</button>
        </form>
        <form method="post" action="{{ route('passport.authorizations.approve') }}">
            @csrf
            <input type="hidden" name="auth_token" value="{{ $authToken }}">
            <button class="approve" type="submit">{{ $copy('approve_label', 'Authorize') }}</button>
        </form>
    </div>
</main>
</body>
</html>
