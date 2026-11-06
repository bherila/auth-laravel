# Two-factor route names

`bherila-auth.two_factor.route_name_prefix` controls the names of the two-factor
confirmation and suspicious-login reporting routes. Its default is
`bherila-auth.two-factor.`, preserving the existing public names:

| Action | Default route name |
| --- | --- |
| Confirmation page | `bherila-auth.two-factor.confirm` |
| Confirmation submission | `bherila-auth.two-factor.confirm.submit` |
| Report page | `bherila-auth.two-factor.report` |
| Report submission | `bherila-auth.two-factor.report.submit` |

The prefix is prepended literally, including any desired trailing separator.
For example, a provider mounted alongside a host's authentication routes can use:

```php
'two_factor' => [
    // Other existing two-factor options...
    'route_name_prefix' => 'example-provider.two-factor.',
],
```

The host can retain the default names while the mounted provider registers
`example-provider.two-factor.*`. The provider must apply its own prefix both
while registering its routes and while handling its requests or generating
challenge mail. A configuration overlay can restore the host's value after
each provider operation; the helper reads the current value on each call.

`BWH\Auth\Support\TwoFactorRoutes::name('confirm')` resolves a name using the
current configuration. Package mail and confirmation/report form actions use
this same helper, so they select the matching route set. Mail URLs still use
the trusted configured `app.url` origin rather than an incoming request host.

This setting changes route names only. HTTP paths, request methods, middleware,
guards and MFA behavior stay unchanged. The embedding application still owns its
HTTP mount prefix and isolation. Give each route set a distinct name prefix and
rebuild the route cache whenever the configured prefix changes. Already emailed
links keep their existing paths.
