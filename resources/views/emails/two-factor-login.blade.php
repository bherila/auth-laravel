@component('mail::message')
# Login Verification

Hi {{ data_get($user, config('bherila-auth.users.name_attribute', 'name'), 'there') }},

We received a login attempt for your account. Use the code below{{ $confirmUrl ? ' or click the button' : '' }} to verify it was you.

**Your verification code is:**

<div style="font-size: 2em; font-weight: bold; letter-spacing: 0.3em; text-align: center; margin: 20px 0;">
{{ $attempt->code }}
</div>

This code expires in **{{ config('bherila-auth.two_factor.expires_minutes', 15) }} minutes**.

@if ($confirmUrl)
@component('mail::button', ['url' => $confirmUrl, 'color' => 'primary'])
Confirm Login
@endcomponent
@endif

---

@if ($reportUrl)
**Not you?** If you did not attempt to log in, report this as suspicious.

@component('mail::button', ['url' => $reportUrl, 'color' => 'error'])
Report Suspicious Activity
@endcomponent
@else
**Not you?** If you did not attempt to log in, do not share this code, and change your password.
@endif

Thanks,<br>
{{ $appName }}
@endcomponent
