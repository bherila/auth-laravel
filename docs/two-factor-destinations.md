# Address proof from a completed emailed-code challenge

`TwoFactorService` records the exact mail destination as a hidden hash when the optional
recipient migration is installed. On `TwoFactorLoginSucceeded`, an application may call
`$event->attempt->wasMailedTo($currentEmail)` before recording that this address was proved.
The application must still recheck the account's current address when it writes proof; a
code sent to a former address cannot verify a replacement. No address is automatically
marked verified. Old attempts and installations without the recipient column return false
and retain their existing sign-in behavior.

Publish the package migration with `php artisan vendor:publish --tag=bherila-auth-migrations`.
Include `2026_11_27_000000_add_recipient_hash_to_two_factor_attempts.php` in the application's
reviewed migration deployment. Updating the package alone does not change its database.
