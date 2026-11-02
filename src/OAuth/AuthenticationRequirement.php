<?php

namespace BWH\Auth\OAuth;

use InvalidArgumentException;

/**
 * How recently, and how, a person must have authenticated.
 *
 * Sent to the provider as `prompt`, `max_age` and `acr_values`, and checked against what it
 * returns: the provider honouring a request is a convenience, and this check is the
 * enforcement. Rungs are read only from `acr` and methods only from `amr`, so neither can
 * stand in for the other.
 */
final readonly class AuthenticationRequirement
{
    public const string ACR_PREFIX = 'urn:auth-manager:acr:';

    public const string AMR_PREFIX = 'urn:auth-manager:amr:';

    public const string ACR_SINGLE = self::ACR_PREFIX.'single';

    public const string ACR_PHISHING_RESISTANT = self::ACR_PREFIX.'phishing-resistant';

    public const string ACR_MFA = self::ACR_PREFIX.'mfa';

    /** Allowed difference between the provider's clock and this application's. */
    private const int CLOCK_SKEW_SECONDS = 30;

    /** @param  list<string>  $acrValues  rung or method-class values; any one satisfies the requirement */
    public function __construct(
        public bool $forceLogin = false,
        public ?int $maxAge = null,
        public array $acrValues = [],
    ) {
        if ($maxAge !== null && $maxAge < 0) {
            throw new InvalidArgumentException('max_age must not be negative.');
        }
        foreach ($acrValues as $value) {
            if (! is_string($value) || preg_match('/^[\x21-\x7E]+$/', $value) !== 1) {
                throw new InvalidArgumentException('acr_values must be space-free strings.');
            }
        }
    }

    /** @param  list<string>  $methods  `amr` values such as otp, hwk or swk */
    public static function methods(array $methods, ?int $maxAge = null): self
    {
        return new self(
            maxAge: $maxAge,
            acrValues: array_map(static fn (string $method): string => self::AMR_PREFIX.$method, $methods),
        );
    }

    public function isEmpty(): bool
    {
        return ! $this->forceLogin && $this->maxAge === null && $this->acrValues === [];
    }

    /** @return array<string, string> the authorization request parameters */
    public function parameters(): array
    {
        return array_filter([
            'prompt' => $this->forceLogin ? 'login' : null,
            'max_age' => $this->maxAge === null ? null : (string) $this->maxAge,
            'acr_values' => $this->acrValues === [] ? null : implode(' ', $this->acrValues),
        ], static fn (?string $value): bool => $value !== null);
    }

    /**
     * @param  list<string>  $amr
     * @param  int|null  $requestedAt  when the sign-in was requested, for a forced fresh sign-in
     */
    public function satisfiedBy(?int $authTime, array $amr, ?string $acr, int $now, ?int $requestedAt = null): bool
    {
        if ($this->isEmpty()) {
            return true;
        }

        if ($authTime === null || $authTime > $now + self::CLOCK_SKEW_SECONDS) {
            return false;
        }

        if (($this->forceLogin || $this->maxAge === 0)
            && ($requestedAt === null || $authTime < $requestedAt - self::CLOCK_SKEW_SECONDS)) {
            return false;
        }

        if ($this->maxAge !== null && $now - $authTime > $this->maxAge + self::CLOCK_SKEW_SECONDS) {
            return false;
        }

        if ($this->acrValues === []) {
            return true;
        }

        foreach ($this->acrValues as $value) {
            if ($this->valueSatisfied($value, $amr, $acr)) {
                return true;
            }
        }

        return false;
    }

    /** @return array{force_login: bool, max_age: int|null, acr_values: list<string>} */
    public function toArray(): array
    {
        return ['force_login' => $this->forceLogin, 'max_age' => $this->maxAge, 'acr_values' => $this->acrValues];
    }

    public static function fromArray(mixed $values): ?self
    {
        if (! is_array($values)
            || ! is_bool($values['force_login'] ?? null)
            || ! (is_int($values['max_age'] ?? null) || ($values['max_age'] ?? null) === null)
            || ! is_array($values['acr_values'] ?? null)
            || ! array_is_list($values['acr_values'])) {
            return null;
        }

        try {
            return new self($values['force_login'], $values['max_age'] ?? null, $values['acr_values']);
        } catch (InvalidArgumentException) {
            return null;
        }
    }

    /** @param  list<string>  $amr */
    private function valueSatisfied(string $value, array $amr, ?string $acr): bool
    {
        if (str_starts_with($value, self::AMR_PREFIX)) {
            return in_array(substr($value, strlen(self::AMR_PREFIX)), $amr, true);
        }

        // Any completed authentication reaches the lowest rung. The others aren't ordered
        // against each other: an emailed code after a password is multi-factor but phishable,
        // and a passkey is phishing-resistant but one factor.
        if ($value === self::ACR_SINGLE) {
            return $acr !== null && str_starts_with($acr, self::ACR_PREFIX);
        }

        return $acr !== null && hash_equals($value, $acr);
    }
}
