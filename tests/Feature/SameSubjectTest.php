<?php

namespace BWH\Auth\Tests\Feature;

use BWH\Auth\OAuth\SameSubject;
use BWH\Auth\OAuth\Session\ProviderBinding;
use BWH\Auth\OAuth\Session\ProviderBindingResolver;
use BWH\Auth\OAuth\Session\ProviderSessionExpired;
use BWH\Auth\Tests\Fixtures\User;
use BWH\Auth\Tests\TestCase;
use Illuminate\Contracts\Auth\Authenticatable;
use PHPUnit\Framework\Attributes\DataProvider;

class SameSubjectTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        config(['bherila-auth.oauth_client.provider' => 'bherila']);
    }

    public function test_the_same_trusted_provider_and_subject_match(): void
    {
        $this->assertTrue(SameSubject::matches('bherila', 'bherila', '42', 'bherila', '42'));
    }

    public function test_an_integer_subject_from_json_matches_its_string_form(): void
    {
        $this->assertTrue(SameSubject::matches('bherila', 'bherila', '42', 'bherila', 42));
    }

    /**
     * @return array<string, array{mixed, mixed, mixed, mixed}>
     */
    public static function mismatches(): array
    {
        return [
            'another subject' => ['bherila', '42', 'bherila', '43'],
            'unbound owner' => [null, null, 'bherila', '42'],
            'owner without a subject' => ['bherila', null, 'bherila', '42'],
            'empty owner subject' => ['bherila', '', 'bherila', ''],
            'empty reported subject' => ['bherila', '42', 'bherila', ''],
            'missing reported subject' => ['bherila', '42', 'bherila', null],
            'owner bound to another provider' => ['other', '42', 'bherila', '42'],
            'reported by another provider' => ['bherila', '42', 'other', '42'],
            'both from an untrusted provider' => ['other', '42', 'other', '42'],
            'subject differing in case' => ['bherila', 'abc', 'bherila', 'ABC'],
            'subject differing in whitespace' => ['bherila', '42', 'bherila', ' 42'],
            'array subject' => ['bherila', '42', 'bherila', ['42']],
            'float subject' => ['bherila', '42', 'bherila', 42.0],
            'boolean subject' => ['bherila', '1', 'bherila', true],
            'negative integer subject' => ['bherila', '-1', 'bherila', -1],
            'overlong subject' => ['bherila', str_repeat('a', 192), 'bherila', str_repeat('a', 192)],
        ];
    }

    #[DataProvider('mismatches')]
    public function test_anything_else_does_not_match(mixed $boundProvider, mixed $boundSubject, mixed $reportedProvider, mixed $reportedSubject): void
    {
        $this->assertFalse(SameSubject::matches('bherila', $boundProvider, $boundSubject, $reportedProvider, $reportedSubject));
    }

    public function test_no_trusted_provider_matches_nothing(): void
    {
        $this->assertFalse(SameSubject::matches('', '', '42', '', '42'));
        $this->assertFalse(SameSubject::matches(' bherila', ' bherila', '42', ' bherila', '42'));
    }

    public function test_a_user_bound_to_the_sign_in_provider_matches_its_subject(): void
    {
        $user = new User(['oauth_provider' => 'bherila', 'oauth_subject' => '42']);

        $this->assertTrue(SameSubject::matchesUser($user, 'bherila', '42'));
        $this->assertFalse(SameSubject::matchesUser($user, 'bherila', '43'));
        $this->assertFalse(SameSubject::matchesUser($user, 'other', '42'));
    }

    public function test_an_unbound_user_matches_nothing(): void
    {
        $user = new User(['oauth_provider' => null, 'oauth_subject' => null]);

        $this->assertFalse(SameSubject::matchesUser($user, 'bherila', '42'));
    }

    public function test_a_broken_binding_matches_nothing(): void
    {
        // Bound to another provider, and missing its columns altogether.
        $this->assertFalse(SameSubject::matchesUser(new User(['oauth_provider' => 'other', 'oauth_subject' => '42']), 'bherila', '42'));
        $this->assertFalse(SameSubject::matchesUser(new User(['name' => 'x']), 'bherila', '42'));
    }

    public function test_the_application_binding_resolver_is_used(): void
    {
        $this->app->instance(ProviderBindingResolver::class, new class implements ProviderBindingResolver
        {
            public function binding(Authenticatable $user): ?ProviderBinding
            {
                return $user->getAuthIdentifier() === 1 ? new ProviderBinding('bherila', 'from-resolver') : throw new ProviderSessionExpired('broken');
            }
        });

        $this->assertTrue(SameSubject::matchesUser(new User(['id' => 1]), 'bherila', 'from-resolver'));
        $this->assertFalse(SameSubject::matchesUser(new User(['id' => 2]), 'bherila', 'from-resolver'));
    }
}
