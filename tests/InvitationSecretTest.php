<?php

namespace BWH\Auth\Tests;

use BWH\Auth\Invitations\InvitationDigest;
use BWH\Auth\Invitations\InvitationSecret;
use PHPUnit\Framework\TestCase;

class InvitationSecretTest extends TestCase
{
    public function test_a_secret_is_256_bits_as_lowercase_hex(): void
    {
        $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/', InvitationSecret::generate()->plaintext);
    }

    public function test_two_secrets_are_never_equal(): void
    {
        $seen = [];
        for ($i = 0; $i < 200; $i++) {
            $seen[InvitationSecret::generate()->plaintext] = true;
        }

        $this->assertCount(200, $seen);
    }

    public function test_the_digest_is_sha256_in_the_chosen_encoding(): void
    {
        $secret = InvitationSecret::generate();

        $this->assertSame(hash('sha256', $secret->plaintext), $secret->digest());
        $this->assertSame(hash('sha256', $secret->plaintext), $secret->digest(InvitationDigest::Hex));
        $this->assertSame(hash('sha256', $secret->plaintext, true), $secret->digest(InvitationDigest::Binary));
        $this->assertSame(32, strlen($secret->digest(InvitationDigest::Binary)));
        $this->assertSame($secret->digest(), InvitationSecret::digestOf($secret->plaintext));
        $this->assertNotSame($secret->plaintext, $secret->digest());
    }

    public function test_a_legacy_token_digests_the_same_way(): void
    {
        $this->assertSame(hash('sha256', 'legacy-48-character-token', true), InvitationSecret::digestOf('legacy-48-character-token', InvitationDigest::Binary));
    }

    public function test_empty_and_oversized_values_are_implausible(): void
    {
        $this->assertFalse(InvitationSecret::plausible(''));
        $this->assertTrue(InvitationSecret::plausible('x'));
        $this->assertTrue(InvitationSecret::plausible(str_repeat('a', InvitationSecret::MAX_PRESENTED_LENGTH)));
        $this->assertFalse(InvitationSecret::plausible(str_repeat('a', InvitationSecret::MAX_PRESENTED_LENGTH + 1)));
        $this->assertTrue(InvitationSecret::plausible(InvitationSecret::generate()->plaintext));
    }

    public function test_the_plaintext_never_appears_in_a_dump(): void
    {
        $secret = InvitationSecret::generate();

        $this->assertStringNotContainsString($secret->plaintext, print_r($secret, true));
        ob_start();
        var_dump($secret);
        $this->assertStringNotContainsString($secret->plaintext, (string) ob_get_clean());
    }

    public function test_the_plaintext_is_marked_sensitive(): void
    {
        foreach ([
            [InvitationSecret::class, '__construct', 0],
            [InvitationSecret::class, 'digestOf', 0],
            [InvitationSecret::class, 'plausible', 0],
        ] as [$class, $method, $position]) {
            $parameter = (new \ReflectionMethod($class, $method))->getParameters()[$position];
            $this->assertNotEmpty($parameter->getAttributes(\SensitiveParameter::class), "{$method}() must mark the secret sensitive.");
        }
    }
}
