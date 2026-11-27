<?php

namespace BWH\Auth\Tests;

use BWH\Auth\OAuth\Invitations\InvitationArguments;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Provider subjects: an account created before opaque subjects keeps its decimal id, and a
 * newer one carries a random ULID. Both are accepted; anything else is refused before a
 * request is sent.
 */
final class InvitationArgumentsTest extends TestCase
{
    /** @return array<string, array{string}> */
    public static function subjects(): array
    {
        return [
            'a decimal id' => ['4181'],
            'a ULID' => ['01JD3Z8M7K2Q9X4R6T5V0W1Y2Z'],
            'a single character' => ['7'],
            'sixty-four characters' => [str_repeat('a', 64)],
        ];
    }

    #[DataProvider('subjects')]
    public function test_a_provider_subject_is_accepted(string $subject): void
    {
        InvitationArguments::subject($subject);

        $this->addToAssertionCount(1);
    }

    /** @return array<string, array{string}> */
    public static function notSubjects(): array
    {
        return [
            'empty' => [''],
            'too long' => [str_repeat('a', 65)],
            'punctuation' => ['01JD3Z8M7K-2Q9X'],
            'an email address' => ['person@example.test'],
            'whitespace' => ['4181 '],
            'a trailing newline' => ["4181\n"],
        ];
    }

    #[DataProvider('notSubjects')]
    public function test_anything_else_is_refused(string $subject): void
    {
        $this->expectException(\InvalidArgumentException::class);

        InvitationArguments::subject($subject);
    }
}
