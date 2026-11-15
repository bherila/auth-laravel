<?php

namespace BWH\Auth\Mail;

use BWH\Auth\Models\TwoFactorAttempt;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Mail\Mailable;
use Illuminate\Mail\Mailables\Content;
use Illuminate\Mail\Mailables\Envelope;
use Illuminate\Queue\SerializesModels;

class TwoFactorLoginMail extends Mailable
{
    use Queueable, SerializesModels;

    public function __construct(
        public Authenticatable $user,
        public TwoFactorAttempt $attempt,
        /** Null when the attempt has no link secret: the email then carries the code only. */
        public ?string $confirmUrl,
        public ?string $reportUrl,
        public string $appName,
    ) {}

    public function envelope(): Envelope
    {
        return new Envelope(
            subject: strtr(config('bherila-auth.two_factor.mail_subject', 'Verify your login - :app'), [':app' => $this->appName]),
        );
    }

    public function content(): Content
    {
        return new Content(
            markdown: 'bherila-auth::emails.two-factor-login',
        );
    }
}
