export interface EmailMessage {
  to: string;
  subject: string;
  text: string;
  html?: string;
}

/**
 * Email provider abstraction.
 * Implementations: SMTPEmailProvider (prod/MailHog), MockEmailProvider (tests).
 * Credentials come exclusively from environment configuration.
 */
export interface EmailProvider {
  send(message: EmailMessage): Promise<void>;
}
