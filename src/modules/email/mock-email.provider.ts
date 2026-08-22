import { EmailMessage, EmailProvider } from './email.types';
import { logger } from '../../common/logger';

/**
 * Dev/test provider: logs the message instead of delivering it.
 * Useful locally and in unit tests (asserts can hook into `sent`).
 */
export class MockEmailProvider implements EmailProvider {
  public readonly sent: EmailMessage[] = [];

  async send(message: EmailMessage): Promise<void> {
    this.sent.push({ ...message });
    logger.info({ to: message.to, subject: message.subject }, '[mock-email] message captured');
  }
}
