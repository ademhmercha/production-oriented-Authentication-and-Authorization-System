import { loadConfig } from '../../config';
import { EmailProvider } from './email.types';
import { MockEmailProvider } from './mock-email.provider';
import { SMTPEmailProvider } from './smtp-email.provider';

let singleton: EmailProvider | null = null;

export function getEmailProvider(): EmailProvider {
  if (singleton) return singleton;
  const config = loadConfig();
  singleton =
    config.EMAIL_PROVIDER === 'smtp'
      ? new SMTPEmailProvider({
          host: config.SMTP_HOST ?? 'localhost',
          port: config.SMTP_PORT,
          secure: config.EMAIL_SECURE,
          user: config.SMTP_USER,
          password: config.SMTP_PASSWORD,
          from: config.SMTP_FROM,
        })
      : new MockEmailProvider();
  return singleton;
}

/** Test seam. */
export function setEmailProvider(provider: EmailProvider | null): void {
  singleton = provider;
}
