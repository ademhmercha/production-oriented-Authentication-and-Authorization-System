import nodemailer, { Transporter } from 'nodemailer';
import { EmailMessage, EmailProvider } from './email.types';

export interface SmtpOptions {
  host: string;
  port: number;
  secure: boolean;
  user?: string;
  password?: string;
  from: string;
}

/** SMTP delivery via nodemailer; works with MailHog/Mailpit in development. */
export class SMTPEmailProvider implements EmailProvider {
  private readonly transporter: Transporter;
  public readonly from: string;

  constructor(options: SmtpOptions) {
    this.from = options.from;
    this.transporter = nodemailer.createTransport({
      host: options.host,
      port: options.port,
      secure: options.secure,
      auth:
        options.user && options.password
          ? { user: options.user, pass: options.password }
          : undefined,
    });
  }

  async send(message: EmailMessage): Promise<void> {
    await this.transporter.sendMail({
      from: this.from,
      to: message.to,
      subject: message.subject,
      text: message.text,
      html: message.html,
    });
  }
}
