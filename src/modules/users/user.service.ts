import { UserRepository, UserRow } from './user.repository';
import { EmailTokenService } from './email-token.service';
import { checkPasswordPolicy, hashPassword } from './password.service';
import { AuditLogService } from '../audit/audit.service';
import { AuditEventType } from '../audit/audit.types';
import { EmailProvider } from '../email/email.types';
import { ConflictError } from '../../common/errors';
import { RequestContext } from '../../common/decorators/request-context';

export interface RegisterInput {
  email: string;
  password: string;
  first_name?: string;
  last_name?: string;
}

/** Public representation - NEVER includes password hash. */
export interface PublicUser {
  id: string;
  email: string;
  first_name: string | null;
  last_name: string | null;
  status: UserRow['status'];
  mfa_required: boolean;
  created_at: Date;
}

export function toPublicUser(row: UserRow): PublicUser {
  return {
    id: row.id,
    email: row.email,
    first_name: row.first_name,
    last_name: row.last_name,
    status: row.status,
    mfa_required: row.mfa_required,
    created_at: row.created_at,
  };
}

/**
 * User lifecycle service: registration, profile, account state.
 * Business rules live here - controllers stay thin.
 */
export class UserService {
  constructor(
    private readonly users: UserRepository,
    private readonly emailTokens: EmailTokenService,
    private readonly audit: AuditLogService,
    private readonly emailProvider: EmailProvider,
  ) {}

  async register(input: RegisterInput, ctx: RequestContext): Promise<PublicUser> {
    // Password policy enforced in the service layer (not only validation
    // middleware) so every caller path is protected.
    checkPasswordPolicy(input.password);

    const existing = await this.users.findByEmail(input.email);
    if (existing) {
      throw new ConflictError('Email is already registered');
    }

    const passwordHash = await hashPassword(input.password);
    const user = await this.users.create({
      email: input.email,
      passwordHash,
      firstName: input.first_name ?? null,
      lastName: input.last_name ?? null,
    });

    await this.audit.record({
      event_type: AuditEventType.USER_REGISTERED,
      user_id: user.id,
      ip: ctx.ip,
      user_agent: ctx.userAgent,
      request_id: ctx.requestId,
      metadata: { email_domain: user.email.split('@')[1] },
    });

    // Verification email (token only inside the email, never in logs).
    const token = await this.emailTokens.issueEmailVerification(user.id, user.email);
    await this.emailProvider.send({
      to: user.email,
      subject: 'Verify your email address',
      text:
        `Welcome! Verify your email with this token:\n\n${token}\n\n` +
        `POST it to /auth/verify-email within 24 hours.`,
      html: `<p>Welcome!</p><p>Verify your email by posting this token to <code>/auth/verify-email</code>:</p><pre>${token}</pre>`,
    });

    return toPublicUser(user);
  }

  async verifyEmail(token: string, ctx: RequestContext): Promise<void> {
    const consumed = await this.emailTokens.consumeEmailVerification(token);
    if (!consumed) {
      // Generic error - do not distinguish expired vs invalid vs unknown.
      throw new ConflictError('Invalid or expired verification token');
    }
    await this.users.markVerified(consumed.userId);
    await this.audit.record({
      event_type: AuditEventType.USER_EMAIL_VERIFIED,
      user_id: consumed.userId,
      ip: ctx.ip,
      request_id: ctx.requestId,
    });
  }

  async getById(id: string): Promise<PublicUser | null> {
    const row = await this.users.findById(id);
    return row ? toPublicUser(row) : null;
  }
}
