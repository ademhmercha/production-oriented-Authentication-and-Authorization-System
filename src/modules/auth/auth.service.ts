import { JwtService } from '../tokens/jwt.service';
import { RefreshTokenService } from '../tokens/refresh-token.service';
import { SessionRepository } from '../sessions/session.repository';
import { UserRepository } from '../users/user.repository';
import { EmailTokenService } from '../users/email-token.service';
import { MfaService } from '../mfa/mfa.service';
import { RiskEngine } from '../risk/risk.types';
import { RiskEventRepository } from '../risk/risk-event.repository';
import { AuditLogService } from '../audit/audit.service';
import { AuditEventType } from '../audit/audit.types';
import { EmailProvider } from '../email/email.types';
import {
  checkPasswordPolicy,
  hashPassword,
  verifyPassword,
} from '../users/password.service';
import { deviceFingerprint } from '../risk/rules-risk.engine';
import { loadConfig } from '../../config';
import { RedisService } from '../../infrastructure/redis/redis.service';
import { RequestContext } from '../../common/decorators/request-context';
import {
  AppError,
  AuthError,
  ForbiddenError,
  InvalidCredentialsError,
} from '../../common/errors';

export interface LoginResultSuccess {
  outcome: 'success';
  access_token: string;
  token_type: 'Bearer';
  expires_in: number;
  refresh_token: string;
  refresh_expires_at: Date;
  scope: string;
  roles: string[];
  user: { id: string; email: string; status: string };
}

export interface LoginResultMfaRequired {
  outcome: 'mfa_required';
  mfa_required: true;
  mfa_challenge_id: string;
}

/**
 * Core authentication orchestration.
 *
 * Login pipeline:
 *   credential validation -> account status checks -> lockout handling ->
 *   risk evaluation -> MFA challenge -> session creation -> token issuance ->
 *   audit events.
 */
export class AuthService {
  constructor(
    private readonly users: UserRepository,
    private readonly sessions: SessionRepository,
    private readonly refreshTokens: RefreshTokenService,
    private readonly jwt: JwtService,
    private readonly mfa: MfaService,
    private readonly riskEngine: RiskEngine,
    private readonly riskEvents: RiskEventRepository,
    private readonly audit: AuditLogService,
    private readonly emailTokens: EmailTokenService,
    private readonly emailProvider: EmailProvider,
    private readonly redis: RedisService,
  ) {}

  async login(
    input: { email: string; password: string },
    ctx: RequestContext,
  ): Promise<LoginResultSuccess | LoginResultMfaRequired> {
    const config = loadConfig();
    const user = await this.users.findByEmail(input.email);

    if (!user) {
      await this.audit.record({
        event_type: AuditEventType.USER_LOGIN_FAILED,
        ip: ctx.ip,
        user_agent: ctx.userAgent,
        request_id: ctx.requestId,
        metadata: { reason: 'unknown_email' },
      });
      // Constant-shape response regardless of user existence.
      throw new InvalidCredentialsError();
    }

    // ---- Account status gates ----
    const now = new Date();
    if (user.status === 'disabled') {
      throw new ForbiddenError('Account is disabled', 'ACCOUNT_DISABLED');
    }
    if (user.locked_until && user.locked_until > now) {
      throw new AppError(423, 'ACCOUNT_LOCKED', 'Account temporarily locked');
    }

    // ---- Credential verification (constant work for existing users) ----
    const passwordOk = await verifyPassword(user.password_hash, input.password);
    if (!passwordOk) {
      await this.users.recordFailedLogin(user.id);
      const failures = user.failed_login_count + 1;
      if (failures >= config.MAX_FAILED_LOGINS) {
        const until = new Date(Date.now() + config.LOCKOUT_MINUTES * 60_000);
        await this.users.lockUntil(user.id, until);
        await this.audit.record({
          event_type: AuditEventType.USER_LOCKED,
          user_id: user.id,
          ip: ctx.ip,
          user_agent: ctx.userAgent,
          request_id: ctx.requestId,
          metadata: { failures },
        });
      }
      await this.audit.record({
        event_type: AuditEventType.USER_LOGIN_FAILED,
        user_id: user.id,
        ip: ctx.ip,
        user_agent: ctx.userAgent,
        request_id: ctx.requestId,
        metadata: { reason: 'bad_password', failures },
      });
      throw new InvalidCredentialsError();
    }

    if (user.status === 'pending_verification') {
      throw new AuthError('Email address not verified', 'EMAIL_NOT_VERIFIED');
    }

    // ---- Risk evaluation ----
    const knownDevice = await this.isKnownDevice(user.id, ctx);
    const evaluation = await this.riskEngine.evaluateLogin({
      userId: user.id,
      ip: ctx.ip,
      userAgent: ctx.userAgent,
      knownDevice,
    });

    let action = 'allow';
    if (evaluation.level === 'high' || evaluation.level === 'medium') {
      await this.audit.record({
        event_type: AuditEventType.SUSPICIOUS_LOGIN,
        user_id: user.id,
        ip: ctx.ip,
        user_agent: ctx.userAgent,
        request_id: ctx.requestId,
        metadata: { score: evaluation.score, signals: evaluation.signals },
      });
      action = evaluation.level === 'high' ? config.RISK_HIGH_SCORE_ACTION : 'allow';
    }
    await this.riskEvents.record({
      userId: user.id,
      eventType: 'login',
      evaluation,
      actionTaken: action,
      ip: ctx.ip,
      userAgent: ctx.userAgent,
      requestId: ctx.requestId,
    });

    if (action === 'deny') {
      await this.audit.record({
        event_type: AuditEventType.AUTHORIZATION_DENIED,
        user_id: user.id,
        ip: ctx.ip,
        request_id: ctx.requestId,
        metadata: { reason: 'high_risk_login' },
      });
      throw new AppError(403, 'RISK_DENIED', 'Login denied due to suspicious activity');
    }

    // ---- Session + tokens (or MFA challenge) ----
    const hasMfa = await this.mfa.hasActiveMethod(user.id);
    if (hasMfa || action === 'mfa') {
      if (!hasMfa && action === 'mfa') {
        // Risk demands step-up but no second factor is enrolled.
        throw new AppError(403, 'MFA_ENROLLMENT_REQUIRED',
          'Additional verification is required. Enroll a second factor first.');
      }
      const session = await this.sessions.create({
        userId: user.id,
        ip: ctx.ip ?? null,
        userAgent: ctx.userAgent ?? null,
        deviceId: deviceFingerprint(ctx.userAgent ?? ''),
        mfaPassed: false,
        ttlSeconds: config.SESSION_TTL,
      });
      const challengeId = await this.mfa.createLoginChallenge(user.id, session.id);
      return { outcome: 'mfa_required', mfa_required: true, mfa_challenge_id: challengeId };
    }

    return this.issueSessionTokens(user.id, ctx, ['pwd']);
  }

  /** Completes an MFA challenge and issues tokens. */
  async completeMfaChallenge(challengeId: string, code: string, ctx: RequestContext): Promise<LoginResultSuccess> {
    const config = loadConfig();
    const { sessionId } = await this.mfa.verifyLoginChallenge(challengeId, code);
    const session = await this.sessions.findById(sessionId);
    if (!session || session.status !== 'active') {
      throw new AuthError('Session no longer valid', 'SESSION_INVALID');
    }
    await this.audit.record({
      event_type: AuditEventType.MFA_CHALLENGE_SUCCEEDED,
      user_id: session.user_id,
      ip: ctx.ip,
      request_id: ctx.requestId,
    });
    void config;
    return this.issueSessionTokensForSession(session.id, session.user_id, ['pwd', 'mfa'], ctx);
  }

  async refresh(refreshToken: string, ctx: RequestContext): Promise<LoginResultSuccess> {
    const config = loadConfig();
    try {
      const { row, nextToken, expiresAt } = await this.refreshTokens.consume(refreshToken);

      // The parent session must still be alive.
      const session = await this.sessions.findById(row.session_id);
      if (!session || session.status !== 'active') {
        await this.refreshTokens.revokeFamily(row.family_id);
        throw new AuthError('Session revoked', 'SESSION_REVOKED');
      }

      const roles = await this.users.rolesOf(row.user_id);
      const permissions = await this.users.permissionsOf(row.user_id);
      const amr = session.mfa_passed ? ['pwd', 'mfa'] : ['pwd'];
      const signed = await this.jwt.signAccessToken({
        sub: row.user_id,
        scope: row.scope,
        roles,
        permissions,
        sid: session.id,
        client_id: row.client_id ?? undefined,
        amr,
      });

      await this.sessions.touch(session.id);
      await this.audit.record({
        event_type: AuditEventType.TOKEN_REFRESHED,
        user_id: row.user_id,
        client_id: row.client_id,
        ip: ctx.ip,
        request_id: ctx.requestId,
        metadata: { session_id: session.id },
      });
      void config;

      return {
        outcome: 'success',
        access_token: signed.token,
        token_type: 'Bearer',
        expires_in: Math.floor((signed.expiresAt.getTime() - Date.now()) / 1000),
        refresh_token: nextToken,
        refresh_expires_at: expiresAt,
        scope: row.scope,
        roles,
        user: { id: row.user_id, email: '', status: '' },
      };
    } catch (err) {
      if ((err as AppError).code === 'REFRESH_TOKEN_REUSE') {
        await this.audit.record({
          event_type: AuditEventType.REFRESH_TOKEN_REUSE_DETECTED,
          ip: ctx.ip,
          request_id: ctx.requestId,
        });
      }
      throw err;
    }
  }

  async logout(userId: string, sessionId: string | undefined, allSessions: boolean,
    refreshToken?: string, ctx?: RequestContext): Promise<{ revoked_sessions: number }> {
    if (allSessions) {
      const count = await this.sessions.revokeAllForUser(userId, 'logout_all');
      await this.audit.record({
        event_type: AuditEventType.USER_LOGOUT,
        user_id: userId,
        ip: ctx?.ip,
        request_id: ctx?.requestId,
        metadata: { scope: 'all_sessions', revoked_sessions: count },
      });
      return { revoked_sessions: count };
    }

    if (sessionId) {
      await this.sessions.revoke(sessionId, 'logout');
    }
    if (refreshToken) {
      await this.refreshTokens.revokeByToken(refreshToken);
    }
    await this.audit.record({
      event_type: AuditEventType.USER_LOGOUT,
      user_id: userId,
      ip: ctx?.ip,
      request_id: ctx?.requestId,
      metadata: { scope: sessionId ? 'current_session' : 'token_only' },
    });
    return { revoked_sessions: sessionId ? 1 : 0 };
  }

  async me(userId: string): Promise<{
    id: string;
    email: string;
    first_name: string | null;
    last_name: string | null;
    status: string;
    roles: string[];
    permissions: string[];
    mfa_enabled: boolean;
  }> {
    const user = await this.users.findById(userId);
    if (!user) throw new AuthError('User not found', 'USER_NOT_FOUND');
    const [roles, permissions, mfaEnabled] = await Promise.all([
      this.users.rolesOf(userId),
      this.users.permissionsOf(userId),
      this.mfa.hasActiveMethod(userId),
    ]);
    return {
      id: user.id,
      email: user.email,
      first_name: user.first_name,
      last_name: user.last_name,
      status: user.status,
      roles,
      permissions,
      mfa_enabled: mfaEnabled,
    };
  }

  /**
   * Forgot password: ALWAYS returns success to prevent account enumeration;
   * the reset email is sent only when the account exists.
   */
  async forgotPassword(email: string, ctx: RequestContext): Promise<void> {
    const user = await this.users.findByEmail(email);
    if (user && user.status !== 'disabled') {
      const token = await this.emailTokens.issuePasswordReset(user.id);
      await this.emailProvider.send({
        to: user.email,
        subject: 'Reset your password',
        text: `Use this token to reset your password:\n\n${token}\n\nExpires in ${loadConfig().PASSWORD_RESET_TTL / 60} minutes.`,
      });
      await this.audit.record({
        event_type: AuditEventType.PASSWORD_RESET_REQUESTED,
        user_id: user.id,
        ip: ctx.ip,
        user_agent: ctx.userAgent,
        request_id: ctx.requestId,
      });
    }
  }

  async resetPassword(token: string, newPassword: string, ctx: RequestContext): Promise<void> {
    checkPasswordPolicy(newPassword);

    const consumed = await this.emailTokens.consumePasswordReset(token);
    if (!consumed) {
      throw new AppError(400, 'INVALID_RESET_TOKEN', 'Invalid or expired reset token');
    }

    const passwordHash = await hashPassword(newPassword);
    await this.users.updatePasswordHash(consumed.userId, passwordHash);
    // Password change invalidates every active session.
    await this.sessions.revokeAllForUser(consumed.userId, 'password_reset');

    await this.audit.record({
      event_type: AuditEventType.PASSWORD_RESET_COMPLETED,
      user_id: consumed.userId,
      ip: ctx.ip,
      request_id: ctx.requestId,
    });
    await this.audit.record({
      event_type: AuditEventType.PASSWORD_CHANGED,
      user_id: consumed.userId,
      ip: ctx.ip,
      request_id: ctx.requestId,
      metadata: { via: 'reset_token' },
    });
  }

  // ---------- internals ----------

  private async isKnownDevice(userId: string, ctx: RequestContext): Promise<boolean> {
    if (!ctx.userAgent || !ctx.ip) return false;
    const fingerprint = deviceFingerprint(ctx.userAgent);
    const key = RedisService.key('risk', 'device', userId, fingerprint);
    const seen = await this.redis.get(key);
    if (!seen) {
      await this.redis.set(key, ctx.ip, 60 * 60 * 24 * 30); // remember 30 days
      return false;
    }
    return true;
  }

  private async issueSessionTokens(
    userId: string,
    ctx: RequestContext,
    amr: string[],
  ): Promise<LoginResultSuccess> {
    const config = loadConfig();
    const session = await this.sessions.create({
      userId,
      ip: ctx.ip ?? null,
      userAgent: ctx.userAgent ?? null,
      deviceId: deviceFingerprint(ctx.userAgent ?? ''),
      mfaPassed: amr.includes('mfa'),
      ttlSeconds: config.SESSION_TTL,
    });
    return this.issueSessionTokensForSession(session.id, userId, amr, ctx);
  }

  private async issueSessionTokensForSession(
    sessionId: string,
    userId: string,
    amr: string[],
    ctx: RequestContext,
  ): Promise<LoginResultSuccess> {
    const config = loadConfig();
    const user = await this.users.findById(userId);
    if (!user) throw new AuthError('User not found', 'USER_NOT_FOUND');

    const roles = await this.users.rolesOf(userId);
    const permissions = await this.users.permissionsOf(userId);
    const scope = defaultScopeForRoles(roles);

    const signed = await this.jwt.signAccessToken({
      sub: userId,
      scope,
      roles,
      permissions,
      sid: sessionId,
      amr,
    });
    const refresh = await this.refreshTokens.issue({
      sessionId,
      userId,
      scope,
    });

    await this.users.setLastLogin(userId);
    await this.users.clearLockAndFailures(userId);

    await this.audit.record({
      event_type: AuditEventType.USER_LOGIN_SUCCESS,
      user_id: userId,
      ip: ctx.ip,
      user_agent: ctx.userAgent,
      request_id: ctx.requestId,
      metadata: { session_id: sessionId, amr },
    });
    await this.audit.record({
      event_type: AuditEventType.TOKEN_ISSUED,
      user_id: userId,
      ip: ctx.ip,
      request_id: ctx.requestId,
      metadata: { kind: 'access+refresh', session_id: sessionId },
    });
    void config;

    return {
      outcome: 'success',
      access_token: signed.token,
      token_type: 'Bearer',
      expires_in: Math.floor((signed.expiresAt.getTime() - Date.now()) / 1000),
      refresh_token: refresh.token,
      refresh_expires_at: refresh.expiresAt,
      scope,
      roles,
      user: { id: user.id, email: user.email, status: user.status },
    };
  }
}

function defaultScopeForRoles(roles: string[]): string {
  // End users authenticate with the standard identity scopes plus API read.
  const scopes = ['openid', 'profile', 'email', 'api.read'];
  if (roles.includes('admin')) scopes.push('api.write');
  return scopes.join(' ');
}
