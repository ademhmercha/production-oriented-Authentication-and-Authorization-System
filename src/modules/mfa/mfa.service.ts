import { authenticator } from 'otplib';
import QRCode from 'qrcode';
import { Database } from '../../infrastructure/database/pool';
import { RedisService } from '../../infrastructure/redis/redis.service';
import { KeyManagementService } from '../keys/kms.types';
import { AuthError } from '../../common/errors';
import { loadConfig } from '../../config';

export interface MfaChallengePayload {
  userId: string;
  sessionId: string;
  attempts: number;
}

/**
 * TOTP MFA (RFC 6238) via otplib - no custom cryptography.
 *
 * Secrets are stored ENCRYPTED with a KMS-derived key (envelope from
 * KeyManagementService), never in plaintext columns.
 *
 * Login integration:
 *   password ok -> risk check -> if active TOTP: create short-lived
 *   challenge in Redis and return mfa_required; tokens only issued after
 *   /mfa/verify succeeds (or when user has no TOTP and risk is low).
 */
export class MfaService {
  constructor(
    private readonly db: Database,
    private readonly kms: KeyManagementService,
    private readonly redis: RedisService,
  ) {}

  /** Step 1 of enrollment: provision secret + QR, stored as pending. */
  async beginEnroll(userId: string, email: string): Promise<{ otpauth_url: string; qr_data_url: string }> {
    const config = loadConfig();
    const secret = authenticator.generateSecret();
    const encrypted = await this.kms.encrypt(Buffer.from(secret, 'utf8'));

    await this.db.query(
      `INSERT INTO mfa_methods (user_id, type, secret_encrypted, status)
       VALUES ($1, 'totp', $2, 'pending')
       ON CONFLICT (user_id, type) DO UPDATE
         SET secret_encrypted = EXCLUDED.secret_encrypted, status = 'pending',
             enrolled_at = NULL, last_used_at = NULL`,
      [userId, JSON.stringify(encrypted)],
    );

    const otpauthUrl = authenticator.keyuri(email, config.MFA_ISSUER, secret);
    const qrDataUrl = await QRCode.toDataURL(otpauthUrl);
    return { otpauth_url: otpauthUrl, qr_data_url: qrDataUrl };
  }

  /** Step 2: confirm enrollment by proving possession of the device. */
  async confirmEnroll(userId: string, code: string): Promise<void> {
    const method = await this.getPendingMethod(userId);
    if (!method) throw new AuthError('No pending MFA enrollment', 'MFA_NOT_ENROLLING');

    const secret = await this.decryptSecret(method.secret_encrypted);
    if (!authenticator.check(code, secret)) {
      throw new AuthError('Invalid MFA code', 'INVALID_MFA_CODE');
    }
    await this.db.query(
      `UPDATE mfa_methods SET status = 'active', enrolled_at = now(), is_primary = TRUE
       WHERE user_id = $1 AND type = 'totp'`,
      [userId],
    );
    await this.db.query(`UPDATE users SET mfa_required = TRUE WHERE id = $1`, [userId]);
  }

  async hasActiveMethod(userId: string): Promise<boolean> {
    const result = await this.db.query<{ exists: boolean }>(
      `SELECT EXISTS(SELECT 1 FROM mfa_methods WHERE user_id = $1 AND type = 'totp' AND status = 'active') AS exists`,
      [userId],
    );
    return result.rows[0]?.exists === true;
  }

  async getEmailForUser(userId: string): Promise<string> {
    const result = await this.db.query<{ email: string }>(`SELECT email FROM users WHERE id = $1`, [userId]);
    if (!result.rows[0]) throw new AuthError('User not found', 'USER_NOT_FOUND');
    return result.rows[0].email;
  }

  /** Creates the login-time challenge (Redis, TTL-limited). */
  async createLoginChallenge(userId: string, sessionId: string): Promise<string> {
    const challengeId = crypto.randomUUID();
    await this.redis.setJson(MfaService.challengeKey(challengeId), {
      userId,
      sessionId,
      attempts: 0,
    }, loadConfig().MFA_CHALLENGE_TTL);
    return challengeId;
  }

  /**
   * Verifies the login challenge code. On success marks the session as
   * MFA-passed and consumes the challenge. Max 3 attempts.
   */
  async verifyLoginChallenge(challengeId: string, code: string): Promise<{ sessionId: string }> {
    const key = MfaService.challengeKey(challengeId);
    const challenge = await this.redis.getJson<MfaChallengePayload>(key);
    if (!challenge) throw new AuthError('Invalid or expired MFA challenge', 'INVALID_MFA_CHALLENGE');

    if (challenge.attempts >= 3) {
      await this.redis.del(key);
      throw new AuthError('Too many MFA attempts', 'MFA_ATTEMPTS_EXCEEDED');
    }

    const method = await this.getActiveMethod(challenge.userId);
    const secret = method ? await this.decryptSecret(method.secret_encrypted) : null;
    if (!secret || !authenticator.check(code, secret)) {
      await this.redis.setJson(key, { ...challenge, attempts: challenge.attempts + 1 },
        loadConfig().MFA_CHALLENGE_TTL);
      throw new AuthError('Invalid MFA code', 'INVALID_MFA_CODE');
    }

    await this.db.query(`UPDATE sessions SET mfa_passed = TRUE WHERE id = $1`, [challenge.sessionId]);
    await this.db.query(`UPDATE mfa_methods SET last_used_at = now() WHERE id = $1`, [method!.id]);
    await this.redis.del(key);
    return { sessionId: challenge.sessionId };
  }

  async disable(userId: string, code: string): Promise<void> {
    const method = await this.getActiveMethod(userId);
    if (!method) throw new AuthError('MFA is not enabled', 'MFA_NOT_ENABLED');
    const secret = await this.decryptSecret(method.secret_encrypted);
    if (!authenticator.check(code, secret)) {
      throw new AuthError('Invalid MFA code', 'INVALID_MFA_CODE');
    }
    await this.db.query(
      `UPDATE mfa_methods SET status = 'disabled' WHERE id = $1`,
      [method.id],
    );
    await this.db.query(`UPDATE users SET mfa_required = FALSE WHERE id = $1`, [userId]);
  }

  // internals

  private static challengeKey(id: string): string {
    return RedisService.key('mfa', 'challenge', id);
  }

  private async getActiveMethod(userId: string): Promise<MfaMethodRow | null> {
    const result = await this.db.query<MfaMethodRow>(
      `SELECT id, user_id, secret_encrypted, status FROM mfa_methods
       WHERE user_id = $1 AND type = 'totp' AND status = 'active'`,
      [userId],
    );
    return result.rows[0] ?? null;
  }

  private async getPendingMethod(userId: string): Promise<MfaMethodRow | null> {
    const result = await this.db.query<MfaMethodRow>(
      `SELECT id, user_id, secret_encrypted, status FROM mfa_methods
       WHERE user_id = $1 AND type = 'totp' AND status = 'pending'`,
      [userId],
    );
    return result.rows[0] ?? null;
  }

  private async decryptSecret(stored: string): Promise<string> {
    const envelope = JSON.parse(stored);
    const buf = await this.kms.decrypt(envelope);
    return buf.toString('utf8');
  }
}

interface MfaMethodRow {
  id: string;
  user_id: string;
  secret_encrypted: string;
  status: string;
}
