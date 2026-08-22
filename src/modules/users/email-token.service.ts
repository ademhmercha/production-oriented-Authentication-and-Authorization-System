import { createHash, randomBytes } from 'node:crypto';
import { Database } from '../../infrastructure/database/pool';
import { loadConfig } from '../../config';

/**
 * Opaque, hashed, single-use tokens for email verification and password
 * reset. Only the SHA-256 hash is persisted; the raw token lives solely in
 * the email we send out.
 */
export class EmailTokenService {
  constructor(private readonly db: Database) {}

  static newToken(): { token: string; tokenHash: string } {
    const token = randomBytes(32).toString('base64url');
    return { token, tokenHash: EmailTokenService.hash(token) };
  }

  static hash(token: string): string {
    return createHash('sha256').update(token).digest('hex');
  }

  async issueEmailVerification(userId: string, email: string): Promise<string> {
    const ttl = loadConfig().EMAIL_VERIFICATION_TTL;
    const { token, tokenHash } = EmailTokenService.newToken();
    await this.db.query(
      `INSERT INTO email_verifications (user_id, token_hash, email, expires_at)
       VALUES ($1, $2, $3, now() + make_interval(secs => $4))`,
      [userId, tokenHash, email.toLowerCase(), ttl],
    );
    return token;
  }

  /**
   * Consumes a verification token. Returns the user id when valid.
   * Single-use: consumed_at set inside the same statement that matches.
   */
  async consumeEmailVerification(token: string): Promise<{ userId: string } | null> {
    const tokenHash = EmailTokenService.hash(token);
    const result = await this.db.query<{ id: string; user_id: string; email: string }>(
      `UPDATE email_verifications SET consumed_at = now()
       WHERE token_hash = $1 AND consumed_at IS NULL AND expires_at > now()
       RETURNING id, user_id, email`,
      [tokenHash],
    );
    const row = result.rows[0];
    if (!row) return null;
    return { userId: row.user_id };
  }

  async issuePasswordReset(userId: string): Promise<string> {
    const ttl = loadConfig().PASSWORD_RESET_TTL;
    const { token, tokenHash } = EmailTokenService.newToken();
    await this.db.query(
      `INSERT INTO password_reset_tokens (user_id, token_hash, expires_at)
       VALUES ($1, $2, now() + make_interval(secs => $3))`,
      [userId, tokenHash, ttl],
    );
    return token;
  }

  async consumePasswordReset(token: string): Promise<{ userId: string } | null> {
    const tokenHash = EmailTokenService.hash(token);
    const result = await this.db.query<{ user_id: string }>(
      `UPDATE password_reset_tokens SET used_at = now()
       WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now()
       RETURNING user_id`,
      [tokenHash],
    );
    const row = result.rows[0];
    if (!row) return null;
    return { userId: row.user_id };
  }
}
