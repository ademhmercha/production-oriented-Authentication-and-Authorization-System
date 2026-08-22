import { createHash, randomBytes } from 'node:crypto';
import { Database } from '../../infrastructure/database/pool';
import { loadConfig } from '../../config';
import { AppError, AuthError } from '../../common/errors';

export interface RefreshTokenRow {
  id: string;
  session_id: string;
  user_id: string;
  client_id: string | null;
  token_hash: string;
  family_id: string;
  previous_token_id: string | null;
  scope: string;
  status: 'active' | 'rotated' | 'revoked';
  expires_at: Date;
}

/**
 * Opaque refresh tokens with rotation and reuse detection.
 *
 * SECURITY MODEL (industry standard - RFC 6819 / OAuth BCP):
 * - Tokens are 256-bit random strings; only SHA-256 hashes are stored.
 * - Every refresh rotates: old token -> 'rotated', new one issued in the
 *   same family (chain rooted at the original grant).
 * - Presenting a rotated/revoked token is treated as THEFT: the entire
 *   family plus its session is revoked (reuse detection) and audited.
 */
export class RefreshTokenService {
  constructor(private readonly db: Database) {}

  static hash(token: string): string {
    return createHash('sha256').update(token).digest('hex');
  }

  async issue(params: {
    sessionId: string;
    userId: string;
    clientId?: string | null;
    scope: string;
    familyId?: string;
    previousTokenId?: string | null;
  }): Promise<{ token: string; expiresAt: Date }> {
    const ttl = loadConfig().REFRESH_TOKEN_TTL;
    const token = randomBytes(32).toString('base64url');

    await this.db.query(
      `INSERT INTO refresh_tokens
         (session_id, user_id, client_id, token_hash, family_id, previous_token_id, scope, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, now() + make_interval(secs => $8))`,
      [
        params.sessionId,
        params.userId,
        params.clientId ?? null,
        RefreshTokenService.hash(token),
        params.familyId ?? crypto.randomUUID(),
        params.previousTokenId ?? null,
        params.scope,
        ttl,
      ],
    );
    return { token, expiresAt: new Date(Date.now() + ttl * 1000) };
  }

  /**
   * Validates a presented refresh token.
   * Throws AuthError('REFRESH_TOKEN_REUSE') when a rotated/revoked token is
   * replayed - callers must then revoke family + session.
   */
  async consume(token: string): Promise<{
    row: RefreshTokenRow;
    nextToken: string;
    expiresAt: Date;
  }> {
    const tokenHash = RefreshTokenService.hash(token);

    // Atomic single-use consumption: only an ACTIVE, unexpired token rotates.
    const rotateResult = await this.db.query<RefreshTokenRow>(
      `UPDATE refresh_tokens SET status = 'rotated', rotated_at = now()
       WHERE token_hash = $1 AND status = 'active' AND expires_at > now()
       RETURNING id, session_id, user_id, client_id, token_hash, family_id,
                 previous_token_id, scope, status, expires_at`,
      [tokenHash],
    );
    const row = rotateResult.rows[0];
    if (!row) {
      await this.handleReuseOrInvalid(tokenHash);
      throw new AuthError('Invalid refresh token', 'INVALID_REFRESH_TOKEN');
    }

    const next = await this.issue({
      sessionId: row.session_id,
      userId: row.user_id,
      clientId: row.client_id,
      scope: row.scope,
      familyId: row.family_id,
      previousTokenId: row.id,
    });
    return { row, nextToken: next.token, expiresAt: next.expiresAt };
  }

  private async handleReuseOrInvalid(tokenHash: string): Promise<void> {
    // Was this hash ever seen (i.e. it's a replay of a known token)?
    const known = await this.db.query<RefreshTokenRow>(
      `SELECT id, session_id, family_id FROM refresh_tokens WHERE token_hash = $1`,
      [tokenHash],
    );
    const knownRow = known.rows[0];
    if (knownRow) {
      // Reuse detected: kill the whole chain + the session.
      await this.db.query(
        `UPDATE refresh_tokens SET status = 'revoked', revoked_at = now()
         WHERE family_id = $1 AND status IN ('active', 'rotated')`,
        [knownRow.family_id],
      );
      await this.db.query(
        `UPDATE sessions SET status = 'revoked', revoked_at = now(), revoke_reason = 'refresh_token_reuse'
         WHERE id = $1 AND status = 'active'`,
        [knownRow.session_id],
      );
      throw new AppError(401, 'REFRESH_TOKEN_REUSE', 'Refresh token reuse detected - session revoked');
    }
    // Unknown hash: simply invalid (wrong/garbage/expired-and-purged).
  }

  /** Explicit revocation path for logout (single token or whole family). */
  async revokeByToken(token: string): Promise<boolean> {
    const tokenHash = RefreshTokenService.hash(token);
    const result = await this.db.query(
      `UPDATE refresh_tokens SET status = 'revoked', revoked_at = now()
       WHERE token_hash = $1 AND status IN ('active', 'rotated')`,
      [tokenHash],
    );
    return (result.rowCount ?? 0) > 0;
  }

  async revokeFamily(familyId: string): Promise<void> {
    await this.db.query(
      `UPDATE refresh_tokens SET status = 'revoked', revoked_at = now()
       WHERE family_id = $1 AND status IN ('active', 'rotated')`,
      [familyId],
    );
  }
}
