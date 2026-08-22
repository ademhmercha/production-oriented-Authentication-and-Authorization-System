import { Database } from '../../infrastructure/database/pool';
import { RedisService } from '../../infrastructure/redis/redis.service';

/**
 * Session persistence + cache.
 *
 * Sessions are the server-side anchor for refresh tokens and logout:
 * revoking a session immediately invalidates all its refresh tokens, while
 * already-issued short-lived access tokens simply expire (standard stateless
 * access-token trade-off; revocation cache covers high-risk cases).
 */
export interface SessionRow {
  id: string;
  user_id: string;
  client_id: string | null;
  ip: string | null;
  user_agent: string | null;
  device_id: string | null;
  mfa_passed: boolean;
  status: 'active' | 'revoked';
  expires_at: Date;
}

export class SessionRepository {
  constructor(
    private readonly db: Database,
    private readonly redis: RedisService,
  ) {}

  async create(params: {
    userId: string;
    clientId?: string | null;
    ip?: string | null;
    userAgent?: string | null;
    deviceId?: string | null;
    mfaPassed?: boolean;
    ttlSeconds: number;
  }): Promise<SessionRow> {
    const result = await this.db.query<SessionRow>(
      `INSERT INTO sessions (user_id, client_id, ip, user_agent, device_id, mfa_passed, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6, now() + make_interval(secs => $7))
       RETURNING id, user_id, client_id, ip, user_agent, device_id, mfa_passed, status, expires_at`,
      [
        params.userId,
        params.clientId ?? null,
        params.ip ?? null,
        params.userAgent ?? null,
        params.deviceId ?? null,
        params.mfaPassed ?? false,
        params.ttlSeconds,
      ],
    );
    return result.rows[0]!;
  }

  async findById(id: string): Promise<SessionRow | null> {
    // Fast path via cache.
    const cached = await this.redis.getJson<SessionRow>(RedisService.key('sess', id));
    if (cached) {
      if (cached.status !== 'active') return cached;
      const fresh = await this.loadFresh(id);
      if (!fresh) {
        await this.redis.del(RedisService.key('sess', id));
        return null;
      }
      return fresh;
    }
    return this.loadFresh(id);
  }

  private async loadFresh(id: string): Promise<SessionRow | null> {
    const result = await this.db.query<SessionRow>(
      `SELECT id, user_id, client_id, ip, user_agent, device_id, mfa_passed, status, expires_at
       FROM sessions WHERE id = $1`,
      [id],
    );
    const row = result.rows[0] ?? null;
    if (row) await this.redis.setJson(RedisService.key('sess', id), row, 300);
    return row;
  }

  async touch(id: string): Promise<void> {
    await this.db.query(`UPDATE sessions SET last_seen_at = now() WHERE id = $1`, [id]);
  }

  /** Revokes the session and every active refresh token inside it. */
  async revoke(id: string, reason: string): Promise<void> {
    await this.db.query(
      `UPDATE sessions SET status = 'revoked', revoked_at = now(), revoke_reason = $2
       WHERE id = $1 AND status = 'active'`,
      [id, reason],
    );
    await this.db.query(
      `UPDATE refresh_tokens SET status = 'revoked', revoked_at = now()
       WHERE session_id = $1 AND status IN ('active')`,
      [id],
    );
    await this.redis.del(RedisService.key('sess', id));
  }

  async revokeAllForUser(userId: string, reason: string): Promise<number> {
    const sessions = await this.db.query<{ id: string }>(
      `SELECT id FROM sessions WHERE user_id = $1 AND status = 'active'`,
      [userId],
    );
    await this.db.query(
      `UPDATE sessions SET status = 'revoked', revoked_at = now(), revoke_reason = $2
       WHERE user_id = $1 AND status = 'active'`,
      [userId, reason],
    );
    await this.db.query(
      `UPDATE refresh_tokens SET status = 'revoked', revoked_at = now()
       WHERE user_id = $1 AND status IN ('active', 'rotated')`,
      [userId],
    );
    await this.redis.delByPrefix(`${RedisService.key('sess')}:`);
    return sessions.rowCount ?? 0;
  }
}
