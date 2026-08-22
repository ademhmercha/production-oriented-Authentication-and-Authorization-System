import { createHash, randomBytes } from 'node:crypto';
import { Database } from '../../infrastructure/database/pool';

export interface AuthorizationCodeRow {
  id: string;
  code_hash: string;
  client_id: string;
  user_id: string;
  redirect_uri: string;
  scope: string;
  nonce: string | null;
  code_challenge: string | null;
  code_challenge_method: string | null;
  expires_at: Date;
  consumed_at: Date | null;
}

interface JoinedRow extends AuthorizationCodeRow {
  client_ref: string;
}

/** Thrown when a consumed authorization code is presented again (RFC 6749 §4.1.2). */
export class CodeReplayError extends Error {
  constructor(
    public readonly userId: string,
    public readonly clientRef: string,
  ) {
    super('Authorization code replay detected');
    this.name = 'CodeReplayError';
  }
}

/**
 * Authorization codes: short-lived, single-use, stored HASHED.
 *
 * Per RFC 6749 §4.1.2 + OAuth BCP: presenting a consumed code is treated as
 * a possible replay attack - callers revoke all tokens issued on that code.
 */
export class AuthorizationCodeRepository {
  constructor(private readonly db: Database) {}

  static hash(code: string): string {
    return createHash('sha256').update(code).digest('hex');
  }

  static newCode(): string {
    return randomBytes(32).toString('base64url');
  }

  async issue(params: {
    clientId: string;
    userId: string;
    redirectUri: string;
    scope: string;
    nonce?: string | null;
    codeChallenge?: string | null;
    codeChallengeMethod?: string | null;
    ttlSeconds: number;
  }): Promise<string> {
    const code = AuthorizationCodeRepository.newCode();
    await this.db.query(
      `INSERT INTO authorization_codes
         (code_hash, client_id, user_id, redirect_uri, scope, nonce,
          code_challenge, code_challenge_method, expires_at)
       VALUES ($1,
               (SELECT id FROM oauth_clients WHERE client_id = $2),
               $3, $4, $5, $6, $7, $8, now() + make_interval(secs => $9))`,
      [
        AuthorizationCodeRepository.hash(code),
        params.clientId,
        params.userId,
        params.redirectUri,
        params.scope,
        params.nonce ?? null,
        params.codeChallenge ?? null,
        params.codeChallengeMethod ?? null,
        params.ttlSeconds,
      ],
    );
    return code;
  }

  /**
   * Reads binding info WITHOUT consuming (used to validate PKCE before
   * burning the single-use code).
   */
  async peek(params: {
    code: string;
    clientId: string;
    redirectUri: string;
  }): Promise<AuthorizationCodeRow | null> {
    const existing = await this.db.query<JoinedRow>(
      `SELECT ac.id, ac.code_hash, c.client_id AS client_ref, ac.user_id,
              ac.redirect_uri, ac.scope, ac.nonce, ac.code_challenge,
              ac.code_challenge_method, ac.expires_at, ac.consumed_at
       FROM authorization_codes ac
       JOIN oauth_clients c ON c.id = ac.client_id
       WHERE ac.code_hash = $1`,
      [AuthorizationCodeRepository.hash(params.code)],
    );
    const row = existing.rows[0];
    if (!row) return null;
    if (row.client_ref !== params.clientId || row.redirect_uri !== params.redirectUri) {
      return null;
    }
    if (row.consumed_at) throw new CodeReplayError(row.user_id, row.client_ref);
    if (new Date(row.expires_at).getTime() < Date.now()) return null;
    return row;
  }

  /**
   * Single-use consumption with binding validation (client_id + redirect_uri).
   * - unknown/expired/mismatched -> null
   * - replay of a consumed code  -> throws CodeReplayError (carries owner info)
   */
  async consume(params: {
    code: string;
    clientId: string;
    redirectUri: string;
  }): Promise<AuthorizationCodeRow | null> {
    const codeHash = AuthorizationCodeRepository.hash(params.code);

    const existing = await this.db.query<JoinedRow>(
      `SELECT ac.id, ac.code_hash, c.client_id AS client_ref, ac.user_id,
              ac.redirect_uri, ac.scope, ac.nonce, ac.code_challenge,
              ac.code_challenge_method, ac.expires_at, ac.consumed_at
       FROM authorization_codes ac
       JOIN oauth_clients c ON c.id = ac.client_id
       WHERE ac.code_hash = $1`,
      [codeHash],
    );
    const row = existing.rows[0];
    if (!row) return null;

    if (row.client_ref !== params.clientId || row.redirect_uri !== params.redirectUri) {
      return null;
    }

    // A previously CONSUMED code being presented again is a replay.
    if (row.consumed_at) {
      throw new CodeReplayError(row.user_id, row.client_ref);
    }

    if (new Date(row.expires_at).getTime() < Date.now()) {
      return null;
    }

    // Atomic single-use flip; losing the race means the code was replayed.
    const updated = await this.db.query<JoinedRow>(
      `UPDATE authorization_codes SET consumed_at = now()
       WHERE id = $1 AND consumed_at IS NULL
       RETURNING id, code_hash, client_id, user_id, redirect_uri, scope, nonce,
                 code_challenge, code_challenge_method, expires_at, consumed_at`,
      [row.id],
    );
    if (!updated.rows[0]) {
      throw new CodeReplayError(row.user_id, row.client_ref);
    }
    return updated.rows[0];
  }

  /**
   * Replay response: revoke every active refresh token of this user+client.
   * Accepts the public client_id string and resolves the DB uuid internally.
   */
  async revokeTokensForReplay(userId: string, clientRef: string): Promise<void> {
    await this.db.query(
      `UPDATE refresh_tokens SET status = 'revoked', revoked_at = now()
       WHERE user_id = $1
         AND client_id IN (SELECT id FROM oauth_clients WHERE client_id = $2)
         AND status IN ('active', 'rotated')`,
      [userId, clientRef],
    );
  }
}
