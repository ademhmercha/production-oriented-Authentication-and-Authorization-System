import { createHash, randomBytes } from 'node:crypto';
import argon2 from 'argon2';
import { Database } from '../../infrastructure/database/pool';

export interface OAuthClientRow {
  id: string;
  client_id: string;
  client_secret_hash: string | null;
  name: string;
  client_type: 'confidential' | 'public';
  redirect_uris: string[];
  allowed_scopes: string[];
  grant_types: string[];
  token_endpoint_auth_method: 'client_secret_basic' | 'client_secret_post' | 'none';
  require_pkce: boolean;
  status: 'active' | 'disabled';
}

/**
 * OAuth client management.
 *
 * SECURITY:
 * - Client secrets are generated server-side and returned exactly ONCE at
 *   creation/rotation; only the Argon2id hash is stored.
 * - Public clients (SPAs / mobile) have NO secret and MUST use PKCE.
 */
export class ClientRepository {
  constructor(private readonly db: Database) {}

  static newClientId(): string {
    return `cli_${randomBytes(8).toString('hex')}`;
  }

  static newClientSecret(): string {
    return `cst_${randomBytes(32).toString('base64url')}`;
  }

  async findByClientId(clientId: string): Promise<OAuthClientRow | null> {
    const result = await this.db.query<OAuthClientRow>(
      `SELECT * FROM oauth_clients WHERE client_id = $1`,
      [clientId],
    );
    return result.rows[0] ?? null;
  }

  async create(params: {
    name: string;
    clientType: 'confidential' | 'public';
    redirectUris: string[];
    allowedScopes: string[];
    grantTypes: string[];
    requirePkce: boolean;
    tokenEndpointAuthMethod: 'client_secret_basic' | 'client_secret_post' | 'none';
  }): Promise<{ row: OAuthClientRow; secret?: string }> {
    const clientId = ClientRepository.newClientId();
    const secret = params.clientType === 'confidential'
      ? ClientRepository.newClientSecret()
      : undefined;
    const secretHash = secret
      ? await argon2.hash(secret, { type: argon2.argon2id })
      : null;

    const result = await this.db.query<OAuthClientRow>(
      `INSERT INTO oauth_clients
         (client_id, client_secret_hash, name, client_type, redirect_uris,
          allowed_scopes, grant_types, token_endpoint_auth_method, require_pkce)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
       RETURNING *`,
      [
        clientId,
        secretHash,
        params.name,
        params.clientType,
        params.redirectUris,
        params.allowedScopes,
        params.grantTypes,
        params.tokenEndpointAuthMethod,
        params.requirePkce,
      ],
    );
    return { row: result.rows[0]!, secret };
  }

  /** Rotation: replaces the hash, old secret dies immediately. */
  async rotateSecret(id: string): Promise<string> {
    const secret = ClientRepository.newClientSecret();
    const hash = await argon2.hash(secret, { type: argon2.argon2id });
    await this.db.query(`UPDATE oauth_clients SET client_secret_hash = $2 WHERE id = $1`, [
      id,
      hash,
    ]);
    return secret;
  }

  async verifySecret(row: OAuthClientRow, presentedSecret: string): Promise<boolean> {
    if (!row.client_secret_hash) return false;
    return argon2.verify(row.client_secret_hash, presentedSecret);
  }

  async setStatus(id: string, status: 'active' | 'disabled'): Promise<void> {
    await this.db.query(`UPDATE oauth_clients SET status = $2 WHERE id = $1`, [id, status]);
  }

  async list(): Promise<Array<Omit<OAuthClientRow, 'client_secret_hash'>>> {
    const result = await this.db.query<Omit<OAuthClientRow, 'client_secret_hash'>>(
      `SELECT id, client_id, name, client_type, redirect_uris, allowed_scopes,
              grant_types, token_endpoint_auth_method, require_pkce, status
       FROM oauth_clients ORDER BY created_at DESC`,
    );
    return result.rows;
  }
}

/** PKCE helpers per RFC 7636 (S256 only is accepted in practice). */
export class PkceUtil {
  static generateVerifier(): string {
    return randomBytes(48).toString('base64url');
  }

  static challengeFromVerifier(verifier: string): string {
    return createHash('sha256').update(verifier).digest('base64url');
  }

  static matches(verifier: string, storedChallenge: string, method: string | null): boolean {
    if (method === 'S256') {
      return PkceUtil.challengeFromVerifier(verifier) === storedChallenge;
    }
    if (method === 'plain') {
      return verifier === storedChallenge;
    }
    return false;
  }
}
