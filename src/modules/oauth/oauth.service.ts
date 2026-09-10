import { JwtService } from '../tokens/jwt.service';
import { RefreshTokenService } from '../tokens/refresh-token.service';
import { TokenRevocationService } from '../tokens/token-revocation';
import { SessionRepository } from '../sessions/session.repository';
import { ClientRepository, PkceUtil } from '../clients/client.repository';
import {
  AuthorizationCodeRepository,
  CodeReplayError,
} from './authorization-code.repository';
import { UserRepository } from '../users/user.repository';
import { AuditLogService } from '../audit/audit.service';
import { AuditEventType } from '../audit/audit.types';
import { RequestContext } from '../../common/decorators/request-context';
import { loadConfig } from '../../config';
import { AppError, AuthError, ForbiddenError } from '../../common/errors';

/** RFC 6749 §5.2 error responses use a specific envelope. */
export class OAuthTokenError extends AppError {
  constructor(statusCode: number, code: string, description: string) {
    super(statusCode, code, description);
  }
}

export interface TokenResponse {
  access_token: string;
  token_type: 'Bearer';
  expires_in: number;
  refresh_token?: string;
  scope: string;
  id_token?: string;
}

export interface AuthorizeInput {
  client_id: string;
  redirect_uri: string;
  scope: string;
  nonce?: string;
  code_challenge: string;
  code_challenge_method: 'S256' | 'plain';
}

/**
 * OAuth 2.0 core: authorization-code (PKCE) + client_credentials grants,
 * token introspection and revocation.
 *
 * SECURITY DECISIONS:
 * - Password grant is deliberately NOT implemented (removed in OAuth 2.1).
 * - PKCE is enforced for ALL clients at /oauth/token (recommended by
 *   OAuth 2.1), and S256 is required for clients with require_pkce.
 * - Confidential clients authenticate with hashed secrets (basic or post).
 */
export class OAuthService {
  constructor(
    private readonly clients: ClientRepository,
    private readonly codes: AuthorizationCodeRepository,
    private readonly jwt: JwtService,
    private readonly refreshTokens: RefreshTokenService,
    private readonly sessions: SessionRepository,
    private readonly users: UserRepository,
    private readonly audit: AuditLogService,
    private readonly tokenRevocation: TokenRevocationService,
  ) {}

  /** Validates an authorize request and issues the code for the logged-in user. */
  async authorize(
    input: AuthorizeInput,
    authenticatedUserId: string | undefined,
    state: string | undefined,
    ctx: RequestContext,
  ): Promise<{ redirect: string }> {
    const config = loadConfig();
    const client = await this.clients.findByClientId(input.client_id);

    const fail = (code: string, description: string): never => {
      throw new OAuthTokenError(400, code, description);
    };

    if (!client) fail('invalid_client', 'Unknown client');
    if (client!.status !== 'active') {
      await this.audit.record({
        event_type: AuditEventType.AUTHORIZATION_DENIED,
        user_id: authenticatedUserId ?? null,
        ip: ctx.ip,
        request_id: ctx.requestId,
        metadata: { reason: 'client_disabled', client_id: input.client_id },
      });
      fail('unauthorized_client', 'Client is disabled');
    }

    // Exact-match redirect URI (no prefix tricks).
    if (!client!.redirect_uris.includes(input.redirect_uri)) {
      await this.audit.record({
        event_type: AuditEventType.AUTHORIZATION_DENIED,
        user_id: authenticatedUserId ?? null,
        ip: ctx.ip,
        request_id: ctx.requestId,
        metadata: { reason: 'redirect_uri_mismatch', client_id: input.client_id },
      });
      fail('invalid_request', 'redirect_uri is not registered for this client');
    }

    // Scope subset check.
    const requested = input.scope.split(/\s+/).filter(Boolean);
    if (!requested.every((s) => client!.allowed_scopes.includes(s))) {
      fail('invalid_scope', 'Requested scope exceeds what the client is allowed');
    }

    if (input.code_challenge_method === 'plain' && client!.require_pkce) {
      fail('invalid_request', 'Only S256 code_challenge_method is allowed');
    }
    if (!/^[\w-]{43,128}$/.test(input.code_challenge)) {
      fail('invalid_request', 'Malformed code_challenge');
    }

    if (!authenticatedUserId) {
      // Browser flows would redirect to the login UI here; headless/API
      // callers get the OIDC-style login_required signal.
      throw new OAuthTokenError(401, 'login_required', 'User authentication required');
    }

    const user = await this.users.findById(authenticatedUserId);
    if (!user || user.status !== 'active') {
      throw new ForbiddenError('User account is not active', 'USER_INACTIVE');
    }

    const code = await this.codes.issue({
      clientId: input.client_id,
      userId: authenticatedUserId,
      redirectUri: input.redirect_uri,
      scope: input.scope,
      nonce: input.nonce ?? null,
      codeChallenge: input.code_challenge,
      codeChallengeMethod: input.code_challenge_method,
      ttlSeconds: config.AUTHORIZATION_CODE_TTL,
    });

    void config;
    await this.audit.record({
      event_type: AuditEventType.AUTHORIZATION_GRANTED,
      user_id: authenticatedUserId,
      ip: ctx.ip,
      request_id: ctx.requestId,
      metadata: { client_id: input.client_id, scope: input.scope },
    });

    const url = new URL(input.redirect_uri);
    url.searchParams.set('code', code);
    if (state !== undefined && /^[A-Za-z0-9\-_.~]{1,512}$/.test(state)) {
      url.searchParams.set('state', state);
    }
    return { redirect: url.toString() };
  }

  async token(
    form: {
      grant_type: 'authorization_code' | 'client_credentials' | 'refresh_token';
      code?: string;
      redirect_uri?: string;
      client_id?: string;
      client_secret?: string;
      code_verifier?: string;
      scope?: string;
      refresh_token?: string;
    },
    basicAuth: { clientId: string; clientSecret: string } | null,
    ctx: RequestContext,
  ): Promise<TokenResponse> {
    // Client identification (basic > post > form)
    const clientId = basicAuth?.clientId ?? form.client_id;
    if (!clientId) {
      throw new OAuthTokenError(401, 'invalid_client', 'Client authentication required');
    }
    const presentedSecret = basicAuth?.clientSecret ?? form.client_secret;

    const client = await this.clients.findByClientId(clientId);
    if (!client || client.status !== 'active') {
      throw new OAuthTokenError(401, 'invalid_client', 'Invalid client');
    }

    if (form.grant_type === 'authorization_code') {
      if (!form.code) throw new OAuthTokenError(400, 'invalid_request', 'code is required');
      if (!form.redirect_uri) {
        throw new OAuthTokenError(400, 'invalid_request', 'redirect_uri is required');
      }
      if (!form.code_verifier) {
        throw new OAuthTokenError(400, 'invalid_request', 'PKCE code_verifier is required');
      }
      // Confidential clients MUST authenticate; public clients must not send secrets.
      if (client.client_type === 'confidential') {
        if (!presentedSecret || !(await this.clients.verifySecret(client, presentedSecret))) {
          await this.recordClientAuthFailure(client.id, ctx);
          throw new OAuthTokenError(401, 'invalid_client', 'Invalid client credentials');
        }
      } else if (presentedSecret) {
        throw new OAuthTokenError(400, 'invalid_request', 'Public clients must not authenticate');
      }

      // Peek + PKCE verification BEFORE consuming, so a wrong verifier
      // does not burn the single-use code.
      let peeked;
      try {
        peeked = await this.codes.peek({
          code: form.code,
          clientId,
          redirectUri: form.redirect_uri,
        });
      } catch (err) {
        if (err instanceof CodeReplayError) {
          await this.handleCodeReplay(err, ctx);
          throw new OAuthTokenError(400, 'invalid_grant',
            'Authorization code replay detected - issued tokens revoked');
        }
        throw err;
      }
      if (!peeked) {
        throw new OAuthTokenError(400, 'invalid_grant', 'Invalid or expired authorization code');
      }
      if (!peeked.code_challenge) {
        throw new OAuthTokenError(400, 'invalid_grant', 'Code was issued without PKCE');
      }
      if (
        !PkceUtil.matches(form.code_verifier, peeked.code_challenge, peeked.code_challenge_method)
      ) {
        throw new OAuthTokenError(400, 'invalid_grant', 'PKCE verification failed');
      }

      // Atomic consume; racing a concurrent exchange is treated as replay.
      let codeRow;
      try {
        codeRow = await this.codes.consume({
          code: form.code,
          clientId,
          redirectUri: form.redirect_uri,
        });
      } catch (err) {
        if (err instanceof CodeReplayError) {
          await this.handleCodeReplay(err, ctx);
          throw new OAuthTokenError(400, 'invalid_grant',
            'Authorization code replay detected - issued tokens revoked');
        }
        throw err;
      }

      if (!codeRow) {
        throw new OAuthTokenError(400, 'invalid_grant', 'Invalid or expired authorization code');
      }

      return this.issueUserTokens(codeRow.user_id, client, codeRow.scope, codeRow.nonce, ctx);
    }

    // refresh_token (RFC 6749 §6) with rotation + theft detection
    if (form.grant_type === 'refresh_token') {
      if (!form.refresh_token) {
        throw new OAuthTokenError(400, 'invalid_request', 'refresh_token is required');
      }
      if (client.client_type === 'confidential') {
        if (!presentedSecret || !(await this.clients.verifySecret(client, presentedSecret))) {
          await this.recordClientAuthFailure(client.id, ctx);
          throw new OAuthTokenError(401, 'invalid_client', 'Invalid client credentials');
        }
      } else if (presentedSecret) {
        throw new OAuthTokenError(400, 'invalid_request', 'Public clients must not authenticate');
      }

      let consumed;
      try {
        consumed = await this.refreshTokens.consume(form.refresh_token);
      } catch (err) {
        if (err instanceof AuthError && err.code === 'REFRESH_TOKEN_REUSE') {
          await this.audit.record({
            event_type: AuditEventType.REFRESH_TOKEN_REUSE_DETECTED,
            ip: ctx.ip,
            request_id: ctx.requestId,
            metadata: { kind: 'oauth_refresh_reuse', client_id: client.client_id },
          });
          throw new OAuthTokenError(401, 'invalid_grant',
            'Refresh token reuse detected - chain revoked');
        }
        if (err instanceof AuthError && err.code === 'INVALID_REFRESH_TOKEN') {
          throw new OAuthTokenError(401, 'invalid_grant', 'Invalid or expired refresh token');
        }
        throw err;
      }
      const { row, nextToken } = consumed;

      // Client binding: a refresh token may only be used by its own client.
      if (row.client_id !== client.id) {
        await this.refreshTokens.revokeByToken(form.refresh_token);
        await this.audit.record({
          event_type: AuditEventType.REFRESH_TOKEN_REUSE_DETECTED,
          user_id: row.user_id,
          ip: ctx.ip,
          request_id: ctx.requestId,
          metadata: { kind: 'client_mismatch' },
        });
        throw new OAuthTokenError(401, 'invalid_grant', 'Token was not issued to this client');
      }

      // The backing session must still be alive.
      const session = await this.sessions.findById(row.session_id);
      if (!session || session.status !== 'active') {
        await this.refreshTokens.revokeFamily(row.family_id);
        throw new OAuthTokenError(401, 'invalid_grant', 'Session is no longer active');
      }

      // Optional scope narrowing - never elevation.
      const originalScopes = row.scope.split(/\s+/).filter(Boolean);
      const requested = (form.scope ?? '').split(/\s+/).filter(Boolean);
      if (requested.some((s) => !originalScopes.includes(s))) {
        throw new OAuthTokenError(400, 'invalid_scope', 'Scope exceeds original grant');
      }
      const scope = requested.length > 0 ? requested.join(' ') : row.scope;

      const roles = await this.users.rolesOf(row.user_id);
      const permissions = await this.users.permissionsOf(row.user_id);
      const signed = await this.jwt.signAccessToken({
        sub: row.user_id,
        scope,
        roles,
        permissions,
        sid: row.session_id,
        client_id: client.client_id,
        amr: ['oauth'],
      });
      await this.audit.record({
        event_type: AuditEventType.TOKEN_ISSUED,
        user_id: row.user_id,
        client_id: client.id,
        ip: ctx.ip,
        request_id: ctx.requestId,
        metadata: { grant: 'refresh_token', scope },
      });
      return {
        access_token: signed.token,
        token_type: 'Bearer',
        expires_in: Math.floor((signed.expiresAt.getTime() - Date.now()) / 1000),
        refresh_token: nextToken,
        scope,
      };
    }

    // client_credentials
    if (form.grant_type === 'client_credentials') {
      if (client.client_type === 'public') {
        throw new OAuthTokenError(401, 'unauthorized_client',
          'Public clients cannot use client_credentials');
      }
      if (client.token_endpoint_auth_method === 'none') {
        throw new OAuthTokenError(401, 'unauthorized_client',
          'This client is not configured for secret authentication');
      }
      if (!presentedSecret || !(await this.clients.verifySecret(client, presentedSecret))) {
        await this.recordClientAuthFailure(client.id, ctx);
        throw new OAuthTokenError(401, 'invalid_client', 'Invalid client credentials');
      }
      if (!client.grant_types.includes('client_credentials')) {
        throw new OAuthTokenError(401, 'unauthorized_client',
          'Grant type not allowed for this client');
      }

      const requested = (form.scope ?? '').split(/\s+/).filter(Boolean);
      if (requested.length === 0) {
        throw new OAuthTokenError(400, 'invalid_scope', 'scope is required');
      }
      if (!requested.every((s) => client.allowed_scopes.includes(s))) {
        throw new OAuthTokenError(400, 'invalid_scope', 'Requested scope exceeds allowance');
      }
      const scope = requested.join(' ');

      const signed = await this.jwt.signAccessToken({
        sub: client.client_id,
        scope,
        roles: ['service'],
        client_id: client.client_id,
        amr: ['client_secret'],
      });

      await this.audit.record({
        event_type: AuditEventType.TOKEN_ISSUED,
        client_id: client.id,
        ip: ctx.ip,
        request_id: ctx.requestId,
        metadata: { grant: 'client_credentials', scope },
      });

      return {
        access_token: signed.token,
        token_type: 'Bearer',
        expires_in: Math.floor((signed.expiresAt.getTime() - Date.now()) / 1000),
        scope,
      };
    }

    throw new OAuthTokenError(400, 'unsupported_grant_type', 'Unsupported grant_type');
  }

  /**
   * Introspection (RFC 7662). Caller must be an authenticated client.
   * Returns active=false for anything invalid/expired/revoked - no details.
   */
  async introspect(token: string): Promise<{
    active: boolean;
    sub?: string;
    scope?: string;
    exp?: number;
    iat?: number;
    aud?: string;
    iss?: string;
    jti?: string;
    token_type?: string;
    client_id?: string;
  }> {
    try {
      const payload = await this.jwt.verifyAccessToken(token);
      return {
        active: true,
        sub: payload.sub,
        scope: payload.scope,
        exp: payload.exp,
        iat: payload.iat,
        aud: Array.isArray(payload.aud) ? payload.aud[0] : payload.aud,
        iss: payload.iss as string,
        jti: payload.jti,
        token_type: 'access_token',
        client_id: payload.client_id,
      };
    } catch {
      return { active: false };
    }
  }

  /**
   * RFC 7009 revocation.
   * - refresh tokens: revoked in the DB chain
   * - access tokens: session killed (user tokens) and jti denylisted until
   *   natural expiry (works for stateless client_credentials tokens too)
   */
  async revoke(token: string, ctx: RequestContext): Promise<void> {
    const wasRefresh = await this.refreshTokens.revokeByToken(token);
    if (wasRefresh) {
      await this.audit.record({
        event_type: AuditEventType.TOKEN_REVOKED,
        ip: ctx.ip,
        request_id: ctx.requestId,
        metadata: { kind: 'refresh_token' },
      });
      return;
    }
    try {
      const payload = await this.jwt.verifyAccessToken(token);
      if (payload.sid) {
        await this.sessions.revoke(payload.sid, 'token_revocation');
      }
      if (payload.jti && payload.exp) {
        await this.tokenRevocation.revokeUntil(payload.jti, payload.exp);
      }
      await this.audit.record({
        event_type: AuditEventType.TOKEN_REVOKED,
        user_id: payload.sub,
        ip: ctx.ip,
        request_id: ctx.requestId,
        metadata: { kind: 'access_token' },
      });
    } catch {
      // Per RFC 7009 §2.2: respond 200 even for unknown tokens.
    }
  }

  private async recordClientAuthFailure(
    clientDbId: string,
    ctx: RequestContext,
    grant = 'unknown',
  ): Promise<void> {
    await this.audit.record({
      event_type: AuditEventType.USER_LOGIN_FAILED,
      client_id: clientDbId,
      ip: ctx.ip,
      request_id: ctx.requestId,
      metadata: { reason: 'client_auth_failed', grant },
    });
  }

  /** Replay response per RFC 6749 §4.1.2: revoke everything derived from the code. */
  private async handleCodeReplay(err: CodeReplayError, ctx: RequestContext): Promise<void> {
    await this.codes.revokeTokensForReplay(err.userId, err.clientRef);
    await this.audit.record({
      event_type: AuditEventType.REFRESH_TOKEN_REUSE_DETECTED,
      user_id: err.userId,
      client_id: err.clientRef,
      ip: ctx.ip,
      request_id: ctx.requestId,
      metadata: { kind: 'authorization_code_replay' },
    });
  }

  private async issueUserTokens(
    userId: string,
    client: { id: string; client_id: string },
    scope: string,
    nonce: string | null,
    ctx: RequestContext,
  ): Promise<TokenResponse> {
    const config = loadConfig();
    const roles = await this.users.rolesOf(userId);
    const permissions = await this.users.permissionsOf(userId);

    const session = await this.sessions.create({
      userId,
      clientId: client.id,
      ip: ctx.ip ?? null,
      userAgent: ctx.userAgent ?? null,
      mfaPassed: true, // authorization implies prior authentication via /auth/login
      ttlSeconds: config.SESSION_TTL,
    });

    const signed = await this.jwt.signAccessToken({
      sub: userId,
      scope,
      roles,
      permissions,
      sid: session.id,
      client_id: client.client_id,
      amr: ['oauth'],
    });
    const refresh = await this.refreshTokens.issue({
      sessionId: session.id,
      userId,
      clientId: client.id,
      scope,
    });

    let idToken: string | undefined;
    if (scope.includes('openid')) {
      const user = await this.users.findById(userId);
      const claims: Record<string, unknown> = {};
      if (nonce) claims.nonce = nonce;
      if (scope.includes('email')) claims.email = user?.email;
      if (scope.includes('profile')) {
        claims.given_name = user?.first_name ?? undefined;
        claims.family_name = user?.last_name ?? undefined;
      }
      idToken = await this.jwt.signIdToken(claims, client.client_id, userId, config.ID_TOKEN_TTL);
    }

    await this.audit.record({
      event_type: AuditEventType.TOKEN_ISSUED,
      user_id: userId,
      client_id: client.id,
      ip: ctx.ip,
      request_id: ctx.requestId,
      metadata: { grant: 'authorization_code', scope },
    });

    return {
      access_token: signed.token,
      token_type: 'Bearer',
      expires_in: Math.floor((signed.expiresAt.getTime() - Date.now()) / 1000),
      refresh_token: refresh.token,
      scope,
      ...(idToken ? { id_token: idToken } : {}),
    };
  }
}
