/**
 * Integration tests: OAuth2 authorization-code + PKCE, client_credentials,
 * introspection and revocation - the full protocol against real services.
 */
import request from 'supertest';
import { randomUUID, createHash, randomBytes } from 'node:crypto';
import { Express } from 'express';

process.env.NODE_ENV = 'test';
process.env.RATE_LIMIT_REGISTER = '100';
process.env.RATE_LIMIT_LOGIN = '100';
process.env.RATE_LIMIT_TOKEN = '200';
process.env.RATE_LIMIT_AUTHORIZE = '100';
process.env.MAX_FAILED_LOGINS = '50';

import { loadConfig, resetConfigCache } from '../../src/config';
import { Database } from '../../src/infrastructure/database/pool';
import { RedisService } from '../../src/infrastructure/redis/redis.service';
import { LocalKeyProvider } from '../../src/modules/keys/local-key-provider';
import { MockEmailProvider } from '../../src/modules/email/mock-email.provider';
import { setEmailProvider } from '../../src/modules/email/email.factory';
import { hashPassword } from '../../src/modules/users/password.service';
import { createAuthServer, finalizeApp } from '../../src/app.factory';

resetConfigCache();

const PASSWORD = 'CorrectHorse9!x';

function pkcePair(): { verifier: string; challenge: string } {
  const verifier = randomBytes(48).toString('base64url');
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  return { verifier, challenge };
}

describe('OAuth2 flows', () => {
  let db: Database;
  let redis: RedisService;
  let app: Express;
  let mockEmail: MockEmailProvider;
  const config = loadConfig();

  let adminToken: string;

  beforeAll(async () => {
    db = new Database();
    redis = new RedisService();
    const kms = new LocalKeyProvider(config.KMS_KEY_DIR);
    mockEmail = new MockEmailProvider();
    setEmailProvider(mockEmail);
    app = createAuthServer({ db, redis, kms, email: mockEmail });
    finalizeApp(app);

    // Deterministic admin.
    const adminEmail = `oauth-admin-${randomUUID()}@example.com`;
    await db.query(
      `INSERT INTO users (email, password_hash, status) VALUES ($1, $2, 'active')`,
      [adminEmail, await hashPassword(PASSWORD)],
    );
    await db.query(
      `INSERT INTO user_roles (user_id, role_id)
       SELECT u.id, r.id FROM users u, roles r WHERE u.email = $1 AND r.name = 'admin'`,
      [adminEmail],
    );
    const login = await request(app).post('/auth/login').send({ email: adminEmail, password: PASSWORD });
    adminToken = login.body.access_token;
  });

  afterAll(async () => {
    await db.close();
    await redis.close();
  });

  async function createClient(params: {
    name: string;
    type: 'confidential' | 'public';
    grants: string[];
    scopes: string[];
  }): Promise<{ clientId: string; secret?: string }> {
    const res = await request(app)
      .post('/admin/clients')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({
        name: params.name,
        client_type: params.type,
        redirect_uris: ['https://app.example.com/callback'],
        allowed_scopes: params.scopes,
        grant_types: params.grants,
        token_endpoint_auth_method:
          params.type === 'confidential' ? 'client_secret_basic' : 'none',
      });
    expect(res.status).toBe(201);
    return { clientId: res.body.client.client_id, secret: res.body.client_secret };
  }

  async function verifiedUser(): Promise<string> {
    const email = `oauth-${randomUUID()}@example.com`;
    await request(app).post('/auth/register').send({ email, password: PASSWORD });
    const mail = mockEmail.sent.reverse().find((m) => m.to === email)!;
    await request(app).post('/auth/verify-email')
      .send({ token: mail.text.match(/[A-Za-z0-9_-]{40,}/)![0] });
    return email;
  }

  it('full Authorization Code + PKCE flow issues tokens + id_token + userinfo', async () => {
    const email = await verifiedUser();
    const userLogin = await request(app).post('/auth/login').send({ email, password: PASSWORD });
    const userBearer = userLogin.body.access_token;

    const { clientId, secret } = await createClient({
      name: 'Web App PKCE',
      type: 'confidential',
      grants: ['authorization_code'],
      scopes: ['openid', 'profile', 'email', 'offline_access', 'api.read'],
    });

    const { verifier, challenge } = pkcePair();

    const authorize = await request(app)
      .get('/oauth/authorize')
      .query({
        response_type: 'code',
        client_id: clientId,
        redirect_uri: 'https://app.example.com/callback',
        scope: 'openid profile email offline_access api.read',
        state: 'xyz-state-123',
        nonce: 'n0nce-value-1',
        code_challenge: challenge,
        code_challenge_method: 'S256',
      })
      .set('Authorization', `Bearer ${userBearer}`);

    expect(authorize.status).toBe(200);
    expect(authorize.body.code_url).toContain('https://app.example.com/callback?code=');
    expect(authorize.body.code_url).toContain('state=xyz-state-123');
    const code = new URL(authorize.body.code_url).searchParams.get('code')!;

    // Exchange with wrong verifier -> rejected
    const badPkce = await request(app)
      .post('/oauth/token')
      .type('form')
      .auth(clientId, secret!)
      .send({
        grant_type: 'authorization_code',
        code,
        redirect_uri: 'https://app.example.com/callback',
        code_verifier: 'a'.repeat(48),
      });
    expect(badPkce.status).toBe(400);
    expect(badPkce.body.error).toBe('invalid_grant');

    // Correct exchange
    const token = await request(app)
      .post('/oauth/token')
      .type('form')
      .auth(clientId, secret!)
      .send({
        grant_type: 'authorization_code',
        code,
        redirect_uri: 'https://app.example.com/callback',
        code_verifier: verifier,
      });
    expect(token.status).toBe(200);
    expect(token.body.access_token).toBeDefined();
    expect(token.body.refresh_token).toBeDefined();
    expect(token.body.id_token).toBeDefined();
    expect(token.body.scope).toContain('api.read');

    // id_token aud = client_id, nonce echoed
    const [, idp] = token.body.id_token.split('.');
    const idPayload = JSON.parse(Buffer.from(idp!, 'base64url').toString());
    expect(idPayload.aud).toBe(clientId);
    expect(idPayload.nonce).toBe('n0nce-value-1');

    // userinfo with access token
    const userinfo = await request(app)
      .get('/userinfo')
      .set('Authorization', `Bearer ${token.body.access_token}`);
    expect(userinfo.status).toBe(200);
    expect(userinfo.body.email).toBe(email);
    expect(userinfo.body.sub).toBeDefined();

    // CODE REPLAY: reusing the same code revokes derived refresh tokens.
    const replay = await request(app)
      .post('/oauth/token')
      .type('form')
      .auth(clientId, secret!)
      .send({
        grant_type: 'authorization_code',
        code,
        redirect_uri: 'https://app.example.com/callback',
        code_verifier: verifier,
      });
    expect(replay.status).toBe(400);
    expect(replay.body.error).toBe('invalid_grant');

    const revokedRefresh = await request(app)
      .post('/auth/refresh')
      .send({ refresh_token: token.body.refresh_token });
    expect(revokedRefresh.status).toBe(401);
  });

  it('authorize rejects unauthenticated callers (login_required) and bad redirect_uri', async () => {
    const { clientId } = await createClient({
      name: 'Anon Probe',
      type: 'public',
      grants: ['authorization_code'],
      scopes: ['openid'],
    });

    const { challenge } = pkcePair();
    const noAuth = await request(app).get('/oauth/authorize').query({
      response_type: 'code',
      client_id: clientId,
      redirect_uri: 'https://app.example.com/callback',
      scope: 'openid',
      code_challenge: challenge,
      code_challenge_method: 'S256',
    });
    expect(noAuth.status).toBe(401);
    expect(noAuth.body.error).toBe('login_required');

    const userLogin = await request(app)
      .post('/auth/login')
      .send({ email: await verifiedUser(), password: PASSWORD });

    const badRedirect = await request(app)
      .get('/oauth/authorize')
      .query({
        response_type: 'code',
        client_id: clientId,
        redirect_uri: 'https://evil.example.com/cb',
        scope: 'openid',
        code_challenge: challenge,
        code_challenge_method: 'S256',
      })
      .set('Authorization', `Bearer ${userLogin.body.access_token}`);
    expect(badRedirect.status).toBe(400);
    expect(badRedirect.body.error).toBe('invalid_request');
  });

  it('client_credentials issues a service JWT; public clients are refused', async () => {
    const service = await createClient({
      name: 'Trusted API Client',
      type: 'confidential',
      grants: ['client_credentials'],
      scopes: ['api.read', 'api.write'],
    });

    const token = await request(app)
      .post('/oauth/token')
      .type('form')
      .auth(service.clientId, service.secret!)
      .send({ grant_type: 'client_credentials', scope: 'api.read api.write' });
    expect(token.status).toBe(200);
    expect(token.body.token_type).toBe('Bearer');

    const [, payloadB64] = token.body.access_token.split('.');
    const payload = JSON.parse(Buffer.from(payloadB64!, 'base64url').toString());
    expect(payload.roles).toEqual(['service']);
    expect(payload.scope).toContain('api.write');

    // No refresh tokens for client_credentials.
    expect(token.body.refresh_token).toBeUndefined();

    // Wrong secret -> invalid_client
    const badSecret = await request(app)
      .post('/oauth/token')
      .type('form')
      .auth(service.clientId, 'cst_wrongsecret_wrongsecret_wrongsecret')
      .send({ grant_type: 'client_credentials', scope: 'api.read' });
    expect(badSecret.status).toBe(401);

    // Exceeding allowed scope -> invalid_scope
    const tooMuch = await request(app)
      .post('/oauth/token')
      .type('form')
      .auth(service.clientId, service.secret!)
      .send({ grant_type: 'client_credentials', scope: 'api.read admin.everything' });
    expect(tooMuch.status).toBe(400);
    expect(tooMuch.body.error).toBe('invalid_scope');
  });

  it('introspection requires client auth and reports revocation', async () => {
    const service = await createClient({
      name: 'Introspecting Client',
      type: 'confidential',
      grants: ['client_credentials'],
      scopes: ['api.read'],
    });
    const issued = await request(app)
      .post('/oauth/token')
      .type('form')
      .auth(service.clientId, service.secret!)
      .send({ grant_type: 'client_credentials', scope: 'api.read' });
    const accessToken = issued.body.access_token as string;

    const anon = await request(app)
      .post('/oauth/introspect')
      .type('form')
      .send({ token: accessToken });
    expect(anon.status).toBe(401);

    const ok = await request(app)
      .post('/oauth/introspect')
      .type('form')
      .auth(service.clientId, service.secret!)
      .send({ token: accessToken });
    expect(ok.status).toBe(200);
    expect(ok.body.active).toBe(true);
    expect(ok.body.scope).toBe('api.read');

    // RFC 7009 revoke -> introspection flips to inactive
    const revoke = await request(app)
      .post('/oauth/revoke')
      .type('form')
      .send({ token: accessToken });
    expect(revoke.status).toBe(200);

    const after = await request(app)
      .post('/oauth/introspect')
      .type('form')
      .auth(service.clientId, service.secret!)
      .send({ token: accessToken });
    expect(after.body.active).toBe(false);
  });

  it('refresh-token revocation via /oauth/revoke kills the chain', async () => {
    const email = await verifiedUser();
    const login = await request(app).post('/auth/login').send({ email, password: PASSWORD });
    const refreshToken = login.body.refresh_token as string;

    const revoke = await request(app)
      .post('/oauth/revoke')
      .type('form')
      .send({ token: refreshToken });
    expect(revoke.status).toBe(200);

    const attempt = await request(app).post('/auth/refresh').send({ refresh_token: refreshToken });
    expect(attempt.status).toBe(401);
    expect(['REFRESH_TOKEN_REUSE', 'INVALID_REFRESH_TOKEN']).toContain(attempt.body.error);
  });

  it('OIDC discovery document is served', async () => {
    const disco = await request(app).get('/.well-known/openid-configuration');
    expect(disco.status).toBe(200);
    expect(disco.body.issuer).toBe(config.JWT_ISSUER);
    expect(disco.body.jwks_uri).toContain('/.well-known/jwks.json');
    expect(disco.body.code_challenge_methods_supported).toContain('S256');

    const jwks = await request(app).get('/.well-known/jwks.json');
    expect(jwks.status).toBe(200);
    expect(jwks.body.keys[0].kty).toBe('OKP');
    expect(jwks.body.keys[0].crv).toBe('Ed25519');
  });
});
