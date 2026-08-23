/**
 * Integration tests: API gateway edge security.
 * Boots the real auth-server on an ephemeral port (JWKS source), a stub
 * upstream resource service, and the real gateway app - verifying token
 * validation, scope enforcement, identity-header injection/anti-spoofing
 * and cross-service revocation propagation.
 */
import request from 'supertest';
import { randomUUID } from 'node:crypto';
import express, { Express } from 'express';
import type { Server } from 'node:http';

process.env.NODE_ENV = 'test';
process.env.RATE_LIMIT_REGISTER = '100';
process.env.RATE_LIMIT_LOGIN = '100';
process.env.RATE_LIMIT_TOKEN = '200';
process.env.RATE_LIMIT_API = '300';
process.env.MAX_FAILED_LOGINS = '50';

import { loadConfig, resetConfigCache } from '../../src/config';
import { Database } from '../../src/infrastructure/database/pool';
import { RedisService } from '../../src/infrastructure/redis/redis.service';
import { LocalKeyProvider } from '../../src/modules/keys/local-key-provider';
import { MockEmailProvider } from '../../src/modules/email/mock-email.provider';
import { setEmailProvider } from '../../src/modules/email/email.factory';
import { hashPassword } from '../../src/modules/users/password.service';
import { createAuthServer, finalizeApp } from '../../src/app.factory';
import { createGatewayApp } from '../../src/modules/gateway/gateway.factory';

resetConfigCache();

const PASSWORD = 'CorrectHorse9!x';

function listen(app: Express): Promise<Server> {
  return new Promise((resolve) => {
    const server = app.listen(0, '127.0.0.1', () => resolve(server));
  });
}

function portOf(server: Server): number {
  const addr = server.address();
  if (addr && typeof addr === 'object') return addr.port;
  throw new Error('no port');
}

describe('API gateway', () => {
  let db: Database;
  let redis: RedisService;
  let authApp: Express;
  let authServer: Server;
  let upstream: Server;
  let gateway: Express;
  let mockEmail: MockEmailProvider;

  beforeAll(async () => {
    // Ephemeral ports must be known BEFORE any loadConfig() call caches them.
    db = new Database();
    redis = new RedisService();
    mockEmail = new MockEmailProvider();
    setEmailProvider(mockEmail);

    // Real auth-server as JWKS issuer.
    const kms = new LocalKeyProvider(loadConfig().KMS_KEY_DIR);
    authApp = createAuthServer({ db, redis, kms, email: mockEmail });
    finalizeApp(authApp);
    authServer = await listen(authApp);

    // Stub upstream that echoes the headers it received.
    const upstreamApp = express();
    upstreamApp.use('/api/v1', (req, res) => {
      res.json({ got: req.headers });
    });
    upstream = await listen(upstreamApp);

    process.env.AUTH_SERVER_URL = `http://127.0.0.1:${portOf(authServer)}`;
    process.env.RESOURCE_API_URL = `http://127.0.0.1:${portOf(upstream)}`;
    resetConfigCache();

    gateway = createGatewayApp({ redis });
  }, 30_000);

  afterAll(async () => {
    authServer.close();
    upstream.close();
    await db.close();
    await redis.close();
  });

  async function registerAndLogin(): Promise<{ id: string; accessToken: string }> {
    const email = `gw-${randomUUID()}@example.com`;
    await request(authApp).post('/auth/register').send({ email, password: PASSWORD });
    const mail = mockEmail.sent.reverse().find((m) => m.to === email)!;
    const verify = await request(authApp)
      .post('/auth/verify-email')
      .send({ token: mail.text.match(/[A-Za-z0-9_-]{40,}/)![0] });
    expect(verify.status).toBe(200);
    const login = await request(authApp).post('/auth/login').send({ email, password: PASSWORD });
    expect(login.status).toBe(200);
    return { id: login.body.user.id, accessToken: login.body.access_token };
  }

  it('rejects requests without a bearer token', async () => {
    const res = await request(gateway).get('/api/v1/things');
    expect(res.status).toBe(401);
    expect(res.body.error).toBe('MISSING_TOKEN');
  });

  it('rejects garbage tokens', async () => {
    const res = await request(gateway)
      .get('/api/v1/things')
      .set('Authorization', 'Bearer not.a.jwt');
    expect(res.status).toBe(401);
    expect(res.body.error).toBe('INVALID_TOKEN');
  });

  it('proxies verified traffic with injected identity headers and strips spoofed ones', async () => {
    const { id, accessToken } = await registerAndLogin();
    const res = await request(gateway)
      .get('/api/v1/things')
      .set('Authorization', `Bearer ${accessToken}`)
      // Spoofed inbound headers must be stripped before injection.
      .set('X-User-Id', 'attacker-id')
      .set('X-User-Roles', 'admin');
    expect(res.status).toBe(200);
    expect(res.body.got['x-user-id']).toBe(id);
    expect(res.body.got['x-user-scopes']).toContain('api.read');
    expect(res.body.got['x-user-roles']).not.toContain('admin');
    // Real role claim replaces the spoofed header value.
    expect(res.body.got['x-user-roles']).toBe('user');
  });

  it('enforces required scopes (service token without api.read -> 403)', async () => {
    // Admin creates a confidential client allowed only api.write.
    const adminEmail = `gw-admin-${randomUUID()}@example.com`;
    await db.query(
      `INSERT INTO users (email, password_hash, status) VALUES ($1, $2, 'active')`,
      [adminEmail, await hashPassword(PASSWORD)],
    );
    await db.query(
      `INSERT INTO user_roles (user_id, role_id)
       SELECT u.id, r.id FROM users u, roles r WHERE u.email = $1 AND r.name = 'admin'`,
      [adminEmail],
    );
    const adminLogin = await request(authApp)
      .post('/auth/login')
      .send({ email: adminEmail, password: PASSWORD });

    const created = await request(authApp)
      .post('/admin/clients')
      .set('Authorization', `Bearer ${adminLogin.body.access_token}`)
      .send({
        name: 'Write-only service',
        client_type: 'confidential',
        redirect_uris: ['https://svc.example.com/cb'],
        allowed_scopes: ['api.write'],
        grant_types: ['client_credentials'],
        token_endpoint_auth_method: 'client_secret_basic',
      });
    expect(created.status).toBe(201);

    const tokenRes = await request(authApp)
      .post('/oauth/token')
      .type('form')
      .auth(created.body.client.client_id, created.body.client_secret)
      .send({ grant_type: 'client_credentials', scope: 'api.write' });
    expect(tokenRes.status).toBe(200);
    const serviceToken = tokenRes.body.access_token;

    const res = await request(gateway)
      .get('/api/v1/things')
      .set('Authorization', `Bearer ${serviceToken}`);
    expect(res.status).toBe(403);
    expect(res.body.error).toBe('INSUFFICIENT_SCOPE');
  });

  it('propagates revocation: token revoked via /oauth/revoke is dead at the gateway', async () => {
    // Reuse a confidential client to authorize the RFC 7009 revocation call.
    const adminEmail = `gw-admin2-${randomUUID()}@example.com`;
    await db.query(
      `INSERT INTO users (email, password_hash, status) VALUES ($1, $2, 'active')`,
      [adminEmail, await hashPassword(PASSWORD)],
    );
    await db.query(
      `INSERT INTO user_roles (user_id, role_id)
       SELECT u.id, r.id FROM users u, roles r WHERE u.email = $1 AND r.name = 'admin'`,
      [adminEmail],
    );
    const adminLogin = await request(authApp)
      .post('/auth/login')
      .send({ email: adminEmail, password: PASSWORD });
    const created = await request(authApp)
      .post('/admin/clients')
      .set('Authorization', `Bearer ${adminLogin.body.access_token}`)
      .send({
        name: 'Revoker',
        client_type: 'confidential',
        redirect_uris: ['https://svc.example.com/cb'],
        allowed_scopes: ['api.read', 'api.write'],
        grant_types: ['client_credentials'],
        token_endpoint_auth_method: 'client_secret_basic',
      });
    expect(created.status).toBe(201);

    const { id, accessToken } = await registerAndLogin();
    const okBefore = await request(gateway)
      .get('/api/v1/things')
      .set('Authorization', `Bearer ${accessToken}`);
    expect(okBefore.status).toBe(200);

    await request(authApp)
      .post('/oauth/revoke')
      .type('form')
      .auth(created.body.client.client_id, created.body.client_secret)
      .send({ token: accessToken })
      .expect(200);

    const after = await request(gateway)
      .get('/api/v1/things')
      .set('Authorization', `Bearer ${accessToken}`);
    expect(after.status).toBe(401);
    expect(after.body.error).toBe('TOKEN_REVOKED');
    void id;
  });
});
