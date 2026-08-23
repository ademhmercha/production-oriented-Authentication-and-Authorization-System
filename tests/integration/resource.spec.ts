/**
 * Integration tests: resource API behind the gateway (zero-trust contract).
 * Boots auth-server + gateway + resource-api on ephemeral ports with a
 * shared secret, then exercises ownership, scope and origin rules.
 */
import request from 'supertest';
import { randomUUID } from 'node:crypto';
import type { Express } from 'express';
import type { Server } from 'node:http';

process.env.NODE_ENV = 'test';
process.env.RATE_LIMIT_REGISTER = '100';
process.env.RATE_LIMIT_LOGIN = '200';
process.env.RATE_LIMIT_TOKEN = '200';
process.env.RATE_LIMIT_API = '300';
process.env.MAX_FAILED_LOGINS = '50';
process.env.GATEWAY_SHARED_SECRET = Buffer.alloc(32, 0xcd).toString('base64');

import { loadConfig, resetConfigCache } from '../../src/config';
import { Database } from '../../src/infrastructure/database/pool';
import { RedisService } from '../../src/infrastructure/redis/redis.service';
import { LocalKeyProvider } from '../../src/modules/keys/local-key-provider';
import { MockEmailProvider } from '../../src/modules/email/mock-email.provider';
import { setEmailProvider } from '../../src/modules/email/email.factory';
import { hashPassword } from '../../src/modules/users/password.service';
import { createAuthServer, finalizeApp } from '../../src/app.factory';
import { createGatewayApp } from '../../src/modules/gateway/gateway.factory';
import { createResourceApiApp } from '../../src/modules/resources/resource.factory';

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

describe('Resource API via gateway', () => {
  let db: Database;
  let redis: RedisService;
  let mockEmail: MockEmailProvider;
  let authApp: Express;
  let resourceApi: Express;
  let gateway: Express;
  const servers: Server[] = [];

  beforeAll(async () => {
    db = new Database();
    redis = new RedisService();
    mockEmail = new MockEmailProvider();
    setEmailProvider(mockEmail);

    const kms = new LocalKeyProvider(loadConfig().KMS_KEY_DIR);
    authApp = createAuthServer({ db, redis, kms, email: mockEmail });
    finalizeApp(authApp);
    const authServer = await listen(authApp);
    servers.push(authServer);

    // Resource API must exist BEFORE the gateway caches its URL.
    resourceApi = createResourceApiApp({ db });
    const upstream = await listen(resourceApi);
    servers.push(upstream);

    process.env.AUTH_SERVER_URL = `http://127.0.0.1:${portOf(authServer)}`;
    process.env.RESOURCE_API_URL = `http://127.0.0.1:${portOf(upstream)}`;
    resetConfigCache();
    gateway = createGatewayApp({ redis });
  }, 30_000);

  afterAll(async () => {
    for (const s of servers) s.close();
    await db.close();
    await redis.close();
  });

  async function newUser(): Promise<{ id: string; token: string }> {
    const email = `res-${randomUUID()}@example.com`;
    await request(authApp).post('/auth/register').send({ email, password: PASSWORD });
    const mail = mockEmail.sent.reverse().find((m) => m.to === email)!;
    await request(authApp)
      .post('/auth/verify-email')
      .send({ token: mail.text.match(/[A-Za-z0-9_-]{40,}/)![0] })
      .expect(200);
    const login = await request(authApp).post('/auth/login').send({ email, password: PASSWORD });
    expect(login.status).toBe(200);
    return { id: login.body.user.id, token: login.body.access_token };
  }

  async function newAdmin(): Promise<{ id: string; token: string }> {
    const email = `res-admin-${randomUUID()}@example.com`;
    await db.query(
      `INSERT INTO users (email, password_hash, status) VALUES ($1, $2, 'active')`,
      [email, await hashPassword(PASSWORD)],
    );
    await db.query(
      `INSERT INTO user_roles (user_id, role_id)
       SELECT u.id, r.id FROM users u, roles r WHERE u.email = $1 AND r.name = 'admin'`,
      [email],
    );
    const login = await request(authApp).post('/auth/login').send({ email, password: PASSWORD });
    expect(login.status).toBe(200);
    return { id: login.body.user.id, token: login.body.access_token };
  }

  function gw(token: string) {
    const auth = (r: request.Test) => r.set('Authorization', `Bearer ${token}`);
    return {
      get: (url: string) => auth(request(gateway).get(url)),
      post: (url: string) => auth(request(gateway).post(url)),
      delete: (url: string) => auth(request(gateway).delete(url)),
    };
  }

  it('rejects direct access to the resource API (shared-secret proof)', async () => {
    const res = await request(resourceApi).get('/api/v1/documents');
    expect(res.status).toBe(403);
    expect(res.body.error).toBe('FORBIDDEN_ORIGIN');
  });

  it('rejects identity-less requests even with the shared secret', async () => {
    const res = await request(resourceApi)
      .get('/api/v1/documents')
      .set('X-Internal-Secret', process.env.GATEWAY_SHARED_SECRET!);
    expect(res.status).toBe(401);
    expect(res.body.error).toBe('NO_IDENTITY');
  });

  it('creates and lists documents scoped to the owning user', async () => {
    // Admin tokens carry api.write; regular users are read-only by default.
    const userA = await newAdmin();
    const created = await gw(userA.token)
      .post('/api/v1/documents')
      .send({ title: 'My doc', content: 'secret plans' });
    expect(created.status).toBe(201);

    const listA = await gw(userA.token).get('/api/v1/documents');
    expect(listA.status).toBe(200);
    expect(listA.body.data).toHaveLength(1);
    expect(listA.body.data[0].owner_id).toBe(userA.id);

    // User B sees an empty list - tenant isolation.
    const userB = await newUser();
    const listB = await gw(userB.token).get('/api/v1/documents');
    expect(listB.status).toBe(200);
    expect(listB.body.data).toHaveLength(0);

    // A read-only user is stopped at the scope layer before ownership checks...
    const docId = listA.body.data[0].id as string;
    const readonlyForeign = await gw(userB.token).delete(`/api/v1/documents/${docId}`);
    expect(readonlyForeign.status).toBe(403);
    expect(readonlyForeign.body.error).toBe('INSUFFICIENT_SCOPE');

    // ...while another admin (write scope) gets a 404 that does not leak existence.
    const adminB = await newAdmin();
    const foreign = await gw(adminB.token).delete(`/api/v1/documents/${docId}`);
    expect(foreign.status).toBe(404);
  });

  it('blocks api.write-only service tokens from creating documents', async () => {
    const adminEmail = `res-admin-${randomUUID()}@example.com`;
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
    const client = await request(authApp)
      .post('/admin/clients')
      .set('Authorization', `Bearer ${adminLogin.body.access_token}`)
      .send({
        name: 'Res svc',
        client_type: 'confidential',
        redirect_uris: ['https://svc.example.com/cb'],
        allowed_scopes: ['api.read', 'api.write'],
        grant_types: ['client_credentials'],
        token_endpoint_auth_method: 'client_secret_basic',
      });
    expect(client.status).toBe(201);

    const tokenRes = await request(authApp)
      .post('/oauth/token')
      .type('form')
      .auth(client.body.client.client_id, client.body.client_secret)
      .send({ grant_type: 'client_credentials', scope: 'api.read api.write' });
    expect(tokenRes.status).toBe(200);
    const svcToken = tokenRes.body.access_token;

    // Service tokens can read all documents...
    const listAll = await gw(svcToken).get('/api/v1/documents');
    expect(listAll.status).toBe(200);

    // ...but cannot create (no end-user identity).
    const created = await gw(svcToken)
      .post('/api/v1/documents')
      .send({ title: 'svc doc' });
    expect(created.status).toBe(403);
    expect(created.body.error).toBe('SERVICE_FORBIDDEN');
  });

  it('exposes verified identity at /api/v1/me', async () => {
    const { id, token } = await newUser();
    const res = await gw(token).get('/api/v1/me');
    expect(res.status).toBe(200);
    expect(res.body.userId).toBe(id);
    expect(res.body.scopes).toContain('api.read');
    expect(res.body.roles).toEqual(['user']);
  });
});
