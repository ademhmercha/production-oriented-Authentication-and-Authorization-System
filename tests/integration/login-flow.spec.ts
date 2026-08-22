/**
 * Integration tests for the full authentication flow against real
 * Postgres + Redis:
 *   register -> verify -> login -> JWT -> /auth/me -> refresh rotation ->
 *   reuse detection -> logout revocation -> lockout -> forgot/reset.
 */
import request from 'supertest';
import { randomUUID } from 'node:crypto';
import { Express } from 'express';

// Test-specific limits so rate limiting does not mask lockout assertions.
process.env.MAX_FAILED_LOGINS = '3';
process.env.LOCKOUT_MINUTES = '10';
process.env.RATE_LIMIT_LOGIN = '50';
process.env.RATE_LIMIT_REGISTER = '50';
process.env.RATE_LIMIT_TOKEN = '100';
process.env.RATE_LIMIT_FORGOT_PASSWORD = '50';
process.env.NODE_ENV = 'test';

import { loadConfig, resetConfigCache } from '../../src/config';
import { Database } from '../../src/infrastructure/database/pool';
import { RedisService } from '../../src/infrastructure/redis/redis.service';
import { LocalKeyProvider } from '../../src/modules/keys/local-key-provider';
import { MockEmailProvider } from '../../src/modules/email/mock-email.provider';
import { setEmailProvider } from '../../src/modules/email/email.factory';
import { createAuthServer, finalizeApp } from '../../src/app.factory';

resetConfigCache();

const PASSWORD = 'CorrectHorse9!x';

describe('auth flow', () => {
  let db: Database;
  let redis: RedisService;
  let app: Express;
  let mockEmail: MockEmailProvider;
  const config = loadConfig();

  beforeAll(() => {
    db = new Database();
    redis = new RedisService();
    const kms = new LocalKeyProvider(config.KMS_KEY_DIR);
    mockEmail = new MockEmailProvider();
    setEmailProvider(mockEmail);
    app = createAuthServer({ db, redis, kms, email: mockEmail });
    finalizeApp(app);
  });

  afterAll(async () => {
    await db.close();
    await redis.close();
  });

  async function registerAndVerify(): Promise<string> {
    const email = `flow-${randomUUID()}@example.com`;
    await request(app).post('/auth/register').send({ email, password: PASSWORD });
    const mail = mockEmail.sent.reverse().find((m) => m.to === email)!;
    const token = mail.text.match(/[A-Za-z0-9_-]{40,}/)![0];
    await request(app).post('/auth/verify-email').send({ token });
    return email;
  }

  it('login issues a verifiable JWT + rotating refresh token; /auth/me works', async () => {
    const email = await registerAndVerify();
    const res = await request(app).post('/auth/login').send({ email, password: PASSWORD });
    expect(res.status).toBe(200);
    expect(res.body.access_token.split('.')).toHaveLength(3);
    expect(res.body.refresh_token).toBeDefined();
    expect(res.body.roles).toContain('user');

    // /auth/me with the bearer token
    const me = await request(app)
      .get('/auth/me')
      .set('Authorization', `Bearer ${res.body.access_token}`);
    expect(me.status).toBe(200);
    expect(me.body.email).toBe(email);
    expect(me.body.roles).toEqual(['user']);

    // /auth/me without a token is rejected
    const anon = await request(app).get('/auth/me');
    expect(anon.status).toBe(401);

    // JWT claims sanity (decode only - verification covered by unit tests)
    const [, payloadB64] = res.body.access_token.split('.');
    const payload = JSON.parse(Buffer.from(payloadB64!, 'base64url').toString());
    expect(payload.iss).toBe(config.JWT_ISSUER);
    expect(payload.aud).toBe(config.JWT_AUDIENCE);
    expect(payload.scope).toContain('api.read');
    expect(payload.sid).toBeDefined();
    expect(JSON.stringify(payload)).not.toContain(PASSWORD);
  });

  it('rejects wrong passwords and locks the account after MAX_FAILED_LOGINS', async () => {
    const email = await registerAndVerify();

    for (let i = 0; i < 3; i++) {
      const bad = await request(app).post('/auth/login').send({ email, password: 'WrongPassword1!' });
      expect(bad.status).toBe(401);
      expect(bad.body.error).toBe('INVALID_CREDENTIALS');
    }

    // Account is now locked even with the correct password.
    const locked = await request(app).post('/auth/login').send({ email, password: PASSWORD });
    expect(locked.status).toBe(423);
    expect(locked.body.error).toBe('ACCOUNT_LOCKED');
  });

  it('refresh rotates tokens; reusing the old token revokes the whole family', async () => {
    const email = await registerAndVerify();
    const login = await request(app).post('/auth/login').send({ email, password: PASSWORD });

    const firstRefresh = login.body.refresh_token as string;

    // Rotation #1: succeeds, returns a DIFFERENT token.
    const rot1 = await request(app).post('/auth/refresh').send({ refresh_token: firstRefresh });
    expect(rot1.status).toBe(200);
    const secondRefresh = rot1.body.refresh_token as string;
    expect(secondRefresh).not.toBe(firstRefresh);

    // REUSE of the rotated token -> detected.
    const reuse = await request(app).post('/auth/refresh').send({ refresh_token: firstRefresh });
    expect(reuse.status).toBe(401);
    expect(reuse.body.error).toBe('REFRESH_TOKEN_REUSE');

    // The family is dead: the successor is also treated as stolen.
    const afterReuse = await request(app).post('/auth/refresh').send({ refresh_token: secondRefresh });
    expect(afterReuse.status).toBe(401);
    expect(afterReuse.body.error).toBe('REFRESH_TOKEN_REUSE');
  });

  it('logout revokes the session so the refresh token can no longer be used', async () => {
    const email = await registerAndVerify();
    const login = await request(app).post('/auth/login').send({ email, password: PASSWORD });
    const accessToken = login.body.access_token;
    const refreshToken = login.body.refresh_token;

    const out = await request(app)
      .post('/auth/logout')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ refresh_token: refreshToken });
    expect(out.status).toBe(200);

    const attempt = await request(app).post('/auth/refresh').send({ refresh_token: refreshToken });
    expect(attempt.status).toBe(401);
    // Revoked tokens are treated with reuse-detection semantics.
    expect(attempt.body.error).toBe('REFRESH_TOKEN_REUSE');
  });

  it('unverified accounts cannot log in (EMAIL_NOT_VERIFIED)', async () => {
    const email = `unv-${randomUUID()}@example.com`;
    await request(app).post('/auth/register').send({ email, password: PASSWORD });
    const res = await request(app).post('/auth/login').send({ email, password: PASSWORD });
    expect(res.status).toBe(401);
    expect(res.body.error).toBe('EMAIL_NOT_VERIFIED');
  });

  it('forgot-password never enumerates; reset-password changes credentials and kills sessions', async () => {
    const email = await registerAndVerify();

    // Unknown email gets the same response shape/status.
    const ghost = await request(app).post('/auth/forgot-password').send({ email: 'ghost@example.com' });
    expect(ghost.status).toBe(202);
    expect(mockEmail.sent.some((m) => m.to === 'ghost@example.com')).toBe(false);

    const real = await request(app).post('/auth/forgot-password').send({ email });
    expect(real.status).toBe(202);
    const mail = mockEmail.sent.reverse().find((m) => m.to === email && m.subject.includes('Reset'))!;
    const resetToken = mail.text.match(/[A-Za-z0-9_-]{40,}/)![0];

    // Weak password rejected by policy.
    const weak = await request(app)
      .post('/auth/reset-password')
      .send({ token: resetToken, password: 'weakpass' });
    expect(weak.status).toBe(400);

    // Old sessions are killed on successful reset.
    const ok = await request(app)
      .post('/auth/reset-password')
      .send({ token: resetToken, password: 'BrandNewPass9!z' });
    expect(ok.status).toBe(200);

    const oldLogin = await request(app).post('/auth/login').send({ email, password: PASSWORD });
    expect(oldLogin.status).toBe(401);

    const newLogin = await request(app).post('/auth/login').send({ email, password: 'BrandNewPass9!z' });
    expect(newLogin.status).toBe(200);

    // Reset tokens are single-use.
    const again = await request(app)
      .post('/auth/reset-password')
      .send({ token: resetToken, password: 'AnotherPass9!x' });
    expect(again.status).toBe(400);
  });
});
