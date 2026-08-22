/**
 * Integration tests: RBAC guards, admin endpoints, audit trail and MFA.
 */
import request from 'supertest';
import { randomUUID } from 'node:crypto';
import { Express } from 'express';

process.env.NODE_ENV = 'test';
process.env.RATE_LIMIT_REGISTER = '100';
process.env.RATE_LIMIT_LOGIN = '100';
process.env.RATE_LIMIT_TOKEN = '100';
process.env.MAX_FAILED_LOGINS = '50';

import { authenticator } from 'otplib';
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

describe('RBAC + admin + audit + MFA', () => {
  let db: Database;
  let redis: RedisService;
  let app: Express;
  let mockEmail: MockEmailProvider;
  const config = loadConfig();
  let adminEmail: string;

  beforeAll(async () => {
    db = new Database();
    redis = new RedisService();
    const kms = new LocalKeyProvider(config.KMS_KEY_DIR);
    mockEmail = new MockEmailProvider();
    setEmailProvider(mockEmail);
    app = createAuthServer({ db, redis, kms, email: mockEmail });
    finalizeApp(app);

    // Deterministic admin for this test file (seed admin password is random).
    adminEmail = `admin-${randomUUID()}@example.com`;
    await db.query(
      `INSERT INTO users (email, password_hash, status) VALUES ($1, $2, 'active')`,
      [adminEmail, await hashPassword(PASSWORD)],
    );
    await db.query(
      `INSERT INTO user_roles (user_id, role_id)
       SELECT u.id, r.id FROM users u, roles r WHERE u.email = $1 AND r.name = 'admin'`,
      [adminEmail],
    );
  });

  afterAll(async () => {
    await db.close();
    await redis.close();
  });

  async function loginAs(email: string): Promise<{ accessToken: string; refreshToken: string }> {
    const res = await request(app).post('/auth/login').send({ email, password: PASSWORD });
    expect(res.status).toBe(200);
    return { accessToken: res.body.access_token, refreshToken: res.body.refresh_token };
  }

  async function registerVerifiedUser(): Promise<string> {
    const email = `rbac-${randomUUID()}@example.com`;
    await request(app).post('/auth/register').send({ email, password: PASSWORD });
    const mail = mockEmail.sent.reverse().find((m) => m.to === email)!;
    const token = mail.text.match(/[A-Za-z0-9_-]{40,}/)![0];
    await request(app).post('/auth/verify-email').send({ token });
    return email;
  }

  it('denies anonymous access to /admin/users', async () => {
    expect((await request(app).get('/admin/users')).status).toBe(401);
  });

  it('denies regular users (missing users:read) but allows admins', async () => {
    const userEmail = await registerVerifiedUser();
    const userTokens = await loginAs(userEmail);
    const denied = await request(app)
      .get('/admin/users')
      .set('Authorization', `Bearer ${userTokens.accessToken}`);
    expect(denied.status).toBe(403);
    expect(denied.body.error).toBe('MISSING_PERMISSION');

    const adminTokens = await loginAs(adminEmail);
    const allowed = await request(app)
      .get('/admin/users')
      .set('Authorization', `Bearer ${adminTokens.accessToken}`);
    expect(allowed.status).toBe(200);
    expect(allowed.body.users.length).toBeGreaterThan(0);
    expect(allowed.body.users[0].roles).toBeDefined();
  });

  it('grants a role via API; new token then carries the permission', async () => {
    const userEmail = await registerVerifiedUser();
    const userIdRes = await db.query<{ id: string }>(`SELECT id FROM users WHERE email = $1`, [userEmail]);
    const userId = userIdRes.rows[0]!.id;

    const adminTokens = await loginAs(adminEmail);
    const put = await request(app)
      .put(`/admin/users/${userId}/roles`)
      .set('Authorization', `Bearer ${adminTokens.accessToken}`)
      .send({ roles: ['support'] });
    expect(put.status).toBe(200);

    // support has audit:read
    const supportLogin = await loginAs(userEmail);
    expect(supportLogin.accessToken.split('.')).toHaveLength(3);

    const audit = await request(app)
      .get('/admin/audit?limit=5')
      .set('Authorization', `Bearer ${supportLogin.accessToken}`);
    expect(audit.status).toBe(200);
    expect(Array.isArray(audit.body.events)).toBe(true);
    // Audit must never leak credentials:
    expect(JSON.stringify(audit.body.events)).not.toContain(PASSWORD);
  });

  it('audit events exist for registration/login/token issuance', async () => {
    const email = await registerVerifiedUser();
    await request(app).post('/auth/login').send({ email, password: PASSWORD });

    const rows = await db.query<{ event_type: string }>(
      `SELECT DISTINCT event_type FROM audit_logs al
       JOIN users u ON u.id = al.user_id WHERE u.email = $1`,
      [email],
    );
    const types = rows.rows.map((r) => r.event_type);
    expect(types).toContain('USER_REGISTERED');
    expect(types).toContain('USER_LOGIN_SUCCESS');
    expect(types).toContain('TOKEN_ISSUED');
  });

  it('full MFA lifecycle: enroll -> confirm -> login requires challenge -> verify issues tokens -> disable', async () => {
    const email = await registerVerifiedUser();
    const first = await loginAs(email);

    // Enroll
    const enroll = await request(app)
      .post('/mfa/enroll')
      .set('Authorization', `Bearer ${first.accessToken}`)
      .send({});
    expect(enroll.status).toBe(201);
    const otpauth = enroll.body.otpauth_url as string;
    expect(otpauth).toContain('otpauth://totp/');
    const secret = otpauth.match(/secret=([^&]+)/)![1]!;
    expect(secret.length).toBeGreaterThanOrEqual(16);
    // QR is a data URL
    expect(enroll.body.qr_data_url).toMatch(/^data:image\/png;base64,/);

    // Confirm enrollment with a valid code
    const code1 = authenticator.generate(secret);
    const confirm = await request(app)
      .post('/mfa/verify')
      .set('Authorization', `Bearer ${first.accessToken}`)
      .send({ code: code1 });
    expect(confirm.status).toBe(200);
    expect(confirm.body.status).toBe('mfa_enabled');

    // Next login demands the second factor - no tokens yet
    const challenge = await request(app).post('/auth/login').send({ email, password: PASSWORD });
    expect(challenge.status).toBe(200);
    expect(challenge.body.mfa_required).toBe(true);
    expect(challenge.body.access_token).toBeUndefined();

    // Wrong code rejected
    const badCode = String((Number(code1) + 1) % 10 === 0 ? Number(code1) + 2 : Number(code1) + 1).padStart(6, '0');
    const wrong = await request(app)
      .post('/mfa/verify')
      .send({ mfa_challenge_id: challenge.body.mfa_challenge_id, code: badCode });
    expect(wrong.status).toBe(401);

    // Correct code completes login and issues tokens with amr pwd+mfa
    const code2 = authenticator.generate(secret);
    const done = await request(app)
      .post('/mfa/verify')
      .send({ mfa_challenge_id: challenge.body.mfa_challenge_id, code: code2 });
    expect(done.status).toBe(200);
    expect(done.body.access_token).toBeDefined();

    const [, payloadB64] = done.body.access_token.split('.');
    const payload = JSON.parse(Buffer.from(payloadB64!, 'base64url').toString());
    expect(payload.amr).toEqual(['pwd', 'mfa']);

    // Disable MFA again (needs valid code), login returns tokens directly
    const code3 = authenticator.generate(secret);
    const disable = await request(app)
      .post('/mfa/disable')
      .set('Authorization', `Bearer ${done.body.access_token}`)
      .send({ code: code3 });
    expect(disable.status).toBe(200);

    const finalLogin = await request(app).post('/auth/login').send({ email, password: PASSWORD });
    expect(finalLogin.status).toBe(200);
    expect(finalLogin.body.access_token).toBeDefined();
  });
});
