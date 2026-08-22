/**
 * Integration test: user registration + email verification against a real
 * Postgres. Requires migrations applied (docker compose / npm run migrate).
 */
import request from 'supertest';
import { randomUUID } from 'node:crypto';
import { createHash } from 'node:crypto';
import { loadConfig, resetConfigCache } from '../../src/config';
import { Database } from '../../src/infrastructure/database/pool';
import { RedisService } from '../../src/infrastructure/redis/redis.service';
import { LocalKeyProvider } from '../../src/modules/keys/local-key-provider';
import { MockEmailProvider } from '../../src/modules/email/mock-email.provider';
import { setEmailProvider } from '../../src/modules/email/email.factory';
import { createAuthServer, finalizeApp } from '../../src/app.factory';

process.env.NODE_ENV = 'test';
resetConfigCache();

describe('POST /auth/register + POST /auth/verify-email', () => {
  let db: Database;
  let redis: RedisService;
  let app: ReturnType<typeof createAuthServer>;
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

  it('registers a user, sends verification token, and verifies the email', async () => {
    const email = `user-${randomUUID()}@example.com`;
    const res = await request(app)
      .post('/auth/register')
      .send({ email, password: 'CorrectHorse9!x', first_name: 'Ada', last_name: 'Lovelace' });

    expect(res.status).toBe(201);
    expect(res.body.user.email).toBe(email);
    expect(res.body.user.status).toBe('pending_verification');
    // No hash leakage:
    expect(JSON.stringify(res.body)).not.toContain('password_hash');
    expect(JSON.stringify(res.body)).not.toContain('argon2');

    const verification = mockEmail.sent.find((m) => m.to === email);
    expect(verification).toBeDefined();
    const tokenMatch = verification!.text.match(/[A-Za-z0-9_-]{40,}/);
    expect(tokenMatch).toBeTruthy();

    const verifyRes = await request(app)
      .post('/auth/verify-email')
      .send({ token: tokenMatch![0] });
    expect(verifyRes.status).toBe(200);

    // Token is single-use.
    const reuse = await request(app).post('/auth/verify-email').send({ token: tokenMatch![0] });
    expect(reuse.status).toBe(409);
  });

  it('rejects duplicate registration with 409', async () => {
    const email = `dup-${randomUUID()}@example.com`;
    const body = { email, password: 'CorrectHorse9!x' };
    const first = await request(app).post('/auth/register').send(body);
    expect(first.status).toBe(201);
    const second = await request(app).post('/auth/register').send(body);
    expect(second.status).toBe(409);
  });

  it('rejects weak passwords with policy details', async () => {
    const res = await request(app)
      .post('/auth/register')
      .send({ email: `weak-${randomUUID()}@example.com`, password: 'short1A' });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('VALIDATION_ERROR');
    expect(JSON.stringify(res.body.details)).toContain('characters');
  });

  it('rejects malformed emails via schema validation', async () => {
    const res = await request(app)
      .post('/auth/register')
      .send({ email: 'not-an-email', password: 'CorrectHorse9!x' });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('VALIDATION_ERROR');
  });

  it('stores only the password hash (never plaintext)', async () => {
    const email = `hash-${randomUUID()}@example.com`;
    await request(app)
      .post('/auth/register')
      .send({ email, password: 'CorrectHorse9!x' });

    const result = await db.query<{ password_hash: string }>(
      'SELECT password_hash FROM users WHERE email = $1',
      [email],
    );
    const hash = result.rows[0]?.password_hash ?? '';
    expect(hash.startsWith('$argon2')).toBe(true);
    expect(hash).not.toContain('CorrectHorse');
    void createHash;
  });
});
