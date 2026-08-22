import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { SignJWT } from 'jose';
import { LocalKeyProvider } from '../../src/modules/keys/local-key-provider';
import { JwtService } from '../../src/modules/tokens/jwt.service';

function makeJwtService(opts?: { issuer?: string; audience?: string; ttl?: number }) {
  const dir = mkdtempSync(join(tmpdir(), 'jwt-test-'));
  const kms = new LocalKeyProvider(dir);
  const svc = new JwtService(kms, {
    issuer: opts?.issuer ?? 'https://auth.test',
    audience: opts?.audience ?? 'api',
    defaultTtlSeconds: opts?.ttl ?? 900,
  });
  return { svc, kms };
}

const claims = {
  sub: '11111111-1111-1111-1111-111111111111',
  scope: 'openid profile email api.read',
  roles: ['user'],
  sid: 'sess-123',
};

describe('JwtService', () => {
  it('signs and verifies an access token with expected claims', async () => {
    const { svc } = makeJwtService();
    const signed = await svc.signAccessToken(claims);

    expect(signed.token.split('.')).toHaveLength(3);
    expect(signed.jti).toBeDefined();

    const payload = await svc.verifyAccessToken(signed.token);
    expect(payload.sub).toBe(claims.sub);
    expect(payload.scope).toBe(claims.scope);
    expect(payload.roles).toEqual(['user']);
    expect(payload.sid).toBe('sess-123');
    expect(payload.iss).toBe('https://auth.test');
    expect(payload.aud).toBe('api');
    expect(payload.jti).toBe(signed.jti);
    // header must pin alg + kid
    const [headerB64] = signed.token.split('.');
    const header = JSON.parse(Buffer.from(headerB64!, 'base64url').toString());
    expect(header.alg).toBe('EdDSA');
    expect(header.kid).toMatch(/^sig-/);
  });

  it('rejects an expired token', async () => {
    const { svc } = makeJwtService({ ttl: -30 });
    const signed = await svc.signAccessToken(claims);
    await expect(svc.verifyAccessToken(signed.token)).rejects.toMatchObject({
      code: 'TOKEN_EXPIRED',
      statusCode: 401,
    });
  });

  it('rejects a token with wrong issuer', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'jwt-test-'));
    const kms = new LocalKeyProvider(dir);
    const signer = new JwtService(kms, { issuer: 'https://auth.test', audience: 'api', defaultTtlSeconds: 900 });
    const verifier = new JwtService(kms, { issuer: 'https://evil.example', audience: 'api', defaultTtlSeconds: 900 });

    const signed = await signer.signAccessToken(claims);
    await expect(verifier.verifyAccessToken(signed.token)).rejects.toMatchObject({
      code: 'INVALID_TOKEN_CLAIMS',
    });
  });

  it('rejects a token with wrong audience', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'jwt-test-'));
    const kms = new LocalKeyProvider(dir);
    const signer = new JwtService(kms, { issuer: 'https://auth.test', audience: 'api', defaultTtlSeconds: 900 });
    const verifier = new JwtService(kms, { issuer: 'https://auth.test', audience: 'other-api', defaultTtlSeconds: 900 });

    const signed = await signer.signAccessToken(claims);
    await expect(verifier.verifyAccessToken(signed.token)).rejects.toMatchObject({
      code: 'INVALID_TOKEN_CLAIMS',
    });
  });

  it('rejects tampered payloads (invalid signature)', async () => {
    const { svc } = makeJwtService();
    const signed = await svc.signAccessToken(claims);
    const parts = signed.token.split('.');
    const forgedPayload = Buffer.from(
      JSON.stringify({
        iss: 'https://auth.test',
        aud: 'api',
        sub: '99999999-9999-9999-9999-999999999999',
        scope: 'openid api.write admin',
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
        jti: 'forged-jti',
      }),
    ).toString('base64url');
    const forged = `${parts[0]}.${forgedPayload}.${parts[2]}`;

    await expect(svc.verifyAccessToken(forged)).rejects.toMatchObject({
      code: expect.stringMatching(/INVALID_TOKEN_SIGNATURE|INVALID_TOKEN/),
    });
  });

  it('rejects tokens signed by an unknown key', async () => {
    const a = makeJwtService();
    const b = makeJwtService();

    const signed = await a.svc.signAccessToken(claims);
    await expect(b.svc.verifyAccessToken(signed.token)).rejects.toBeInstanceOf(Error);
  });

  it('rejects algorithm-confusion (HS256) tokens', async () => {
    const { svc, kms } = makeJwtService();
    const secret = new TextEncoder().encode('attacker-controlled-secret');

    const confused = await new SignJWT({ sub: claims.sub, scope: 'openid admin' })
      .setProtectedHeader({ alg: 'HS256' })
      .setIssuer('https://auth.test')
      .setAudience('api')
      .setExpirationTime(Math.floor(Date.now() / 1000) + 600)
      .sign(secret);

    void kms;
    await expect(svc.verifyAccessToken(confused)).rejects.toMatchObject({
      code: 'UNSUPPORTED_TOKEN_ALG',
    });
  });
});
