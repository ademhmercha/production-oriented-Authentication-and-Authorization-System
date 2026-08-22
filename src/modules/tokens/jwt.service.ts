import {
  SignJWT,
  jwtVerify,
  decodeProtectedHeader,
  importPKCS8,
  importSPKI,
} from 'jose';
import type { JWTPayload } from 'jose';
import { KeyManagementService, KmsError } from '../keys/kms.types';
import { AppError, AuthError } from '../../common/errors';

/**
 * JWT access/ID token service.
 *
 * SECURITY DECISIONS:
 * - Asymmetric signing with EdDSA (Ed25519) so resource servers/gateway only
 *   ever need public keys (via JWKS).
 * - Short-lived access tokens; TTL configurable via ACCESS_TOKEN_TTL.
 * - Minimal claims only: no PII beyond user id, scope and roles.
 */
export interface AccessTokenInput {
  sub: string;
  scope: string;
  roles?: string[];
  /** Expanded RBAC permissions (from roles) embedded for stateless checks. */
  permissions?: string[];
  sid?: string;
  client_id?: string;
  amr?: string[];
}

export interface AccessTokenPayload extends JWTPayload {
  sub: string;
  scope: string;
  roles?: string[];
  permissions?: string[];
  sid?: string;
  client_id?: string;
  amr?: string[];
}

export interface JwtServiceOptions {
  issuer: string;
  audience: string;
  defaultTtlSeconds: number;
}

export class JwtService {
  private revocationChecker?: (jti: string) => Promise<boolean>;

  constructor(
    private readonly kms: KeyManagementService,
    private readonly options: JwtServiceOptions,
  ) {}

  /**
   * Optional denylist hook (Redis-backed in production): when set, tokens
   * whose jti was explicitly revoked are rejected even before expiry.
   */
  setRevocationChecker(checker: (jti: string) => Promise<boolean>): void {
    this.revocationChecker = checker;
  }

  async signAccessToken(input: AccessTokenInput, ttlOverrideSeconds?: number): Promise<{
    token: string;
    jti: string;
    expiresAt: Date;
    issuedAt: Date;
  }> {
    const { kid, privateKeyPem } = await this.kms.getCurrentSigningKey();
    const key = await importPKCS8(privateKeyPem, 'EdDSA');

    const ttl = ttlOverrideSeconds ?? this.options.defaultTtlSeconds;
    const now = Math.floor(Date.now() / 1000);
    const jti = crypto.randomUUID();

    const token = await new SignJWT({
      scope: input.scope,
      ...(input.roles?.length ? { roles: input.roles } : {}),
      ...(input.permissions?.length ? { permissions: input.permissions } : {}),
      ...(input.sid ? { sid: input.sid } : {}),
      ...(input.client_id ? { client_id: input.client_id } : {}),
      ...(input.amr ? { amr: input.amr } : {}),
    })
      .setProtectedHeader({ alg: 'EdDSA', kid, typ: 'JWT' })
      .setIssuer(this.options.issuer)
      .setAudience(this.options.audience)
      .setSubject(input.sub)
      .setIssuedAt(now)
      .setNotBefore(now)
      .setJti(jti)
      .setExpirationTime(now + ttl)
      .sign(key);

    return {
      token,
      jti,
      expiresAt: new Date((now + ttl) * 1000),
      issuedAt: new Date(now * 1000),
    };
  }

  /**
   * Verifies signature (against the key identified by kid), iss, aud, exp, nbf
   * and algorithm confusion. Throws AuthError subclasses on any failure.
   */
  async verifyAccessToken(token: string): Promise<AccessTokenPayload> {
    try {
      const headerResult = decodeProtectedHeaderSafe(token);
      if (headerResult.alg !== 'EdDSA') {
        throw new AuthError('Unsupported token algorithm', 'UNSUPPORTED_TOKEN_ALG');
      }
      const kid = headerResult.kid;
      const signing = kid
        ? await this.kms.getPublicKey(kid)
        // No kid: fall back to newest known key.
        : (await this.kms.listPublicKeys())[0];
      if (!signing) throw new AuthError('Unknown signing key', 'UNKNOWN_SIGNING_KEY');

      const publicKey = await importSPKI(signing.publicKeyPem, 'EdDSA');
      const { payload } = await jwtVerify(token, publicKey, {
        issuer: this.options.issuer,
        audience: this.options.audience,
        algorithms: ['EdDSA'],
        clockTolerance: 5,
        requiredClaims: ['iss', 'sub', 'aud', 'exp', 'iat', 'jti'],
      });
      if (payload.jti && this.revocationChecker && (await this.revocationChecker(payload.jti))) {
        throw new AuthError('Token has been revoked', 'TOKEN_REVOKED');
      }
      return payload as AccessTokenPayload;
    } catch (err) {
      throw mapJoseError(err);
    }
  }

  /** ID token for OIDC flows: aud = client_id, sub = user id, plus extra claims. */
  async signIdToken(
    extraClaims: Record<string, unknown>,
    audience: string,
    subject: string,
    ttlSeconds: number,
  ): Promise<string> {
    const { kid, privateKeyPem } = await this.kms.getCurrentSigningKey();
    const key = await importPKCS8(privateKeyPem, 'EdDSA');
    const now = Math.floor(Date.now() / 1000);
    return new SignJWT({ ...extraClaims })
      .setProtectedHeader({ alg: 'EdDSA', kid, typ: 'JWT' })
      .setIssuer(this.options.issuer)
      .setAudience(audience)
      .setSubject(subject)
      .setIssuedAt(now)
      .setNotBefore(now)
      .setExpirationTime(now + ttlSeconds)
      .sign(key);
  }
}

function decodeProtectedHeaderSafe(token: string): { alg?: string; kid?: string; typ?: string } {
  try {
    return decodeProtectedHeader(token) as { alg?: string; kid?: string; typ?: string };
  } catch {
    throw new AuthError('Malformed token', 'MALFORMED_TOKEN');
  }
}

function mapJoseError(err: unknown): AppError {
  if (err instanceof AppError || err instanceof KmsError) {
    return err instanceof KmsError ? new AuthError(err.message, 'KMS_ERROR') : err;
  }
  const e = err as { code?: string; message?: string };
  switch (e?.code) {
    case 'ERR_JWT_EXPIRED':
      return new AuthError('Token expired', 'TOKEN_EXPIRED');
    case 'ERR_JWS_SIGNATURE_VERIFICATION_FAILED':
    case 'ERR_JWS_VERIFICATION_FAILED':
      return new AuthError('Invalid token signature', 'INVALID_TOKEN_SIGNATURE');
    case 'ERR_JWT_CLAIM_VALIDATION_FAILED':
      return new AuthError('Invalid token claims', 'INVALID_TOKEN_CLAIMS');
    case 'ERR_JWT_MALFORMED':
      return new AuthError('Malformed token', 'MALFORMED_TOKEN');
    default:
      return new AuthError('Invalid token', 'INVALID_TOKEN');
  }
}
