import { createRemoteJWKSet, jwtVerify } from 'jose';
import type { JWTPayload } from 'jose';
import { AuthError } from '../../common/errors';

/**
 * Remote token verification for edge services (API gateway).
 *
 * Verifies access tokens against the auth-server's published JWKS
 * (key rotation friendly: new kids are fetched automatically) instead of
 * sharing signing keys. The issuer/audience/alg constraints mirror the
 * auth-server's own verification.
 */
export class RemoteTokenVerifier {
  private readonly jwks: ReturnType<typeof createRemoteJWKSet>;
  private revocationChecker?: (jti: string) => Promise<boolean>;

  constructor(
    private readonly options: {
      jwksUrl: string;
      issuer: string;
      audience: string;
    },
  ) {
    this.jwks = createRemoteJWKSet(new URL(options.jwksUrl), {
      cacheMaxAge: 60_000, // refresh keys at most once a minute
    });
  }

  /** Optional denylist hook (Redis-backed), same semantics as auth-server side. */
  setRevocationChecker(checker: (jti: string) => Promise<boolean>): void {
    this.revocationChecker = checker;
  }

  async verify(token: string): Promise<JWTPayload> {
    try {
      const { payload } = await jwtVerify(token, this.jwks, {
        issuer: this.options.issuer,
        audience: this.options.audience,
        algorithms: ['EdDSA'],
        clockTolerance: 5,
        requiredClaims: ['iss', 'sub', 'aud', 'exp', 'iat', 'jti', 'scope'],
      });
      if (payload.jti && this.revocationChecker && (await this.revocationChecker(payload.jti))) {
        throw new AuthError('Token has been revoked', 'TOKEN_REVOKED');
      }
      return payload;
    } catch (err) {
      if (err instanceof AuthError) throw err;
      const code = (err as { code?: string }).code ?? '';
      if (code === 'ERR_JWT_EXPIRED') {
        throw new AuthError('Token expired', 'TOKEN_EXPIRED');
      }
      if (code === 'ERR_JWKS_NO_MATCHING_KEY' || code === 'ERR_JWKS_MULTIPLE_MATCHING_KEYS') {
        throw new AuthError('Unknown signing key', 'UNKNOWN_SIGNING_KEY');
      }
      throw new AuthError('Invalid access token', 'INVALID_TOKEN');
    }
  }
}
