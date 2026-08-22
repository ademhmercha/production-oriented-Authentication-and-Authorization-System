import { RedisService } from '../../infrastructure/redis/redis.service';

/**
 * Stateless-token revocation cache.
 *
 * JWTs cannot be "deleted", so revoked access-token identifiers (jti) are
 * blacklisted in Redis until their natural expiry. Verification consults
 * this list; entries self-purge when the token would expire anyway.
 */
export class TokenRevocationService {
  constructor(private readonly redis: RedisService) {}

  async revokeUntil(jti: string, expiresAtEpochSeconds: number): Promise<void> {
    const ttl = Math.max(1, Math.ceil(expiresAtEpochSeconds - Date.now() / 1000));
    await this.redis.set(RedisService.key('jti', 'revoked', jti), '1', ttl);
  }

  async isRevoked(jti: string): Promise<boolean> {
    const v = await this.redis.get(RedisService.key('jti', 'revoked', jti));
    return v === '1';
  }
}
