import type { NextFunction, Request, RequestHandler, Response } from 'express';
import { RedisService } from '../../infrastructure/redis/redis.service';
import { TooManyRequestsError } from '../../common/errors';

export interface RateLimitOptions {
  /** Max requests allowed within the window. */
  limit: number;
  /** Window size in seconds. */
  windowSeconds: number;
  /** Logical bucket name, e.g. 'login'. Combined with IP/client identity. */
  bucket: string;
  /**
   * Optional key resolver - defaults to client IP.
   * e.g. use client_id for the OAuth token endpoint.
   */
  keyResolver?: (req: Request) => string;
}

/**
 * Redis fixed-window rate limiter middleware factory.
 *
 * Different buckets get different limits (login vs token vs API), all
 * configurable via environment variables at composition time.
 * Atomicity: INCR + EXPIRE via incrementWindow (count==1 sets expiry).
 */
export function rateLimitMiddleware(redis: RedisService, options: RateLimitOptions): RequestHandler {
  return (req: Request, res: Response, next: NextFunction): void => {
    const identity = options.keyResolver ? options.keyResolver(req) : req.ip ?? 'unknown';
    const key = RedisService.key('rl', options.bucket, identity);
    redis
      .incrementWindow(key, options.windowSeconds)
      .then((count) => {
        const remaining = Math.max(0, options.limit - count);
        res.setHeader('X-RateLimit-Limit', String(options.limit));
        res.setHeader('X-RateLimit-Remaining', String(remaining));
        if (count > options.limit) {
          return redis.ttl(key).then((ttl) => {
            const retry = ttl > 0 ? ttl : options.windowSeconds;
            res.setHeader('Retry-After', String(retry));
            next(new TooManyRequestsError(retry));
          });
        }
        next();
      })
      .catch(next);
  };
}
