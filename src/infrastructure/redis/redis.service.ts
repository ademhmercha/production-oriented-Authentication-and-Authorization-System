import Redis from 'ioredis';

/**
 * Thin client wrapper so business logic never talks to ioredis directly.
 */
export class RedisService {
  private readonly client: Redis;

  constructor(url?: string) {
    this.client = new Redis(url ?? loadRedisUrl(), {
      maxRetriesPerRequest: 3,
      lazyConnect: false,
    });
    this.client.on('error', (err) => {
      // eslint-disable-next-line no-console
      console.error('[redis] error:', err.message);
    });
  }

  /** Namespaced key builder to avoid collisions between environments. */
  static key(...parts: (string | number)[]): string {
    return `identity:${parts.join(':')}`;
  }

  async get(key: string): Promise<string | null> {
    return this.client.get(key);
  }

  async set(key: string, value: string, ttlSeconds?: number): Promise<void> {
    if (ttlSeconds) await this.client.set(key, value, 'EX', ttlSeconds);
    else await this.client.set(key, value);
  }

  /** GETSET-style JSON helper for small cached objects. */
  async getJson<T>(key: string): Promise<T | null> {
    const raw = await this.get(key);
    if (!raw) return null;
    try {
      return JSON.parse(raw) as T;
    } catch {
      return null;
    }
  }

  setJson(key: string, value: unknown, ttlSeconds?: number): Promise<void> {
    return this.set(key, JSON.stringify(value), ttlSeconds);
  }

  async del(key: string): Promise<void> {
    await this.client.del(key);
  }

  async delByPrefix(prefix: string): Promise<number> {
    let cursor = '0';
    let deleted = 0;
    do {
      const [next, keys] = await this.client.scan(cursor, 'MATCH', `${prefix}*`, 'COUNT', 200);
      cursor = next;
      if (keys.length > 0) deleted += await this.client.del(...keys);
    } while (cursor !== '0');
    return deleted;
  }

  /** Fixed-window counter used by RateLimitService. Returns current count. */
  async incrementWindow(key: string, windowSeconds: number): Promise<number> {
    const count = await this.client.incr(key);
    if (count === 1) await this.client.expire(key, windowSeconds);
    return count;
  }

  // Set operations (risk engine: distinct-IP tracking)
  async setAdd(key: string, member: string): Promise<void> {
    await this.client.sadd(key, member);
  }

  async setSize(key: string): Promise<number> {
    return this.client.scard(key);
  }

  async setExpire(key: string, ttlSeconds: number): Promise<void> {
    await this.client.expire(key, ttlSeconds);
  }

  async ttl(key: string): Promise<number> {
    return this.client.ttl(key);
  }

  async ping(): Promise<void> {
    const pong = await this.client.ping();
    if (pong !== 'PONG') throw new Error('Redis ping failed');
  }

  async close(): Promise<void> {
    this.client.disconnect();
  }
}

function loadRedisUrl(): string {
  // Loaded lazily so unit tests that import this module don't force config
  // validation; the URL is only read when a client is actually created.
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const { loadConfig } = require('../../config') as typeof import('../../config');
  return loadConfig().REDIS_URL;
}

let singleton: RedisService | null = null;

export function getRedis(): RedisService {
  if (!singleton) singleton = new RedisService();
  return singleton;
}
