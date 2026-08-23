/**
 * Deterministic environment for unit tests. Loaded via jest setupFiles so it
 * runs BEFORE any module import can trigger loadConfig().
 */
process.env.NODE_ENV ??= 'test';
process.env.LOG_LEVEL = process.env.LOG_LEVEL ?? 'fatal';

process.env.DATABASE_URL = process.env.DATABASE_URL ?? 'postgres://test:test@localhost:5432/test';
process.env.REDIS_URL = process.env.REDIS_URL ?? 'redis://localhost:6379/1';

process.env.JWT_ISSUER = 'https://auth.test';
process.env.JWT_AUDIENCE = 'api';
process.env.ACCESS_TOKEN_TTL = '900';

// Fixed 32-byte master key for reproducible crypto tests.
process.env.KMS_MASTER_KEY = Buffer.alloc(32, 0xab).toString('base64');

export {};
