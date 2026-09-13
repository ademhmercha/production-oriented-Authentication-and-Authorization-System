/**
 * Runtime configuration from environment variables, validated with zod at
 * startup so missing or malformed settings fail fast.
 */
import 'dotenv/config';
import { z } from 'zod';

const int = (defaultValue?: number) =>
  z
    .string()
    .optional()
    .transform((v) => (v === undefined || v === '' ? defaultValue : Number(v)))
    .pipe(z.number().int().finite());

const bool = (defaultValue: boolean) =>
  z
    .string()
    .optional()
    .transform((v) => (v === undefined || v === '' ? defaultValue : v === 'true' || v === '1'));

const envSchema = z.object({
  // Runtime
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: int(3001),
  GATEWAY_PORT: int(3000),
  FRONTEND_PORT: int(8080),
  LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace']).default('info'),

  // Persistence
  DATABASE_URL: z.string().min(1, 'DATABASE_URL is required'),
  DATABASE_POOL_MAX: int(10),
  REDIS_URL: z.string().min(1, 'REDIS_URL is required'),

  // Tokens / JWT
  JWT_ISSUER: z.string().url().default('https://auth.local'),
  JWT_AUDIENCE: z.string().default('api'),
  ACCESS_TOKEN_TTL: int(900), // seconds, 15 min default; spec allows 5-15 min
  REFRESH_TOKEN_TTL: int(60 * 60 * 24 * 14), // 14 days
  AUTHORIZATION_CODE_TTL: int(120), // 2 minutes per OAuth spec guidance (< 10 min)
  ID_TOKEN_TTL: int(3600),
  SESSION_TTL: int(60 * 60 * 24 * 30),

  // Key management
  KMS_PROVIDER: z.enum(['local', 'aws-kms', 'azure-kv', 'gcp-kms', 'vault']).default('local'),
  KMS_KEY_DIR: z.string().default('./keys'),
  KMS_MASTER_KEY: z.string().optional(), // base64 32-byte key used by LocalKeyProvider to wrap signing keys at rest

  // Passwords
  PASSWORD_MIN_LENGTH: int(12),
  BCRYPT_ROUNDS: int(12), // only used if argon2 unavailable; argon2id is primary

  // Email
  EMAIL_PROVIDER: z.enum(['mock', 'smtp']).default('mock'),
  SMTP_HOST: z.string().optional(),
  SMTP_PORT: int(1025),
  SMTP_USER: z.string().optional(),
  SMTP_PASSWORD: z.string().optional(),
  SMTP_FROM: z.string().default('no-reply@auth.local'),
  EMAIL_SECURE: bool(false),
  EMAIL_VERIFICATION_TTL: int(60 * 60 * 24), // 24h
  PASSWORD_RESET_TTL: int(60 * 30), // 30 min

  // CORS / security
  CORS_ORIGINS: z.string().default('http://localhost:3000,http://localhost:8080'),
  TRUST_PROXY: bool(true),
  COOKIE_DOMAIN: z.string().optional(),

  // Rate limiting (requests per window per key)
  RATE_LIMIT_WINDOW: int(60),
  RATE_LIMIT_LOGIN: int(5),
  RATE_LIMIT_REGISTER: int(3),
  RATE_LIMIT_FORGOT_PASSWORD: int(3),
  RATE_LIMIT_TOKEN: int(10),
  RATE_LIMIT_AUTHORIZE: int(10),
  RATE_LIMIT_API: int(120),

  // Risk engine
  RISK_FAILED_LOGINS_THRESHOLD: int(5),
  RISK_LOCKOUT_MINUTES: int(15),
  RISK_HIGH_SCORE_ACTION: z.enum(['deny', 'mfa', 'allow']).default('mfa'),

  // Account lockout
  MAX_FAILED_LOGINS: int(5),
  LOCKOUT_MINUTES: int(15),

  // MFA
  MFA_ISSUER: z.string().default('Identity Platform'),
  MFA_CHALLENGE_TTL: int(300),

  // Service topology (used by gateway + e2e)
  AUTH_SERVER_URL: z.string().url().default('http://localhost:3001'),
  RESOURCE_API_URL: z.string().url().default('http://localhost:3002'),
  RESOURCE_PORT: int(3002),
  // Shared secret proving requests reached the resource API via the gateway.
  GATEWAY_SHARED_SECRET: z.string().optional(),

  // Frontend (browser SPA) service
  // Same-origin (empty string) lets the SPA talk to the platform through one
  // host (Ingress / nginx). Set explicit origins for local development where
  // the backends run on different ports than the frontend.
  PUBLIC_AUTH_BASE: z.string().default(''),
  PUBLIC_API_BASE: z.string().default(''),

  // Bootstrap admin (seed only)
  ADMIN_EMAIL: z.string().email().default('admin@auth.local'),
  ADMIN_PASSWORD: z.string().optional(),
});

export type AppConfig = z.infer<typeof envSchema> & {
  corsOriginsList: string[];
  isProd: boolean;
  isTest: boolean;
};

let cached: AppConfig | null = null;

export function loadConfig(): AppConfig {
  if (cached) return cached;

  const parsed = envSchema.safeParse(process.env);
  if (!parsed.success) {
    const issues = parsed.error.issues
      .map((i) => `  - ${i.path.join('.')}: ${i.message}`)
      .join('\n');
    throw new Error(`Invalid environment configuration:\n${issues}`);
  }

  const cfg = parsed.data;
  cached = {
    ...cfg,
    corsOriginsList: cfg.CORS_ORIGINS.split(',')
      .map((s) => s.trim())
      .filter(Boolean),
    isProd: cfg.NODE_ENV === 'production',
    isTest: cfg.NODE_ENV === 'test',
  };
  return cached;
}

/** Test helper: reset the cached config so a new env can be loaded. */
export function resetConfigCache(): void {
  cached = null;
}
