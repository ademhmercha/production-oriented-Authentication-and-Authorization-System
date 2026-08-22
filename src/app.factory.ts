/**
 * Auth Server application factory.
 *
 * Composition root for the Authorization Server: wires infrastructure
 * (Postgres, Redis, KMS, email) into module services and mounts routes.
 * Kept as a pure factory so tests can build isolated instances with
 * overridden dependencies.
 */
import express, { Express } from 'express';
import helmet from 'helmet';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import { loadConfig } from './config';
import { logger } from './common/logger';
import { requestIdMiddleware } from './common/middleware/request-id';
import { errorHandler, notFoundHandler } from './common/middleware/error-handler';
import { createHealthRouter } from './modules/health/health.routes';
import { Database } from './infrastructure/database/pool';
import { RedisService } from './infrastructure/redis/redis.service';
import { KeyManagementService } from './modules/keys/kms.types';
import { createKeysRoutes } from './modules/keys/keys.routes';
import { AuditLogService } from './modules/audit/audit.service';
import { EmailProvider } from './modules/email/email.types';
import { UserRepository } from './modules/users/user.repository';
import { EmailTokenService } from './modules/users/email-token.service';
import { UserService } from './modules/users/user.service';
import { createAuthRoutes } from './modules/auth/auth.routes';

/** Fully wired service graph (grows with each module). */
export interface Services {
  db: Database;
  redis: RedisService;
  kms: KeyManagementService;
  audit: AuditLogService;
  users: UserRepository;
  userService: UserService;
}

export interface AuthServerDeps {
  db: Database;
  redis: RedisService;
  kms: KeyManagementService;
  email: EmailProvider;
  /** Override for tests; defaults to the Postgres-backed sink. */
  audit?: AuditLogService;
}

export function buildServices(deps: AuthServerDeps): Services {
  const audit = deps.audit ?? AuditLogService.withDefaults(deps.db);
  const users = new UserRepository(deps.db);
  const emailTokens = new EmailTokenService(deps.db);
  const userService = new UserService(users, emailTokens, audit, deps.email);
  return {
    db: deps.db,
    redis: deps.redis,
    kms: deps.kms,
    audit,
    users,
    userService,
  };
}

export function createAuthServer(deps: AuthServerDeps): Express {
  const config = loadConfig();
  const services = buildServices(deps);

  const app = express();
  app.disable('x-powered-by');
  if (config.TRUST_PROXY) app.set('trust proxy', 1);

  // Security headers (helmet) + strict CORS allow-list.
  app.use(helmet());
  app.use(
    cors({
      origin: config.corsOriginsList,
      credentials: true,
      methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    }),
  );

  app.use(requestIdMiddleware());
  app.use(express.json({ limit: '100kb' }));
  app.use(cookieParser());

  // Public key material for JWT verification (JWKS).
  app.use(createKeysRoutes(services.kms));

  // Authentication endpoints.
  app.use('/auth', createAuthRoutes(services.userService));

  app.use('/health', createHealthRouter({
    readinessChecks: {
      postgres: () => services.db.ping(),
      redis: () => services.redis.ping(),
      kms: async () => {
        await services.kms.getCurrentSigningKey();
      },
    },
  }));

  return app;
}

/** Finalizes the app: 404 + central error handling must be registered last. */
export function finalizeApp(app: Express): void {
  app.use(notFoundHandler);
  app.use(errorHandler(logger));
}
