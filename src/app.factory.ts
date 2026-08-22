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
import { KeyManagementService } from './modules/keys/kms.types';
import { createKeysRoutes } from './modules/keys/keys.routes';

export interface AuthServerDeps {
  kms: KeyManagementService;
  readinessChecks?: Record<string, () => Promise<void>>;
}

export function createAuthServer(deps: AuthServerDeps): Express {
  const config = loadConfig();

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
  app.use(createKeysRoutes(deps.kms));

  app.use('/health', createHealthRouter({ readinessChecks: deps.readinessChecks }));

  return app;
}

/** Finalizes the app: 404 + central error handling must be registered last. */
export function finalizeApp(app: Express): void {
  app.use(notFoundHandler);
  app.use(errorHandler(logger));
}
