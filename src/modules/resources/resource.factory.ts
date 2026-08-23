/**
 * Resource API application factory.
 *
 * A zero-trust downstream service: it serves /api/v1 protected data but
 * NEVER sees raw access tokens - only verified identity headers injected
 * by the API gateway, plus a shared-secret proof that traffic traversed
 * the gateway.
 */
import express, { Express } from 'express';
import helmet from 'helmet';
import cors from 'cors';
import { loadConfig } from '../../config';
import { logger } from '../../common/logger';
import { requestIdMiddleware } from '../../common/middleware/request-id';
import '../../common/middleware/request-id'; // Request.id augmentation
import { errorHandler, notFoundHandler } from '../../common/middleware/error-handler';
import { Database } from '../../infrastructure/database/pool';
import { createDocumentsRoutes } from './documents.routes';
import { DocumentRepository } from './document.repository';
import { requireGatewaySecret } from './resource.middlewares';

export interface ResourceApiDeps {
  db: Database;
}

export function createResourceApiApp(deps: ResourceApiDeps): Express {
  const config = loadConfig();
  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', 1);

  app.use(helmet());
  app.use(
    cors({
      origin: config.corsOriginsList,
      credentials: true,
    }),
  );
  app.use(requestIdMiddleware());
  app.use(express.json({ limit: '100kb' }));

  // Proof the request came through the gateway (shared secret).
  app.use(requireGatewaySecret());

  // Liveness + readiness.
  app.get('/health', async (_req, res) => {
    res.json({ status: 'ok', service: 'resource-api' });
  });

  app.use('/api/v1', createDocumentsRoutes(new DocumentRepository(deps.db)));

  app.use(notFoundHandler);
  app.use(errorHandler(logger));
  return app;
}
