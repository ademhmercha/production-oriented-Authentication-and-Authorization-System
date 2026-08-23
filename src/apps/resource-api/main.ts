/**
 * Resource API entrypoint.
 */
import { loadConfig } from '../../config';
import { logger } from '../../common/logger';
import { Database } from '../../infrastructure/database/pool';
import { createResourceApiApp } from '../../modules/resources/resource.factory';

async function main(): Promise<void> {
  const config = loadConfig();
  const db = new Database();
  const app = createResourceApiApp({ db });

  const server = app.listen(config.RESOURCE_PORT, () => {
    logger.info({ port: config.RESOURCE_PORT }, 'resource-api listening');
  });

  const shutdown = (signal: string) => {
    logger.info({ signal }, 'shutting down');
    server.close(() => {
      db.close().finally(() => process.exit(0));
    });
  };
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

void main();
