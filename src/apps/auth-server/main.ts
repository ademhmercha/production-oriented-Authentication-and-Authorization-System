/**
 * Authorization Server entrypoint.
 */
import { loadConfig } from '../../config';
import { logger } from '../../common/logger';
import { createAuthServer, finalizeApp } from '../../app.factory';

async function main(): Promise<void> {
  const config = loadConfig();
  const app = createAuthServer();
  finalizeApp(app);

  const server = app.listen(config.PORT, () => {
    logger.info({ port: config.PORT, env: config.NODE_ENV }, 'Authorization server started');
  });

  const shutdown = (): void => {
    logger.info('Shutting down authorization server');
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(1), 10_000).unref();
  };
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
}

main().catch((err) => {
  logger.error({ err }, 'Fatal startup error');
  process.exit(1);
});
