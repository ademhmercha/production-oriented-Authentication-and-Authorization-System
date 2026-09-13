import { loadConfig } from '../../config';
import { logger } from '../../common/logger';
import { createFrontendApp } from './server';

function main(): void {
  const config = loadConfig();
  const app = createFrontendApp();

  const server = app.listen(config.FRONTEND_PORT, () => {
    logger.info(
      { port: config.FRONTEND_PORT, authBase: config.PUBLIC_AUTH_BASE, apiBase: config.PUBLIC_API_BASE },
      'frontend listening',
    );
  });

  const shutdown = (signal: string) => {
    logger.info({ signal }, 'shutting down');
    server.close(() => process.exit(0));
  };
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

main();