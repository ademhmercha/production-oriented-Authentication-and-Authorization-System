/**
 * Authorization Server entrypoint.
 */
import { loadConfig } from '../../config';
import { logger } from '../../common/logger';
import { createAuthServer, finalizeApp } from '../../app.factory';
import { LocalKeyProvider } from '../../modules/keys/local-key-provider';

async function main(): Promise<void> {
  const config = loadConfig();

  const kms = new LocalKeyProvider(config.KMS_KEY_DIR);
  // Ensure a signing key exists at startup.
  const signing = await kms.getCurrentSigningKey();
  logger.info({ kid: signing.kid }, 'Signing key loaded');

  const app = createAuthServer({
    kms,
    readinessChecks: {
      kms: async () => {
        await kms.getCurrentSigningKey();
      },
    },
  });
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
