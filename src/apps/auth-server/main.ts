/**
 * Authorization Server entrypoint.
 */
import { loadConfig } from '../../config';
import { logger } from '../../common/logger';
import { createAuthServer, finalizeApp } from '../../app.factory';
import { LocalKeyProvider } from '../../modules/keys/local-key-provider';
import { Database } from '../../infrastructure/database/pool';
import { RedisService } from '../../infrastructure/redis/redis.service';
import { getEmailProvider } from '../../modules/email/email.factory';

async function main(): Promise<void> {
  const config = loadConfig();

  const db = new Database();
  const redis = new RedisService();
  const kms = new LocalKeyProvider(config.KMS_KEY_DIR);
  const email = getEmailProvider();

  // Ensure a signing key exists at startup.
  const signing = await kms.getCurrentSigningKey();
  logger.info({ kid: signing.kid }, 'Signing key loaded');

  const app = createAuthServer({ db, redis, kms, email });
  finalizeApp(app);

  const server = app.listen(config.PORT, () => {
    logger.info(
      { port: config.PORT, env: config.NODE_ENV, emailProvider: config.EMAIL_PROVIDER },
      'Authorization server started',
    );
  });

  const shutdown = async (): Promise<void> => {
    logger.info('Shutting down authorization server');
    server.close(() => undefined);
    await Promise.allSettled([db.close(), redis.close()]);
    process.exit(0);
  };
  process.on('SIGTERM', () => void shutdown());
  process.on('SIGINT', () => void shutdown());
}

main().catch((err) => {
  logger.error({ err }, 'Fatal startup error');
  process.exit(1);
});
