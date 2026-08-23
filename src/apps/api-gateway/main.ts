/**
 * API Gateway entrypoint.
 */
import { loadConfig } from '../../config';
import { logger } from '../../common/logger';
import { RedisService } from '../../infrastructure/redis/redis.service';
import { createGatewayApp } from '../../modules/gateway/gateway.factory';

function main(): void {
  const config = loadConfig();
  const redis = new RedisService();
  const app = createGatewayApp({ redis });

  const server = app.listen(config.GATEWAY_PORT, () => {
    logger.info(
      {
        port: config.GATEWAY_PORT,
        authServer: config.AUTH_SERVER_URL,
        resourceApi: config.RESOURCE_API_URL,
      },
      'api-gateway listening',
    );
  });

  const shutdown = (signal: string) => {
    logger.info({ signal }, 'shutting down');
    server.close(() => {
      redis.close().finally(() => process.exit(0));
    });
  };
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

main();
