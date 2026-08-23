/**
 * API Gateway application factory.
 *
 * The gateway is the single entry point for client traffic:
 *  - verifies access tokens against the auth-server's published JWKS
 *    (no shared signing secrets - asymmetric trust only)
 *  - consults the shared Redis jti denylist so revocation is effective
 *    at the edge immediately (client_credentials tokens included)
 *  - enforces scope-based authorization per route group
 *  - strips spoofable identity headers, then injects verified identity
 *    headers for downstream services
 *  - proxies /api/v1/** to the resource API
 */
import express, { Express } from 'express';
import helmet from 'helmet';
import cors from 'cors';
import { createProxyMiddleware, fixRequestBody } from 'http-proxy-middleware';
import type { Request } from 'express';
import '../../common/middleware/request-id';
import { loadConfig } from '../../config';
import { logger } from '../../common/logger';
import { requestIdMiddleware } from '../../common/middleware/request-id';
import { errorHandler, notFoundHandler } from '../../common/middleware/error-handler';
import { RedisService } from '../../infrastructure/redis/redis.service';
import { rateLimitMiddleware } from '../rate-limit/rate-limit.middleware';
import { TokenRevocationService } from '../tokens/token-revocation';
import { RemoteTokenVerifier } from './remote-token-verifier';
import { authenticateRemote, requireScopes } from './gateway.middlewares';

export interface GatewayDeps {
  redis: RedisService;
}

/** Headers a downstream service may trust - clients must never set these. */
const PROTECTED_HEADERS = [
  'x-user-id',
  'x-user-scopes',
  'x-user-roles',
  'x-client-id',
  'x-token-sid',
] as const;

export function createGatewayApp(deps: GatewayDeps): Express {
  const config = loadConfig();
  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', 1);

  app.use(helmet());
  app.use(
    cors({
      origin: config.corsOriginsList,
      credentials: true,
      methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    }),
  );
  app.use(requestIdMiddleware());

  // Coarse IP-based rate limit before any auth work happens.
  app.use(
    rateLimitMiddleware(deps.redis, {
      bucket: 'gw',
      limit: config.RATE_LIMIT_API,
      windowSeconds: config.RATE_LIMIT_WINDOW,
    }),
  );

  // Liveness for orchestrators; no dependency checks (readiness lives in services).
  app.get('/healthz', (_req, res) => {
    res.json({ status: 'ok', service: 'api-gateway' });
  });

  // Shared denylist: revoking a token at the auth-server kills it here too.
  const verifier = new RemoteTokenVerifier({
    jwksUrl: `${config.AUTH_SERVER_URL}/.well-known/jwks.json`,
    issuer: config.JWT_ISSUER,
    audience: config.JWT_AUDIENCE,
  });
  const revocation = new TokenRevocationService(deps.redis);
  verifier.setRevocationChecker((jti) => revocation.isRevoked(jti));

  // Drop inbound identity headers before anything else can see them.
  app.use((req, _res, next) => {
    for (const h of PROTECTED_HEADERS) delete req.headers[h];
    next();
  });

  const authenticate = authenticateRemote(verifier);
  const authorizeRead = requireScopes('api.read');

  const proxy = createProxyMiddleware({
    target: config.RESOURCE_API_URL,
    changeOrigin: false,
    xfwd: true,
    on: {
      proxyReq: (proxyReq, req) => {
        const creq = req as Request & {
          id?: string;
          originalUrl?: string;
          user?: { sub: string; scope: string; roles?: string[]; sid?: string; client_id?: string };
        };
        // Express strips the mount path from req.url; forward the original.
        if (creq.originalUrl) proxyReq.path = creq.originalUrl;
        if (creq.user) {
          proxyReq.setHeader('X-User-Id', creq.user.sub);
          proxyReq.setHeader('X-User-Scopes', creq.user.scope);
          proxyReq.setHeader('X-User-Roles', (creq.user.roles ?? []).join(','));
          if (creq.user.sid) proxyReq.setHeader('X-Token-Sid', creq.user.sid);
          if (creq.user.client_id) proxyReq.setHeader('X-Client-Id', creq.user.client_id);
        }
        if (creq.id) proxyReq.setHeader('X-Request-Id', String(creq.id));
        fixRequestBody(proxyReq, req);
      },
      error: (err, _req, res) => {
        logger.error({ err, msg: 'Proxy target unreachable' });
        if ('writeHead' in res && typeof res.writeHead === 'function') {
          res.writeHead(502, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'BAD_GATEWAY', message: 'Upstream service unavailable' }));
        }
      },
    },
  });

  // Protected resource traffic.
  app.use('/api/v1', authenticate, authorizeRead, proxy);

  // Unknown routes + central error formatting (same envelope as services).
  app.use(notFoundHandler);
  app.use(errorHandler(logger));
  return app;
}
