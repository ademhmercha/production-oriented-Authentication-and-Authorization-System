/**
 * Frontend application factory.
 *
 * Serves the browser SPA (vanilla TypeScript, no bundler) plus:
 *  - GET /healthz   - liveness probe for orchestrators (compose / Helm)
 *  - GET /config.js - runtime configuration injected into the page
 *
 * The SPA itself talks to the platform backends (auth-server and api-gateway)
 * using the base URLs advertised in /config.js. When PUBLIC_AUTH_BASE and
 * PUBLIC_API_BASE are empty the browser uses the same origin, which relies on
 * the network layer (Ingress / nginx) routing /auth, /mfa and /api to the
 * correct backend.
 *
 * Kept as a pure factory so tests can boot the app without listening.
 */
import express, { Express, Response } from 'express';
import helmet from 'helmet';
import { join } from 'node:path';
import { loadConfig } from '../../config';
import { notFoundHandler, errorHandler } from '../../common/middleware/error-handler';
import { logger } from '../../common/logger';

function resolveStaticRoot(): string {
  // __dirname points at src/apps/frontend under tsx and dist/apps/frontend
  // after compilation - the static dir is a sibling in both cases.
  return join(__dirname, 'static');
}

function noStore(res: Response): void {
  res.setHeader('Cache-Control', 'no-store');
}

export function createFrontendApp(): Express {
  const config = loadConfig();
  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', 1);

  // The SPA is served over plain HTTP in the local/dev setup (identity.local via
  // ingress, no edge TLS). helmet's defaults are HTTPS-oriented and their
  // `upgrade-insecure-requests` + HSTS headers make browsers force every
  // subresource to https://identity.local, which has no trusted cert and breaks
  // the page with ERR_CERT_AUTHORITY_INVALID. Disable both headers here; when a
  // TLS-terminating Ingress is configured (ingress.tls.enabled), the edge adds
  // its own HSTS. Keep the rest of the CSP defaults.
  app.use(
    helmet({
      crossOriginResourcePolicy: { policy: 'same-site' },
      hsts: false,
      contentSecurityPolicy: {
        directives: {
          'upgrade-insecure-requests': null,
        },
      },
    }),
  );
  app.disable('etag');

  const staticRoot = resolveStaticRoot();

  app.get('/healthz', (_req, res) => {
    res.json({ status: 'ok', service: 'frontend' });
  });

  // Browser-safe runtime config. The values come from validated env config, so
  // no injection surface here; we still JSON-stringify them.
  app.get('/config.js', (_req, res) => {
    res
      .type('application/javascript')
      .set('Cache-Control', 'no-store')
      .send(
        [
          'window.__APP_CONFIG__ = {',
          `  authBase: ${JSON.stringify(config.PUBLIC_AUTH_BASE)},`,
          `  apiBase: ${JSON.stringify(config.PUBLIC_API_BASE)},`,
          `  version: ${JSON.stringify(process.env.npm_package_version ?? 'dev')},`,
          '};',
        ].join('\n'),
      );
  });

  // Versioned build assets (compiled app/*.js) can be cached immutably.
  app.use(
    '/app',
    express.static(join(staticRoot, 'app'), {
      immutable: true,
      maxAge: '1y',
      index: false,
    }),
  );

  // HTML, CSS and anything else static - never cached across deployments.
  app.use(express.static(staticRoot, { index: 'index.html', setHeaders: noStore }));

  // SPA fallback: any unmatched GET serves the shell so deep links work.
  app.use((req, res, next) => {
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      next();
      return;
    }
    res.sendFile(join(staticRoot, 'index.html'), (err) => {
      if (err) next(err);
    });
  });

  app.use(notFoundHandler);
  app.use(errorHandler(logger));
  return app;
}