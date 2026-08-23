import { Router } from 'express';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { parse } from 'yaml';
import swaggerUi from 'swagger-ui-express';

/**
 * Interactive API documentation.
 * - /docs          Swagger UI (try-it-out)
 * - /openapi.json  Machine-readable spec
 */
export function createDocsRoutes(): Router {
  const router = Router();
  const specPath = join(process.cwd(), 'docs', 'openapi.yaml');
  const spec = parse(readFileSync(specPath, 'utf8')) as object;

  router.get('/openapi.json', (_req, res) => {
    res.json(spec);
  });
  router.use('/docs', swaggerUi.serve, swaggerUi.setup(spec, { customSiteTitle: 'Identity Platform API' }));
  return router;
}
