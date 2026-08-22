import { Router } from 'express';
import { asyncHandler } from '../../common/decorators/async-handler';

export interface HealthDeps {
  /** Optional liveness checks that can fail (e.g. DB ping). */
  readinessChecks?: Record<string, () => Promise<void>>;
}

/**
 * GET /health/live  - process is up (always 200 if reached)
 * GET /health/ready - dependencies reachable
 */
export function createHealthRouter(deps: HealthDeps = {}): Router {
  const router = Router();

  router.get('/live', (_req, res) => {
    res.json({ status: 'ok' });
  });

  router.get(
    '/ready',
    asyncHandler(async (_req, res) => {
      const results: Record<string, string> = {};
      let failed = false;
      for (const [name, check] of Object.entries(deps.readinessChecks ?? {})) {
        try {
          await check();
          results[name] = 'ok';
        } catch {
          results[name] = 'unavailable';
          failed = true;
        }
      }
      res.status(failed ? 503 : 200).json({ status: failed ? 'degraded' : 'ok', dependencies: results });
    }),
  );

  return router;
}
