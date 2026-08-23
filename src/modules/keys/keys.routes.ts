import { Router } from 'express';
import { exportJWK, importSPKI } from 'jose';
import { KeyManagementService } from './kms.types';
import { asyncHandler } from '../../common/decorators/async-handler';

/**
 * GET /.well-known/jwks.json
 *
 * Publishes all *public* signing keys (never private material) so the API
 * Gateway and resource servers can verify JWTs without sharing secrets.
 */
export function createKeysRoutes(kms: KeyManagementService): Router {
  const router = Router();

  router.get(
    '/.well-known/jwks.json',
    asyncHandler(async (_req, res) => {
      const publicKeys = await kms.listPublicKeys();
      const keys = await Promise.all(
        publicKeys.map(async (k) => {
          const spki = await importSPKI(k.publicKeyPem, 'EdDSA');
          const jwk = await exportJWK(spki);
          return { ...jwk, kid: k.kid, alg: 'EdDSA', use: 'sig' };
        }),
      );
      res.setHeader('Cache-Control', 'public, max-age=300');
      res.json({ keys });
    }),
  );

  return router;
}
