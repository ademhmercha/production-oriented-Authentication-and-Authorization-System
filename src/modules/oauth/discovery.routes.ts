import { Router } from 'express';
import { loadConfig } from '../../config';
import { asyncHandler } from '../../common/decorators/async-handler';

/**
 * OIDC Discovery (OpenID Connect Discovery 1.0).
 * Lets relying parties auto-configure issuer, endpoints, scopes and key material.
 */
export function createDiscoveryRoutes(): Router {
  const router = Router();
  const config = loadConfig();
  const issuer = config.JWT_ISSUER.replace(/\/$/, '');

  router.get(
    '/.well-known/openid-configuration',
    asyncHandler(async (_req, res) => {
      res.setHeader('Cache-Control', 'public, max-age=300');
      res.json({
        issuer,
        authorization_endpoint: `${issuer}/oauth/authorize`,
        token_endpoint: `${issuer}/oauth/token`,
        userinfo_endpoint: `${issuer}/userinfo`,
        jwks_uri: `${issuer}/.well-known/jwks.json`,
        introspection_endpoint: `${issuer}/oauth/introspect`,
        revocation_endpoint: `${issuer}/oauth/revoke`,
        response_types_supported: ['code'],
        grant_types_supported: ['authorization_code', 'client_credentials', 'refresh_token'],
        subject_types_supported: ['public'],
        id_token_signing_alg_values_supported: ['EdDSA'],
        scopes_supported: ['openid', 'profile', 'email', 'offline_access', 'api.read', 'api.write'],
        token_endpoint_auth_methods_supported: [
          'client_secret_basic',
          'client_secret_post',
          'none',
        ],
        code_challenge_methods_supported: ['S256'],
        claims_supported: ['sub', 'iss', 'aud', 'exp', 'iat', 'email', 'given_name', 'family_name'],
      });
    }),
  );

  return router;
}
