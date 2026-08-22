import { Router } from 'express';
import { authenticate } from '../../common/guards/authenticate';
import { asyncHandler } from '../../common/decorators/async-handler';
import { UserRepository } from '../users/user.repository';
import { JwtService } from '../tokens/jwt.service';

/**
 * OIDC UserInfo (OpenID Connect Core §5.3).
 *
 * Requires a valid access token with the `openid` scope; returns sub plus
 * only the claims matching granted scopes (email, profile).
 */
export function createOidcRoutes(users: UserRepository, jwtService: JwtService): Router {
  const router = Router();
  const auth = authenticate(jwtService);

  router.get(
    '/userinfo',
    auth,
    asyncHandler(async (req, res) => {
      const user = req.user!;
      if (!user.scope.split(/\s+/).includes('openid')) {
        res.status(403).json({
          error: 'insufficient_scope',
          error_description: 'openid scope required',
        });
        return;
      }
      const row = await users.findById(user.sub);
      if (!row) {
        res.status(404).json({ error: 'not_found' });
        return;
      }
      const claims: Record<string, unknown> = { sub: row.id };
      const scopes = new Set(user.scope.split(/\s+/));
      if (scopes.has('email')) {
        claims.email = row.email;
        claims.email_verified = row.status === 'active';
      }
      if (scopes.has('profile')) {
        claims.given_name = row.first_name ?? undefined;
        claims.family_name = row.last_name ?? undefined;
        claims.preferred_username = row.email.split('@')[0]!;
      }
      res.json(claims);
    }),
  );

  return router;
}
