import type { NextFunction, Request, RequestHandler, Response } from 'express';
import { AppError } from '../../common/errors';
import type { AuthenticatedUser } from '../../common/guards/authenticate';
import { RemoteTokenVerifier } from './remote-token-verifier';

function bearerToken(req: Request): string | null {
  const header = req.headers.authorization;
  if (!header?.startsWith('Bearer ')) return null;
  const token = header.slice('Bearer '.length).trim();
  return token.length > 0 ? token : null;
}

/**
 * Edge authentication: verifies the bearer token against the auth-server's
 * JWKS and attaches the claims to req.user. Downstream services never see
 * raw tokens - only trusted identity headers injected by the proxy layer.
 */
export function authenticateRemote(verifier: RemoteTokenVerifier): RequestHandler {
  return (req: Request, _res: Response, next: NextFunction): void => {
    const token = bearerToken(req);
    if (!token) {
      next(new AppError(401, 'MISSING_TOKEN', 'Authorization header required'));
      return;
    }
    verifier
      .verify(token)
      .then((payload) => {
        req.user = {
          sub: String(payload.sub),
          scope: typeof payload.scope === 'string' ? payload.scope : '',
          roles: (payload.roles as string[]) ?? [],
          permissions: (payload.permissions as string[]) ?? [],
          sid: payload.sid as string | undefined,
          client_id: payload.client_id as string | undefined,
          jti: String(payload.jti),
        } satisfies AuthenticatedUser;
        next();
      })
      .catch(next);
  };
}

/** Any-of scope check on the verified access token. */
export function requireScopes(...anyOf: string[]): RequestHandler {
  return (req: Request, _res: Response, next: NextFunction): void => {
    const user = req.user as AuthenticatedUser | undefined;
    if (!user) {
      next(new AppError(401, 'MISSING_TOKEN', 'Authentication required'));
      return;
    }
    const granted = new Set(user.scope.split(/\s+/).filter(Boolean));
    if (!anyOf.some((s) => granted.has(s))) {
      next(new AppError(403, 'INSUFFICIENT_SCOPE', `Requires one of scopes: ${anyOf.join(', ')}`));
      return;
    }
    next();
  };
}
