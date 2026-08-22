import type { NextFunction, Request, RequestHandler, Response } from 'express';
import { JwtService } from '../../modules/tokens/jwt.service';
import { AuthError } from '../errors';

export interface AuthenticatedUser {
  sub: string;
  scope: string;
  roles?: string[];
  permissions?: string[];
  sid?: string;
  client_id?: string;
  jti: string;
}

declare module 'express-serve-static-core' {
  interface Request {
    user?: AuthenticatedUser;
    auth?: AuthenticatedUser;
  }
}

/**
 * Bearer-JWT authentication middleware.
 * Verifies signature/iss/aud/exp/nbf through the shared JwtService.
 */
export function authenticate(jwtService: JwtService): RequestHandler {
  return async (req: Request, _res: Response, next: NextFunction): Promise<void> => {
    try {
      const header = req.header('authorization');
      if (!header?.startsWith('Bearer ')) {
        throw new AuthError();
      }
      const payload = await jwtService.verifyAccessToken(header.slice(7));
      req.user = {
        sub: payload.sub,
        scope: payload.scope ?? '',
        roles: payload.roles,
        permissions: payload.permissions,
        sid: payload.sid,
        client_id: payload.client_id,
        jti: payload.jti ?? '',
      };
      next();
    } catch (err) {
      next(err);
    }
  };
}

/** Optional variant: attaches identity when a token is present, never rejects. */
export function maybeAuthenticate(jwtService: JwtService): RequestHandler {
  return (req: Request, res: Response, next: NextFunction): void => {
    const header = req.header('authorization');
    if (!header?.startsWith('Bearer ')) return next();
    authenticate(jwtService)(req, res, next);
  };
}
