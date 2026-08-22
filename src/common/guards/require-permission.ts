import type { NextFunction, Request, RequestHandler, Response } from 'express';
import { ForbiddenError } from '../errors';
import { AuthenticatedUser } from './authenticate';

/**
 * Permission guard factory: @RequirePermission equivalent for Express.
 * Usage: router.get('/users', authenticate(jwt), requirePermission('users:read'), handler)
 *
 * Authorization model: permissions come from RBAC via roles and are embedded
 * in the access token at issuance; the gateway/resource APIs re-check scopes.
 */
export function requirePermission(...permissions: string[]): RequestHandler {
  return (req: Request, _res: Response, next: NextFunction): void => {
    const user = req.user as AuthenticatedUser | undefined;
    if (!user) {
      next(new ForbiddenError('Authentication required'));
      return;
    }
    const granted = new Set<string>([...(user.permissions ?? []), ...tokenPermissions(user)]);
    const ok = permissions.every((p) => granted.has(p));
    if (!ok) {
      next(new ForbiddenError(`Missing required permission(s): ${permissions.join(', ')}`, 'MISSING_PERMISSION'));
      return;
    }
    next();
  };
}

/**
 * Token convention: scope entries like `users:read` double as permissions
 * when issued from user context. OAuth-only tokens carry plain scopes, so a
 * permission check on those fails unless the client was granted them.
 */
function tokenPermissions(user: AuthenticatedUser): string[] {
  return (user.scope ?? '').split(/\s+/).filter(Boolean);
}

/** Scope guard for resource servers: any-of semantics. */
export function requireScope(...scopes: string[]): RequestHandler {
  return (req: Request, _res: Response, next: NextFunction): void => {
    const user = req.user as AuthenticatedUser | undefined;
    if (!user) {
      next(new ForbiddenError('Authentication required'));
      return;
    }
    const tokenScopes = new Set(tokenPermissions(user));
    if (!scopes.some((s) => tokenScopes.has(s))) {
      next(
        new ForbiddenError(
          `Missing required scope(s): ${scopes.join(', ')}`,
          'INSUFFICIENT_SCOPE',
        ),
      );
      return;
    }
    next();
  };
}
