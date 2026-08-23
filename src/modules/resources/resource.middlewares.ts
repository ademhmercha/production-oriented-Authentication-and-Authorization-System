import type { NextFunction, Request, RequestHandler, Response } from 'express';
import { AppError } from '../../common/errors';
import { loadConfig } from '../../config';

declare module 'express-serve-static-core' {
  interface Request {
    identity?: ResourceIdentity;
  }
}

/**
 * Zero-trust edge contract: the resource API never validates tokens itself.
 * It trusts ONLY requests from the gateway, proven two ways:
 *  1. shared secret header (GATEWAY_SHARED_SECRET) injected by the proxy
 *  2. verified identity headers (X-User-Id / X-Client-Id + scopes/roles)
 *
 * In production this is complemented by network isolation (private subnet)
 * and/or mTLS between services.
 */
export interface ResourceIdentity {
  userId?: string;
  clientId?: string;
  scopes: string[];
  roles: string[];
  requestId?: string;
}

export function requireGatewaySecret(): RequestHandler {
  const secret = loadConfig().GATEWAY_SHARED_SECRET;
  return (req: Request, _res: Response, next: NextFunction): void => {
    if (!secret) return next(); // not configured (local dev without hardening)
    if (req.headers['x-internal-secret'] !== secret) {
      next(new AppError(403, 'FORBIDDEN_ORIGIN', 'Direct access to resource API is not allowed'));
      return;
    }
    next();
  };
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Parses (and requires) the identity the gateway injected. */
export function requireIdentity(): RequestHandler {
  return (req: Request, _res: Response, next: NextFunction): void => {
    const rawUserId = asString(req.headers['x-user-id']);
    const clientId = asString(req.headers['x-client-id']);
    // Service tokens (client_credentials) carry sub=<client_id>, not a uuid.
    const userId = rawUserId && UUID_RE.test(rawUserId) ? rawUserId : undefined;
    if (!userId && !clientId) {
      next(new AppError(401, 'NO_IDENTITY', 'Request must traverse the gateway'));
      return;
    }
    req.identity = {
      userId,
      clientId,
      scopes: splitCsvOrSpace(asString(req.headers['x-user-scopes'])),
      roles: splitCsvOrSpace(asString(req.headers['x-user-roles'])),
      requestId: asString(req.headers['x-request-id']),
    } satisfies ResourceIdentity;
    next();
  };
}

/** Any-of scope check against the gateway-provided scope list. */
export function requireResourceScope(...anyOf: string[]): RequestHandler {
  return (req: Request, _res: Response, next: NextFunction): void => {
    const identity = req.identity as ResourceIdentity | undefined;
    if (!identity) {
      next(new AppError(401, 'NO_IDENTITY', 'Request must traverse the gateway'));
      return;
    }
    if (!anyOf.some((s) => identity.scopes.includes(s))) {
      next(new AppError(403, 'INSUFFICIENT_SCOPE', `Requires one of scopes: ${anyOf.join(', ')}`));
      return;
    }
    next();
  };
}

function asString(value: unknown): string | undefined {
  const v = Array.isArray(value) ? value[0] : value;
  return typeof v === 'string' && v.length > 0 ? v : undefined;
}

function splitCsvOrSpace(value: string | undefined): string[] {
  if (!value) return [];
  return value.split(/[\s,]+/).filter(Boolean);
}
