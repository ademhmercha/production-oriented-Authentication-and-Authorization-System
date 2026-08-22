import type { Request } from 'express';

/**
 * Per-request context passed into services for audit logging.
 * Keeps domain logic free of express types.
 */
export interface RequestContext {
  requestId: string;
  ip: string | null;
  userAgent: string | null;
}

export function requestContext(req: Request): RequestContext {
  return {
    requestId: req.requestId,
    ip: req.ip ?? null,
    userAgent: req.header('user-agent') ?? null,
  };
}
