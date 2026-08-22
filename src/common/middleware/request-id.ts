import { randomUUID } from 'node:crypto';
import type { NextFunction, Request, RequestHandler, Response } from 'express';

declare module 'express-serve-static-core' {
  interface Request {
    requestId: string;
  }
}

/**
 * Attaches a correlation ID to every request (from X-Request-ID when trusted,
 * otherwise generated). The ID is echoed back and used in logs + audit events.
 */
export function requestIdMiddleware(headerName = 'x-request-id'): RequestHandler {
  return (req: Request, res: Response, next: NextFunction): void => {
    const incoming = req.header(headerName);
    req.requestId = incoming && /^[A-Za-z0-9\-_.]{8,64}$/.test(incoming) ? incoming : randomUUID();
    res.setHeader('X-Request-ID', req.requestId);
    next();
  };
}
