import type { NextFunction, Request, Response } from 'express';
import { AppError } from '../errors';

/**
 * Central error handler. Maps known errors to safe JSON responses; internal
 * errors are logged server-side and returned as a generic 500 so stack
 * traces and messages never leak to clients.
 */
export function errorHandler(logger: { error: (obj: unknown, msg?: string) => void }) {
  return (err: unknown, req: Request, res: Response, _next: NextFunction): void => {
    if (err instanceof AppError) {
      if (err.statusCode >= 500) {
        logger.error({ err, requestId: req.requestId }, err.message);
      }
      res.status(err.statusCode).json({
        error: err.code,
        message: err.message,
        ...(err.details ? { details: err.details } : {}),
        request_id: req.requestId,
      });
      return;
    }

    // Body-parser / JSON syntax errors etc.
    const anyErr = err as { statusCode?: number; type?: string; message?: string };
    if (anyErr?.statusCode && anyErr.statusCode < 500) {
      res.status(anyErr.statusCode).json({
        error: 'BAD_REQUEST',
        message: 'Malformed request',
        request_id: req.requestId,
      });
      return;
    }

    logger.error(
      { err, requestId: req.requestId, path: req.path },
      'Unhandled error',
    );
    res.status(500).json({
      error: 'INTERNAL_ERROR',
      message: 'An internal error occurred',
      request_id: req.requestId,
    });
  };
}

export function notFoundHandler(_req: Request, res: Response): void {
  res.status(404).json({ error: 'NOT_FOUND', message: 'Route not found' });
}
