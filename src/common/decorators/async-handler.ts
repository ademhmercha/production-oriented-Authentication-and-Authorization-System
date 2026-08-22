import type { NextFunction, Request, RequestHandler, Response } from 'express';

/**
 * Wraps async route handlers so rejected promises reach the error middleware.
 * (Express 4 does not catch async rejections on its own.)
 */
export const asyncHandler =
  (fn: (req: Request, res: Response, next: NextFunction) => Promise<unknown>): RequestHandler =>
  (req, res, next) => {
    fn(req, res, next).catch(next);
  };
