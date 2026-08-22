import { NextFunction, Request, Response } from 'express';
import { z } from 'zod';
import { ValidationError } from '../errors';

/**
 * Validates and parses the request with a zod schema.
 *
 * Which parts of the request to parse is configurable; by default body only.
 * Parsed (and coerced/stripped) values replace the original request fields,
 * so handlers work with validated data only.
 */
export function validate<TBody extends z.ZodTypeAny = z.ZodUndefined>(opts: {
  body?: TBody;
  query?: z.ZodTypeAny;
  params?: z.ZodTypeAny;
}) {
  return (req: Request, _res: Response, next: NextFunction): void => {
    try {
      if (opts.body) {
        const result = opts.body.safeParse(req.body);
        if (!result.success) throw validationError(result.error);
        req.body = result.data;
      }
      if (opts.query) {
        const result = opts.query.safeParse(req.query);
        if (!result.success) throw validationError(result.error);
        // Express 5 makes this readonly; keep compatible assignment for Express 4 typings.
        Object.assign(req.query, result.data as Record<string, unknown>);
      }
      if (opts.params) {
        const result = opts.params.safeParse(req.params);
        if (!result.success) throw validationError(result.error);
        Object.assign(req.params, result.data as Record<string, unknown>);
      }
      next();
    } catch (err) {
      next(err);
    }
  };
}

function validationError(error: z.ZodError): ValidationError {
  const details: Record<string, string> = {};
  for (const issue of error.issues) {
    const key = issue.path.join('.') || '_root';
    if (!details[key]) details[key] = issue.message;
  }
  return new ValidationError('Validation failed', details);
}
