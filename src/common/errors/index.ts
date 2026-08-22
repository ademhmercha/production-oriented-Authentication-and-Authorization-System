/**
 * Application error hierarchy.
 *
 * Handlers/services throw these; the central error middleware maps them
 * to safe HTTP responses. Internal details are never leaked to clients
 * (secure error messages requirement).
 */

export class AppError extends Error {
  readonly statusCode: number;
  readonly code: string;
  /** Extra machine-readable details (safe to expose). */
  readonly details?: Record<string, unknown>;

  constructor(statusCode: number, code: string, message: string, details?: Record<string, unknown>) {
    super(message);
    this.name = new.target.name;
    this.statusCode = statusCode;
    this.code = code;
    this.details = details;
    Error.captureStackTrace?.(this, new.target);
  }
}

export class ValidationError extends AppError {
  constructor(message = 'Validation failed', details?: Record<string, unknown>) {
    super(400, 'VALIDATION_ERROR', message, details);
  }
}

export class AuthError extends AppError {
  constructor(message = 'Authentication required', code = 'AUTH_REQUIRED') {
    super(401, code, message);
  }
}

export class InvalidCredentialsError extends AuthError {
  constructor() {
    // Deliberately generic - do not reveal whether email or password was wrong.
    super('Invalid credentials', 'INVALID_CREDENTIALS');
  }
}

export class ForbiddenError extends AppError {
  constructor(message = 'Insufficient permissions', code = 'FORBIDDEN') {
    super(403, code, message);
  }
}

export class NotFoundError extends AppError {
  constructor(resource = 'Resource') {
    super(404, 'NOT_FOUND', `${resource} not found`);
  }
}

export class ConflictError extends AppError {
  constructor(message = 'Conflict') {
    super(409, 'CONFLICT', message);
  }
}

export class TooManyRequestsError extends AppError {
  constructor(retryAfterSeconds: number) {
    super(429, 'RATE_LIMITED', 'Too many requests', { retryAfterSeconds });
  }
}

export class UnauthorizedClientError extends AppError {
  constructor(message = 'Unauthorized client') {
    super(401, 'UNAUTHORIZED_CLIENT', message);
  }
}
