import { Router } from 'express';
import { AuthService } from './auth.service';
import { UserService } from '../users/user.service';
import { JwtService } from '../tokens/jwt.service';
import { authenticate } from '../../common/guards/authenticate';
import { validate } from '../../common/validation/validate';
import { asyncHandler } from '../../common/decorators/async-handler';
import { requestContext } from '../../common/decorators/request-context';
import { rateLimitMiddleware } from '../rate-limit/rate-limit.middleware';
import { RedisService } from '../../infrastructure/redis/redis.service';
import { loadConfig } from '../../config';
import {
  loginSchema,
  refreshSchema,
  logoutSchema,
  verifyEmailSchema,
  forgotPasswordSchema,
  resetPasswordSchema,
  registerSchema,
} from './auth.schemas';

/**
 * Authentication routes.
 * Handlers stay thin: parse/validate -> call service -> shape response.
 * Each sensitive endpoint gets its own Redis-backed rate-limit bucket.
 */
export function createAuthRoutes(
  authService: AuthService,
  userService: UserService,
  jwtService: JwtService,
  redis: RedisService,
): Router {
  const config = loadConfig();
  const router = Router();

  const limit = (bucket: string, n: number) =>
    rateLimitMiddleware(redis, {
      bucket,
      limit: n,
      windowSeconds: config.RATE_LIMIT_WINDOW,
    });

  router.post(
    '/register',
    validate({ body: registerSchema }),
    limit('register', config.RATE_LIMIT_REGISTER),
    asyncHandler(async (req, res) => {
      const user = await userService.register(req.body, requestContext(req));
      res.status(201).json({ user });
    }),
  );

  router.post(
    '/verify-email',
    validate({ body: verifyEmailSchema }),
    asyncHandler(async (req, res) => {
      await userService.verifyEmail(req.body.token, requestContext(req));
      res.json({ status: 'verified' });
    }),
  );

  router.post(
    '/login',
    validate({ body: loginSchema }),
    limit('login', config.RATE_LIMIT_LOGIN),
    asyncHandler(async (req, res) => {
      const result = await authService.login(req.body, requestContext(req));
      if (result.outcome === 'mfa_required') {
        res.status(200).json(result);
        return;
      }
      res.status(200).json({
        access_token: result.access_token,
        token_type: result.token_type,
        expires_in: result.expires_in,
        refresh_token: result.refresh_token,
        refresh_expires_at: result.refresh_expires_at,
        scope: result.scope,
        roles: result.roles,
        user: result.user,
      });
    }),
  );

  router.post(
    '/refresh',
    validate({ body: refreshSchema }),
    limit('token', config.RATE_LIMIT_TOKEN),
    asyncHandler(async (req, res) => {
      const result = await authService.refresh(req.body.refresh_token, requestContext(req));
      res.json({
        access_token: result.access_token,
        token_type: result.token_type,
        expires_in: result.expires_in,
        refresh_token: result.refresh_token,
        scope: result.scope,
      });
    }),
  );

  router.post(
    '/logout',
    authenticate(jwtService),
    validate({ body: logoutSchema }),
    asyncHandler(async (req, res) => {
      const result = await authService.logout(
        req.user!.sub,
        req.user!.sid,
        req.body.all_sessions === true,
        req.body.refresh_token,
        requestContext(req),
      );
      res.json({ status: 'logged_out', ...result });
    }),
  );

  router.post(
    '/forgot-password',
    validate({ body: forgotPasswordSchema }),
    limit('forgot-password', config.RATE_LIMIT_FORGOT_PASSWORD),
    asyncHandler(async (req, res) => {
      // Always the same response - prevents account enumeration.
      await authService.forgotPassword(req.body.email, requestContext(req));
      res.status(202).json({ status: 'accepted' });
    }),
  );

  router.post(
    '/reset-password',
    validate({ body: resetPasswordSchema }),
    asyncHandler(async (req, res) => {
      await authService.resetPassword(req.body.token, req.body.password, requestContext(req));
      res.json({ status: 'password_reset' });
    }),
  );

  router.get(
    '/me',
    authenticate(jwtService),
    asyncHandler(async (req, res) => {
      const profile = await authService.me(req.user!.sub);
      res.json(profile);
    }),
  );

  return router;
}
