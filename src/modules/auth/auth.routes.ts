import { Router } from 'express';
import { UserService } from '../users/user.service';
import { validate } from '../../common/validation/validate';
import { asyncHandler } from '../../common/decorators/async-handler';
import { requestContext } from '../../common/decorators/request-context';
import { registerSchema, verifyEmailSchema } from './auth.schemas';

/**
 * Authentication routes.
 * Handlers stay thin: parse/validate -> call service -> shape response.
 */
export function createAuthRoutes(userService: UserService): Router {
  const router = Router();

  router.post(
    '/register',
    validate({ body: registerSchema }),
    asyncHandler(async (req, res) => {
      const user = await userService.register(req.body, requestContext(req));
      // 201 with public representation; never echoes the password/hash back.
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

  return router;
}
