import { Router } from 'express';
import { MfaService } from './mfa.service';
import { AuditLogService } from '../audit/audit.service';
import { AuditEventType } from '../audit/audit.types';
import { AuthService } from '../auth/auth.service';
import { JwtService } from '../tokens/jwt.service';
import { authenticate, maybeAuthenticate } from '../../common/guards/authenticate';
import { validate } from '../../common/validation/validate';
import { asyncHandler } from '../../common/decorators/async-handler';
import { requestContext } from '../../common/decorators/request-context';
import {
  mfaEnrollSchema,
  mfaVerifyEnrollSchema,
  mfaLoginVerifySchema,
  mfaDisableSchema,
} from './mfa.schemas';

/**
 * MFA routes.
 *
 * POST /mfa/enroll         (auth) begin TOTP enrollment -> otpauth URL + QR
 * POST /mfa/verify         completes the LOGIN challenge -> tokens;
 *                          (auth) confirms enrollment when called with a code
 * POST /mfa/disable        (auth) disable with valid code
 */
export function createMfaRoutes(
  mfa: MfaService,
  audit: AuditLogService,
  jwtService: JwtService,
  authService: AuthService,
): Router {
  const router = Router();

  router.post(
    '/enroll',
    authenticate(jwtService),
    validate({ body: mfaEnrollSchema }),
    asyncHandler(async (req, res) => {
      const userId = req.user!.sub;
      const email = await mfa.getEmailForUser(userId);
      const enrollment = await mfa.beginEnroll(userId, email);
      await audit.record({
        event_type: AuditEventType.MFA_ENROLL_STARTED,
        user_id: userId,
        ip: req.ip,
        request_id: req.requestId,
      });
      // The secret travels ONLY inside the otpauth URL to the enrolled device.
      res.status(201).json(enrollment);
    }),
  );

  router.post(
    '/verify',
    maybeAuthenticate(jwtService),
    validate({ body: mfaLoginVerifySchema.or(mfaVerifyEnrollSchema) }),
    asyncHandler(async (req, res) => {
      if ('mfa_challenge_id' in req.body) {
        // Login-time challenge completion -> issues the real tokens.
        const result = await authService.completeMfaChallenge(
          req.body.mfa_challenge_id,
          req.body.code,
          requestContext(req),
        );
        res.json({
          access_token: result.access_token,
          token_type: result.token_type,
          expires_in: result.expires_in,
          refresh_token: result.refresh_token,
          scope: result.scope,
          roles: result.roles,
        });
        return;
      }
      // Enrollment confirmation - requires an authenticated user.
      if (!req.user) {
        res.status(401).json({ error: 'AUTH_REQUIRED', message: 'Authentication required' });
        return;
      }
      await mfa.confirmEnroll(req.user.sub, req.body.code);
      await audit.record({
        event_type: AuditEventType.MFA_ENABLED,
        user_id: req.user.sub,
        ip: req.ip,
        request_id: req.requestId,
      });
      res.json({ status: 'mfa_enabled' });
    }),
  );

  router.post(
    '/disable',
    authenticate(jwtService),
    validate({ body: mfaDisableSchema }),
    asyncHandler(async (req, res) => {
      await mfa.disable(req.user!.sub, req.body.code);
      await audit.record({
        event_type: AuditEventType.MFA_DISABLED,
        user_id: req.user!.sub,
        ip: req.ip,
        request_id: req.requestId,
      });
      res.json({ status: 'mfa_disabled' });
    }),
  );

  return router;
}
