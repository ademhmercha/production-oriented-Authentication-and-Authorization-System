import { Router, raw } from 'express';
import { OAuthService } from './oauth.service';
import { JwtService } from '../tokens/jwt.service';
import { ClientRepository } from '../clients/client.repository';
import { AuditLogService } from '../audit/audit.service';
import { maybeAuthenticate } from '../../common/guards/authenticate';
import { AppError } from '../../common/errors';
import { validate } from '../../common/validation/validate';
import { asyncHandler } from '../../common/decorators/async-handler';
import { requestContext } from '../../common/decorators/request-context';
import { rateLimitMiddleware } from '../rate-limit/rate-limit.middleware';
import { RedisService } from '../../infrastructure/redis/redis.service';
import { loadConfig } from '../../config';
import {
  authorizeQuerySchema,
  tokenFormSchema,
  introspectFormSchema,
  revokeFormSchema,
} from './oauth.schemas';
import type { Request } from 'express';

/**
 * OAuth 2.0 endpoints.
 *
 * GET  /oauth/authorize   (auth optional -> login_required) issues codes
 * POST /oauth/token       form-encoded; basic or post client auth
 * POST /oauth/introspect  RFC 7662 (client-authenticated)
 * POST /oauth/revoke      RFC 7009
 */
export function createOAuthRoutes(
  oauth: OAuthService,
  jwt: JwtService,
  clients: ClientRepository,
  audit: AuditLogService,
  redis: RedisService,
): Router {
  const config = loadConfig();
  const router = Router();

  // Token endpoint requires exact body parsing - keep raw for basic auth.
  router.use('/token', raw({ type: 'application/octet-stream', limit: '64kb' }));

  router.get(
    '/authorize',
    rateLimitMiddleware(redis, { bucket: 'authorize', limit: config.RATE_LIMIT_AUTHORIZE,
      windowSeconds: config.RATE_LIMIT_WINDOW }),
    maybeAuthenticate(jwt),
    validate({ query: authorizeQuerySchema }),
    asyncHandler(async (req, res) => {
      const q = req.query as unknown as {
        response_type: 'code';
        client_id: string;
        redirect_uri: string;
        scope: string;
        state?: string;
        nonce?: string;
        code_challenge?: string;
        code_challenge_method: 'S256' | 'plain';
      };
      if (q.response_type !== 'code' || !q.code_challenge) {
        res.status(400).json({
          error: 'invalid_request',
          error_description: 'response_type=code and PKCE code_challenge are required',
        });
        return;
      }
      const result = await oauth.authorize(
        {
          client_id: q.client_id,
          redirect_uri: q.redirect_uri,
          scope: q.scope,
          nonce: q.nonce,
          code_challenge: q.code_challenge,
          code_challenge_method: q.code_challenge_method,
        },
        req.user?.sub,
        q.state,
        requestContext(req),
      );
      res.json({
        code_url: result.redirect,
        ...(q.state ? { state: q.state } : {}),
      });
    }),
  );

  function parseBasicAuth(req: Request): { clientId: string; clientSecret: string } | null {
    const header = req.header('authorization');
    if (!header?.startsWith('Basic ')) return null;
    try {
      const decoded = Buffer.from(header.slice(6), 'base64').toString('utf8');
      const idx = decoded.indexOf(':');
      if (idx <= 0) return null;
      return {
        clientId: decodeURIComponent(decoded.slice(0, idx)),
        clientSecret: decodeURIComponent(decoded.slice(idx + 1)),
      };
    } catch {
      return null;
    }
  }

  function parseFormBody(req: Request): Record<string, string> {
    if (typeof req.body === 'object' && req.body !== null && !Buffer.isBuffer(req.body)) {
      return req.body as Record<string, string>;
    }
    if (Buffer.isBuffer(req.body)) {
      return Object.fromEntries(new URLSearchParams(req.body.toString('utf8')).entries());
    }
    return {};
  }

  /** RFC 6749 Â§5.2: malformed token-endpoint input is 400, never a 500. */
  function parseForm<T>(schema: { safeParse: (data: unknown) => { success: true; data: T } | { success: false; error: { issues: unknown[] } } }, req: Request): T {
    const result = schema.safeParse(parseFormBody(req));
    if (!result.success) {
      throw new AppError(400, 'INVALID_REQUEST', 'Malformed form body');
    }
    return result.data;
  }

  router.post(
    '/token',
    rateLimitMiddleware(redis, {
      bucket: 'token-client',
      limit: config.RATE_LIMIT_TOKEN,
      windowSeconds: config.RATE_LIMIT_WINDOW,
      keyResolver: (req) => parseBasicAuth(req)?.clientId ?? req.ip ?? 'unknown',
    }),
    asyncHandler(async (req, res) => {
      const form = parseForm(tokenFormSchema, req);
      const basic = parseBasicAuth(req);
      const result = await oauth.token(form, basic, requestContext(req));
      res.setHeader('Cache-Control', 'no-store');
      res.setHeader('Pragma', 'no-cache');
      res.status(200).json(result);
    }),
  );

  router.post(
    '/introspect',
    asyncHandler(async (req, res) => {
      const form = parseForm(introspectFormSchema, req);
      const basic = parseBasicAuth(req);
      // RFC 7662 Â§2.1: introspection requires an authenticated caller.
      if (!basic) {
        res.status(401).json({ error: 'invalid_client', error_description: 'Client authentication required' });
        return;
      }
      const client = await clients.findByClientId(basic.clientId);
      if (!client || !(await clients.verifySecret(client, basic.clientSecret))) {
        await audit.record({
          event_type: 'INTROSPECTION_DENIED',
          ip: req.ip,
          request_id: req.requestId,
          metadata: { reason: 'client_auth_failed' },
        });
        res.status(401).json({ error: 'invalid_client', error_description: 'Invalid client credentials' });
        return;
      }
      res.json(await oauth.introspect(form.token));
    }),
  );

  router.post(
    '/revoke',
    asyncHandler(async (req, res) => {
      const form = parseForm(revokeFormSchema, req);
      await oauth.revoke(form.token, requestContext(req));
      res.status(200).json({ revoked: true });
    }),
  );

  return router;
}
