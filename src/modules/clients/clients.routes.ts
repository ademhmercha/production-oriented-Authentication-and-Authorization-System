import { Router } from 'express';
import { z } from 'zod';
import { ClientRepository } from './client.repository';
import { AuditLogService } from '../audit/audit.service';
import { AuditEventType } from '../audit/audit.types';
import { authenticate } from '../../common/guards/authenticate';
import { requirePermission } from '../../common/guards/require-permission';
import { validate } from '../../common/validation/validate';
import { asyncHandler } from '../../common/decorators/async-handler';
import { JwtService } from '../tokens/jwt.service';

const createClientSchema = z.object({
  name: z.string().trim().min(3).max(100),
  client_type: z.enum(['confidential', 'public']),
  redirect_uris: z.array(z.string().url()).max(10),
  allowed_scopes: z.array(z.string().regex(/^[\w.]+$/)).min(1).max(20),
  grant_types: z.array(z.enum(['authorization_code', 'client_credentials'])).min(1),
  token_endpoint_auth_method: z.enum(['client_secret_basic', 'client_secret_post', 'none']),
});

const idParamSchema = z.object({ id: z.string().uuid() });

/**
 * Client administration API (permission-guarded).
 * Secrets are returned EXACTLY ONCE at creation / rotation.
 */
export function createClientsRoutes(
  clientsRepo: ClientRepository,
  audit: AuditLogService,
  jwtService: JwtService,
): Router {
  const router = Router();
  const auth = authenticate(jwtService);

  router.get(
    '/',
    auth,
    requirePermission('clients:read'),
    asyncHandler(async (_req, res) => {
      res.json({ clients: await clientsRepo.list() });
    }),
  );

  router.post(
    '/',
    auth,
    requirePermission('clients:write'),
    validate({ body: createClientSchema }),
    asyncHandler(async (req, res) => {
      const body = req.body as z.infer<typeof createClientSchema>;
      // Public clients must not use secret-based auth methods.
      const method = body.client_type === 'public' ? 'none' : body.token_endpoint_auth_method;
      if (body.client_type === 'confidential') {
        for (const grant of body.grant_types) {
          if (grant === 'client_credentials' && !body.allowed_scopes.every((s) => s.startsWith('api.'))) {
            res.status(400).json({
              error: 'VALIDATION_ERROR',
              message: 'client_credentials clients may only request api.* scopes',
            });
            return;
          }
        }
      }

      const created = await clientsRepo.create({
        name: body.name,
        clientType: body.client_type,
        redirectUris: body.redirect_uris,
        allowedScopes: body.allowed_scopes,
        grantTypes: body.grant_types,
        requirePkce: true, // always enforce PKCE for authorization_code
        tokenEndpointAuthMethod: method,
      });

      await audit.record({
        event_type: AuditEventType.CLIENT_CREATED,
        user_id: req.user!.sub,
        request_id: req.requestId,
        metadata: { client_id: created.row.client_id, client_type: body.client_type },
      });

      res.status(201).json({
        client: created.row,
        // Shown once - only the Argon2id hash is stored server-side.
        client_secret: created.secret,
      });
    }),
  );

  router.post(
    '/:id/rotate-secret',
    auth,
    requirePermission('clients:write'),
    validate({ params: idParamSchema }),
    asyncHandler(async (req, res) => {
      const secret = await clientsRepo.rotateSecret(req.params.id!);
      await audit.record({
        event_type: AuditEventType.CLIENT_SECRET_ROTATED,
        user_id: req.user!.sub,
        request_id: req.requestId,
        metadata: { target_client_db_id: req.params.id },
      });
      res.status(201).json({ client_secret: secret });
    }),
  );

  router.put(
    '/:id/status',
    auth,
    requirePermission('clients:write'),
    validate({ params: idParamSchema }),
    asyncHandler(async (req, res) => {
      const status = (req.body as { status?: string }).status;
      if (status !== 'active' && status !== 'disabled') {
        res.status(400).json({ error: 'VALIDATION_ERROR', message: 'status must be active|disabled' });
        return;
      }
      await clientsRepo.setStatus(req.params.id!, status);
      await audit.record({
        event_type: status === 'disabled'
          ? AuditEventType.CLIENT_DISABLED
          : AuditEventType.CLIENT_UPDATED,
        user_id: req.user!.sub,
        request_id: req.requestId,
        metadata: { target_client_db_id: req.params.id, status },
      });
      res.json({ status });
    }),
  );

  return router;
}
