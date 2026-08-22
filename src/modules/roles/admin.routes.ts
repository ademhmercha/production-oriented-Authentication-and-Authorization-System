import { Router } from 'express';
import { RbacRepository } from './rbac.repository';
import { AuditLogService } from '../audit/audit.service';
import { JwtService } from '../tokens/jwt.service';
import { authenticate } from '../../common/guards/authenticate';
import { requirePermission } from '../../common/guards/require-permission';
import { validate } from '../../common/validation/validate';
import { asyncHandler } from '../../common/decorators/async-handler';
import {
  idParamSchema,
  listUsersQuerySchema,
  setUserRolesSchema,
  setUserStatusSchema,
  setRolePermissionsSchema,
} from './rbac.schemas';

/**
 * Admin RBAC + user management routes.
 * Every route requires authentication AND an explicit permission
 * (granted through roles, embedded in the JWT at issuance).
 */
export function createAdminRoutes(rbac: RbacRepository, audit: AuditLogService, jwtService: JwtService): Router {
  const router = Router();
  const auth = authenticate(jwtService);

  // ---- Role / permission / scope catalogues ----
  router.get(
    '/roles',
    auth,
    requirePermission('roles:read'),
    asyncHandler(async (_req, res) => {
      const roles = await rbac.listRoles();
      const withPermissions = await Promise.all(
        roles.map(async (r) => ({ ...r, permissions: await rbac.rolePermissionNames(r.id) })),
      );
      res.json({ roles: withPermissions });
    }),
  );

  router.put(
    '/roles/:id/permissions',
    auth,
    requirePermission('roles:write'),
    validate({ params: idParamSchema, body: setRolePermissionsSchema }),
    asyncHandler(async (req, res) => {
      await rbac.setRolePermissions(req.params.id!, req.body.permissions);
      await audit.record({
        event_type: 'ROLE_PERMISSIONS_UPDATED',
        user_id: req.user!.sub,
        request_id: req.requestId,
        metadata: { role_id: req.params.id },
      });
      res.json({ status: 'updated' });
    }),
  );

  router.get(
    '/permissions',
    auth,
    requirePermission('roles:read'),
    asyncHandler(async (_req, res) => res.json({ permissions: await rbac.listPermissions() })),
  );

  router.get(
    '/scopes',
    auth,
    requirePermission('roles:read'),
    asyncHandler(async (_req, res) => res.json({ scopes: await rbac.listScopes() })),
  );

  // ---- User administration ----
  router.get(
    '/users',
    auth,
    requirePermission('users:read'),
    validate({ query: listUsersQuerySchema }),
    asyncHandler(async (req, res) => {
      const { limit, offset } = req.query as unknown as { limit: number; offset: number };
      res.json({ users: await rbac.listUsers(limit, offset), limit, offset });
    }),
  );

  router.put(
    '/users/:id/roles',
    auth,
    requirePermission('users:write'),
    validate({ params: idParamSchema, body: setUserRolesSchema }),
    asyncHandler(async (req, res) => {
      await rbac.setUserRoles(req.params.id!, req.body.roles);
      await audit.record({
        event_type: 'USER_ROLES_UPDATED',
        user_id: req.user!.sub,
        request_id: req.requestId,
        metadata: { target_user_id: req.params.id, roles: req.body.roles },
      });
      res.json({ status: 'updated' });
    }),
  );

  router.put(
    '/users/:id/status',
    auth,
    requirePermission('users:write'),
    validate({ params: idParamSchema, body: setUserStatusSchema }),
    asyncHandler(async (req, res) => {
      await rbac.setUserStatus(req.params.id!, req.body.status);
      await audit.record({
        event_type: req.body.status === 'disabled' ? 'USER_DISABLED' : 'USER_ENABLED',
        user_id: req.user!.sub,
        request_id: req.requestId,
        metadata: { target_user_id: req.params.id },
      });
      res.json({ status: 'updated' });
    }),
  );

  // ---- Audit trail access ----
  router.get(
    '/audit',
    auth,
    requirePermission('audit:read'),
    asyncHandler(async (req, res) => {
      const limit = Math.min(Number(req.query.limit ?? 50) || 50, 200);
      const eventType = typeof req.query.event_type === 'string' ? req.query.event_type : undefined;
      res.json({ events: await rbac.listAuditEvents(limit, eventType), limit });
    }),
  );

  return router;
}
