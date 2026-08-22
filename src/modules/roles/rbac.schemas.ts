import { z } from 'zod';

export const idParamSchema = z.object({ id: z.string().uuid() });

export const listUsersQuerySchema = z.object({
  limit: z.coerce.number().int().min(1).max(100).default(25),
  offset: z.coerce.number().int().min(0).default(0),
});

export const setUserRolesSchema = z.object({
  roles: z.array(z.string().regex(/^[a-z_-]+$/)).max(10),
});

export const setUserStatusSchema = z.object({
  status: z.enum(['active', 'disabled']),
});

export const setRolePermissionsSchema = z.object({
  permissions: z.array(z.string().regex(/^[a-z_.:-]+$/)).max(50),
});
