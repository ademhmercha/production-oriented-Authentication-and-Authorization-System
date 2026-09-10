import { Database } from './pool';
import argon2 from 'argon2';
import { randomBytes } from 'node:crypto';
import { loadConfig } from '../../config';

/**
 * Idempotent seed data: roles, permissions, scopes, RBAC links and a
 * bootstrap admin. Safe to run repeatedly.
 */
export async function runSeeds(db: Database): Promise<{ adminEmail: string; generatedPassword?: string }> {
  const config = loadConfig();

  const roles = [
    ['admin', 'Full administrative access'],
    ['user', 'Standard end-user'],
    ['support', 'Read-only support access to users and audits'],
    ['service', 'Machine/service account'],
  ] as const;

  const permissions = [
    'users:read',
    'users:write',
    'users:delete',
    'clients:read',
    'clients:write',
    'roles:read',
    'roles:write',
    'audit:read',
  ] as const;

  const scopes = [
    ['openid', 'Authenticate via OpenID Connect'],
    ['profile', 'Access basic profile claims'],
    ['email', 'Access email claims'],
    ['offline_access', 'Request refresh tokens'],
    ['api.read', 'Read access to protected APIs'],
    ['api.write', 'Write access to protected APIs'],
    ['mfa', 'Manage own MFA methods'],
  ] as const;

  await db.withTransaction(async (tx) => {
    for (const [name, description] of roles) {
      await tx.query(
        `INSERT INTO roles (name, description, is_system) VALUES ($1, $2, TRUE)
         ON CONFLICT (name) DO UPDATE SET description = EXCLUDED.description`,
        [name, description],
      );
    }
    for (const name of permissions) {
      await tx.query(`INSERT INTO permissions (name) VALUES ($1) ON CONFLICT (name) DO NOTHING`, [name]);
    }
    for (const [name, description] of scopes) {
      await tx.query(`INSERT INTO scopes (name, description) VALUES ($1, $2) ON CONFLICT (name) DO NOTHING`, [
        name,
        description,
      ]);
    }

    // Role -> permission mapping
    const grant = async (role: string, perms: readonly string[]): Promise<void> => {
      await tx.query(
        `INSERT INTO role_permissions (role_id, permission_id)
         SELECT r.id, p.id FROM roles r, permissions p
         WHERE r.name = $1 AND p.name = ANY($2::text[])
         ON CONFLICT DO NOTHING`,
        [role, perms],
      );
    };
    const allPerms = [...permissions];
    await grant('admin', allPerms);
    await grant('support', ['users:read', 'audit:read']);
    await grant('service', ['clients:read']);
    // 'user' has no direct permissions; end-users authorize via scopes.
  });

  // Bootstrap admin
  let generatedPassword: string | undefined;
  const adminEmail = config.ADMIN_EMAIL;
  let adminPassword = config.ADMIN_PASSWORD;
  if (!adminPassword) {
    adminPassword = randomBytes(18).toString('base64url');
    generatedPassword = adminPassword;
  }
  const passwordHash = await argon2.hash(adminPassword, { type: argon2.argon2id });

  await db.withTransaction(async (tx) => {
    await tx.query(
      `INSERT INTO users (email, password_hash, status)
       VALUES ($1, $2, 'active')
       ON CONFLICT (email) DO NOTHING`,
      [adminEmail, passwordHash],
    );
    await tx.query(
      `INSERT INTO user_roles (user_id, role_id)
       SELECT u.id, r.id FROM users u, roles r
       WHERE u.email = $1 AND r.name = 'admin'
       ON CONFLICT DO NOTHING`,
      [adminEmail],
    );
  });

  return { adminEmail, generatedPassword };
}
