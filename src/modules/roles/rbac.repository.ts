import { Database } from '../../infrastructure/database/pool';

export interface RoleRow {
  id: string;
  name: string;
  description: string | null;
  is_system: boolean;
}

/**
 * RBAC administration repository.
 * Roles/permissions/scopes were seeded; this manages assignments + listing.
 */
export class RbacRepository {
  constructor(private readonly db: Database) {}

  async listRoles(): Promise<RoleRow[]> {
    const result = await this.db.query<RoleRow>(
      `SELECT id, name, description, is_system FROM roles ORDER BY name`,
    );
    return result.rows;
  }

  async listPermissions(): Promise<Array<{ name: string }>> {
    const result = await this.db.query<{ name: string }>(`SELECT name FROM permissions ORDER BY name`);
    return result.rows;
  }

  async listScopes(): Promise<Array<{ name: string; description: string | null }>> {
    const result = await this.db.query<{ name: string; description: string | null }>(
      `SELECT name, description FROM scopes ORDER BY name`,
    );
    return result.rows;
  }

  async rolePermissionNames(roleId: string): Promise<string[]> {
    const result = await this.db.query<{ name: string }>(
      `SELECT p.name FROM permissions p
       JOIN role_permissions rp ON rp.permission_id = p.id
       WHERE rp.role_id = $1 ORDER BY p.name`,
      [roleId],
    );
    return result.rows.map((r) => r.name);
  }

  async setRolePermissions(roleId: string, permissionNames: string[]): Promise<void> {
    await this.db.withTransaction(async (tx) => {
      await tx.query(`DELETE FROM role_permissions WHERE role_id = $1`, [roleId]);
      if (permissionNames.length === 0) return;
      await tx.query(
        `INSERT INTO role_permissions (role_id, permission_id)
         SELECT $1, id FROM permissions WHERE name = ANY($2::text[])
         ON CONFLICT DO NOTHING`,
        [roleId, permissionNames],
      );
    });
  }

  async userRoleIds(userId: string): Promise<string[]> {
    const result = await this.db.query<{ role_id: string }>(
      `SELECT role_id FROM user_roles WHERE user_id = $1`,
      [userId],
    );
    return result.rows.map((r) => r.role_id);
  }

  async setUserRoles(userId: string, roleNames: string[]): Promise<void> {
    await this.db.withTransaction(async (tx) => {
      await tx.query(`DELETE FROM user_roles WHERE user_id = $1`, [userId]);
      if (roleNames.length === 0) return;
      await tx.query(
        `INSERT INTO user_roles (user_id, role_id)
         SELECT $1, id FROM roles WHERE name = ANY($2::text[])`,
        [userId, roleNames],
      );
    });
  }

  /** Admin listing of users with their roles. */
  async listUsers(limit: number, offset: number): Promise<
    Array<{ id: string; email: string; status: string; created_at: Date; roles: string[] }>
  > {
    const result = await this.db.query<{
      id: string;
      email: string;
      status: string;
      created_at: Date;
      roles: string[] | null;
    }>(
      `SELECT u.id, u.email, u.status, u.created_at,
              array_remove(array_agg(r.name), NULL) AS roles
       FROM users u
       LEFT JOIN user_roles ur ON ur.user_id = u.id
       LEFT JOIN roles r ON r.id = ur.role_id
       GROUP BY u.id
       ORDER BY u.created_at DESC
       LIMIT $1 OFFSET $2`,
      [limit, offset],
    );
    return result.rows.map((r) => ({ ...r, roles: r.roles ?? [] }));
  }

  async setUserStatus(userId: string, status: 'active' | 'disabled'): Promise<void> {
    await this.db.query(
      `UPDATE users SET status = $2, updated_at = now() WHERE id = $1`,
      [userId, status],
    );
  }

  async listAuditEvents(limit: number, eventType?: string): Promise<
    Array<{ id: string; event_type: string; user_id: string | null; client_id: string | null; ip: string | null; metadata: unknown; created_at: Date }>
  > {
    interface AuditRow {
      id: string;
      event_type: string;
      user_id: string | null;
      client_id: string | null;
      ip: string | null;
      user_agent: string | null;
      request_id: string | null;
      metadata: unknown;
      created_at: Date;
    }
    if (eventType) {
      const r = await this.db.query<AuditRow>(
        `SELECT id, event_type, user_id, client_id, ip, user_agent, request_id, metadata, created_at
         FROM audit_logs WHERE event_type = $2 ORDER BY created_at DESC LIMIT $1`,
        [limit, eventType],
      );
      return r.rows;
    }
    const r = await this.db.query<AuditRow>(
      `SELECT id, event_type, user_id, client_id, ip, user_agent, request_id, metadata, created_at
       FROM audit_logs ORDER BY created_at DESC LIMIT $1`,
      [limit],
    );
    return r.rows;
  }
}
