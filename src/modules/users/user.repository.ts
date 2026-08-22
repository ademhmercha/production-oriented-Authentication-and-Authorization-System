import { Database } from '../../infrastructure/database/pool';

/** Raw DB row shape for users. */
export interface UserRow {
  id: string;
  email: string;
  password_hash: string;
  first_name: string | null;
  last_name: string | null;
  status: 'active' | 'pending_verification' | 'locked' | 'disabled';
  failed_login_count: number;
  locked_until: Date | null;
  mfa_required: boolean;
  last_login_at: Date | null;
  password_changed_at: Date;
  created_at: Date;
  updated_at: Date;
}

export interface CreateUserData {
  email: string;
  passwordHash: string;
  firstName?: string | null;
  lastName?: string | null;
}

/**
 * Repository boundary for users. All SQL lives here - services never
 * construct queries, keeping domain logic persistence-agnostic.
 */
export class UserRepository {
  constructor(private readonly db: Database) {}

  async create(data: CreateUserData): Promise<UserRow> {
    const result = await this.db.query<UserRow>(
      `INSERT INTO users (email, password_hash, first_name, last_name)
       VALUES ($1, $2, $3, $4)
       RETURNING *`,
      [data.email.toLowerCase(), data.passwordHash, data.firstName ?? null, data.lastName ?? null],
    );
    return result.rows[0]!;
  }

  async findByEmail(email: string): Promise<UserRow | null> {
    const result = await this.db.query<UserRow>(`SELECT * FROM users WHERE email = $1`, [
      email.toLowerCase(),
    ]);
    return result.rows[0] ?? null;
  }

  async findById(id: string): Promise<UserRow | null> {
    const result = await this.db.query<UserRow>(`SELECT * FROM users WHERE id = $1`, [id]);
    return result.rows[0] ?? null;
  }

  async updateProfile(id: string, firstName: string | null, lastName: string | null): Promise<void> {
    await this.db.query(
      `UPDATE users SET first_name = $2, last_name = $3, updated_at = now() WHERE id = $1`,
      [id, firstName, lastName],
    );
  }

  async markVerified(id: string): Promise<void> {
    await this.db.query(
      `UPDATE users SET status = 'active', updated_at = now() WHERE id = $1 AND status = 'pending_verification'`,
      [id],
    );
  }

  async setStatus(id: string, status: UserRow['status']): Promise<void> {
    await this.db.query(`UPDATE users SET status = $2, updated_at = now() WHERE id = $1`, [id, status]);
  }

  async recordFailedLogin(id: string): Promise<void> {
    await this.db.query(
      `UPDATE users SET failed_login_count = failed_login_count + 1, updated_at = now() WHERE id = $1`,
      [id],
    );
  }

  async lockUntil(id: string, until: Date): Promise<void> {
    await this.db.query(
      `UPDATE users SET locked_until = $2, status = 'locked', updated_at = now()
       WHERE id = $1 AND (locked_until IS NULL OR locked_until < $2)`,
      [id, until],
    );
  }

  async clearLockAndFailures(id: string): Promise<void> {
    await this.db.query(
      `UPDATE users SET failed_login_count = 0, locked_until = NULL,
              status = CASE WHEN status = 'locked' THEN 'active' ELSE status END,
              updated_at = now()
       WHERE id = $1`,
      [id],
    );
  }

  async setLastLogin(id: string): Promise<void> {
    await this.db.query(`UPDATE users SET last_login_at = now(), updated_at = now() WHERE id = $1`, [id]);
  }

  async updatePasswordHash(id: string, passwordHash: string): Promise<void> {
    await this.db.query(
      `UPDATE users SET password_hash = $2, password_changed_at = now(),
              failed_login_count = 0, locked_until = NULL, updated_at = now()
       WHERE id = $1`,
      [id, passwordHash],
    );
  }

  async rolesOf(userId: string): Promise<string[]> {
    const result = await this.db.query<{ name: string }>(
      `SELECT r.name FROM roles r
       JOIN user_roles ur ON ur.role_id = r.id
       WHERE ur.user_id = $1 ORDER BY r.name`,
      [userId],
    );
    return result.rows.map((r) => r.name);
  }

  /** Grants a system role by name (used for the implicit 'user' role). */
  async addRole(userId: string, roleName: string): Promise<void> {
    await this.db.query(
      `INSERT INTO user_roles (user_id, role_id)
       SELECT $1, id FROM roles WHERE name = $2
       ON CONFLICT DO NOTHING`,
      [userId, roleName],
    );
  }

  async permissionsOf(userId: string): Promise<string[]> {
    const result = await this.db.query<{ name: string }>(
      `SELECT DISTINCT p.name FROM permissions p
       JOIN role_permissions rp ON rp.permission_id = p.id
       JOIN user_roles ur ON ur.role_id = rp.role_id
       WHERE ur.user_id = $1 ORDER BY p.name`,
      [userId],
    );
    return result.rows.map((r) => r.name);
  }
}
