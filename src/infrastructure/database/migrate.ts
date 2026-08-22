import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { Database } from './pool';
import { logger } from '../../common/logger';

/**
 * Minimal, explicit SQL migration runner.
 *
 * Production rule: schema changes are applied through these versioned,
 * ordered, transactional migrations - never via automatic schema sync.
 */
export async function runMigrations(db: Database, migrationsDir: string): Promise<string[]> {
  await db.query(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      name        TEXT PRIMARY KEY,
      applied_at  TIMESTAMPTZ NOT NULL DEFAULT now()
    )
  `);

  const files = readdirSync(migrationsDir)
    .filter((f) => f.endsWith('.sql'))
    .sort();

  const applied = new Set(
    (await db.query<{ name: string }>('SELECT name FROM schema_migrations')).rows.map((r) => r.name),
  );

  const executedNow: string[] = [];
  for (const file of files) {
    if (applied.has(file)) continue;
    const sql = readFileSync(join(migrationsDir, file), 'utf8');
    await db.withTransaction(async (tx) => {
      await tx.query(sql);
      await tx.query('INSERT INTO schema_migrations (name) VALUES ($1)', [file]);
    });
    logger.info({ migration: file }, 'Applied migration');
    executedNow.push(file);
  }
  return executedNow;
}
