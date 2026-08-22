import { join } from 'node:path';
import 'dotenv/config';
import { Database } from '../infrastructure/database/pool';
import { runMigrations } from '../infrastructure/database/migrate';

async function main(): Promise<void> {
  const db = new Database();
  try {
    const dir = join(__dirname, '..', 'infrastructure', 'database', 'migrations');
    const applied = await runMigrations(db, dir);
    // eslint-disable-next-line no-console
    console.log(applied.length ? `Applied ${applied.length} migration(s).` : 'Database up to date.');
  } finally {
    await db.close();
  }
}

main().catch((err) => {
  // eslint-disable-next-line no-console
  console.error('Migration failed:', err.message);
  process.exit(1);
});
