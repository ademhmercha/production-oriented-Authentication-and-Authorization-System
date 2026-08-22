import 'dotenv/config';
import { Database } from '../infrastructure/database/pool';
import { runSeeds } from '../infrastructure/database/seed';

async function main(): Promise<void> {
  const db = new Database();
  try {
    const { adminEmail, generatedPassword } = await runSeeds(db);
    // eslint-disable-next-line no-console
    console.log(`Seed complete. Admin user: ${adminEmail}`);
    if (generatedPassword) {
      // eslint-disable-next-line no-console
      console.log(`Generated admin password (store it now, shown once): ${generatedPassword}`);
    }
  } finally {
    await db.close();
  }
}

main().catch((err) => {
  // eslint-disable-next-line no-console
  console.error('Seed failed:', err.message);
  process.exit(1);
});
