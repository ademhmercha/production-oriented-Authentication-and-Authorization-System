/**
 * Generates a fresh Ed25519 signing key through the LocalKeyProvider.
 * Used at deploy time / docker entrypoint; safe to run repeatedly.
 */
import 'dotenv/config';
import { join } from 'node:path';
import { loadConfig } from '../config';
import { LocalKeyProvider } from '../modules/keys/local-key-provider';

async function main(): Promise<void> {
  const config = loadConfig();
  const provider = new LocalKeyProvider(config.KMS_KEY_DIR);
  const current = await provider.getCurrentSigningKey();
  // eslint-disable-next-line no-console
  console.log(`Signing key ready: kid=${current.kid} dir=${join(config.KMS_KEY_DIR)}`);
}

main().catch((err) => {
  // eslint-disable-next-line no-console
  console.error('Key generation failed:', err.message);
  process.exit(1);
});
