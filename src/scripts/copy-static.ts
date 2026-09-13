/**
 * Copies the frontend static assets (HTML/CSS + compiled ESM app bundle) from
 * source (src/apps/frontend/static) into the build output
 * (dist/apps/frontend/static) so the compiled server can serve them.
 * TSC is compile-only; static files are not part of the emit graph.
 */
import { cpSync, existsSync } from 'node:fs';
import { join, resolve } from 'node:path';
import 'dotenv/config';

const root = resolve(__dirname, '..', '..'); // dist -> repo root when compiled
const fromBase =
  process.env.STATIC_SOURCE ?? join(root, 'src', 'apps', 'frontend', 'static');
const toBase = join(root, 'dist', 'apps', 'frontend', 'static');

if (!existsSync(fromBase)) {
  // eslint-disable-next-line no-console
  console.error(`Static source not found: ${fromBase}`);
  process.exit(1);
}

cpSync(fromBase, toBase, { recursive: true });

// eslint-disable-next-line no-console
console.log(`Copied ${fromBase} -> ${toBase}`);