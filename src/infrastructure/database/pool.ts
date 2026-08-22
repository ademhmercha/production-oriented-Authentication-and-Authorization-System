import { Pool, PoolClient, QueryResult, QueryResultRow } from 'pg';
import { loadConfig } from '../../config';

/**
 * Thin PostgreSQL access layer.
 *
 * All repositories go through parameterized queries ($1, $2, ...) which
 * prevents SQL injection by construction. No string concatenation of
 * user input into SQL is ever done.
 */
export class Database {
  private readonly pool: Pool;

  constructor(connectionString?: string, poolMax?: number) {
    const config = loadConfig();
    this.pool = new Pool({
      connectionString: connectionString ?? config.DATABASE_URL,
      max: poolMax ?? config.DATABASE_POOL_MAX,
      idleTimeoutMillis: 30_000,
      connectionTimeoutMillis: 10_000,
    });
    this.pool.on('error', (err) => {
      // Prevent process crash on idle-client errors.
      // eslint-disable-next-line no-console
      console.error('[db] idle client error', err.message);
    });
  }

  query<T extends QueryResultRow = QueryResultRow>(
    text: string,
    params?: unknown[],
  ): Promise<QueryResult<T>> {
    return this.pool.query(text, params as unknown[]) as Promise<QueryResult<T>>;
  }

  /** Runs `fn` inside a transaction; rolls back on throw. */
  async withTransaction<T>(fn: (tx: PoolClient) => Promise<T>): Promise<T> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const result = await fn(client);
      await client.query('COMMIT');
      return result;
    } catch (err) {
      await client.query('ROLLBACK').catch(() => undefined);
      throw err;
    } finally {
      client.release();
    }
  }

  async ping(): Promise<void> {
    await this.pool.query('SELECT 1');
  }

  /** Acquires a raw client (caller must release). */
  withClient(): Promise<PoolClient> {
    return this.pool.connect();
  }

  async close(): Promise<void> {
    await this.pool.end();
  }
}

let singleton: Database | null = null;

export function getDatabase(): Database {
  if (!singleton) singleton = new Database();
  return singleton;
}
