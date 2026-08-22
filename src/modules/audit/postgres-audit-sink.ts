import { PoolClient } from 'pg';
import { AuditSink } from './audit.sink';
import { AuditEvent } from './audit.types';
import { logger } from '../../common/logger';

/**
 * Writes audit events into PostgreSQL (audit_logs table) via the shared pool.
 * Used as the default durable sink; SIEM-style sinks can be added alongside.
 */
export class PostgresAuditSink implements AuditSink {
  constructor(
    private readonly getClient: () => Promise<PoolClient>,
    private readonly release: (client: PoolClient) => void,
  ) {}

  async write(event: AuditEvent): Promise<void> {
    const client = await this.getClient();
    try {
      await client.query(
        `INSERT INTO audit_logs (event_type, user_id, client_id, ip, user_agent, request_id, metadata)
         VALUES ($1, $2, $3, $4, $5, $6, $7)`,
        [
          event.event_type,
          event.user_id ?? null,
          event.client_id ?? null,
          event.ip ?? null,
          event.user_agent ?? null,
          event.request_id ?? null,
          JSON.stringify(sanitizeMetadata(event.metadata)),
        ],
      );
    } catch (err) {
      // Audit failures must not break the request path, but must be visible.
      logger.error({ err, eventType: event.event_type }, 'Failed to persist audit event');
    } finally {
      this.release(client);
    }
  }
}

/**
 * Defense in depth: strips credential-like fields before persisting.
 * Callers should never include secrets, but we enforce it here too.
 */
const REDACTED_KEYS = /password|secret|token|authorization|cookie|code_verifier/i;
export function sanitizeMetadata(metadata: Record<string, unknown> | undefined): Record<string, unknown> {
  if (!metadata) return {};
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(metadata)) {
    out[key] = REDACTED_KEYS.test(key) ? '[REDACTED]' : value;
  }
  return out;
}
