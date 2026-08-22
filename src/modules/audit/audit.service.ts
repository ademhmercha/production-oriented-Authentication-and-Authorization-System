import { AuditEvent, AuditEventType } from './audit.types';
import { AuditSink } from './audit.sink';
import { PostgresAuditSink, sanitizeMetadata } from './postgres-audit-sink';
import { Database } from '../../infrastructure/database/pool';
import { logger } from '../../common/logger';

/**
 * Central audit logging service.
 *
 * Every security-sensitive operation calls `AuditLogService.record(...)`.
 * Events fan out to all registered sinks (Postgres by default; SIEM/Kafka
 * etc. can be plugged in later). Recording is fire-and-forget from the
 * caller's perspective but errors are logged loudly.
 */
export class AuditLogService {
  private readonly sinks: AuditSink[];

  constructor(...sinks: AuditSink[]) {
    this.sinks = sinks;
  }

  static withDefaults(db: Database): AuditLogService {
    return new AuditLogService(new PostgresAuditSink(() => db.withClient(), (c) => c.release()));
  }

  registerSink(sink: AuditSink): void {
    this.sinks.push(sink);
  }

  /** Records an event to every sink. Never throws. */
  async record(event: AuditEvent): Promise<void> {
    const enriched: AuditEvent = {
      ...event,
      metadata: sanitizeMetadata(event.metadata),
    };
    for (const sink of this.sinks) {
      try {
        await sink.write(enriched);
      } catch (err) {
        logger.error({ err, event_type: event.event_type }, 'audit sink failure');
      }
    }
  }
}
