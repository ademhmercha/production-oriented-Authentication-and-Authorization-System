import { AuditEvent } from './audit.types';

/**
 * Pluggable audit sink.
 *
 * Default sink writes to PostgreSQL. Additional sinks (SIEM, Kafka,
 * CloudWatch, Elastic, Splunk) can be registered without touching callers.
 */
export interface AuditSink {
  write(event: AuditEvent): Promise<void>;
}
