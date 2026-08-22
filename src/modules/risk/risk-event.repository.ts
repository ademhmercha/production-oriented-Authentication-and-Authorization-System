import { Database } from '../../infrastructure/database/pool';
import { RiskEvaluation } from './risk.types';

/** Persists risk evaluations for observability + audit correlation. */
export class RiskEventRepository {
  constructor(private readonly db: Database) {}

  async record(params: {
    userId?: string | null;
    sessionId?: string | null;
    eventType: string;
    evaluation: RiskEvaluation;
    actionTaken: string;
    ip?: string | null;
    userAgent?: string | null;
    requestId?: string | null;
  }): Promise<void> {
    await this.db.query(
      `INSERT INTO risk_events (user_id, session_id, event_type, level, score, signals, action_taken, ip, user_agent, request_id)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
      [
        params.userId ?? null,
        params.sessionId ?? null,
        params.eventType,
        params.evaluation.level,
        params.evaluation.score,
        JSON.stringify(params.evaluation.signals),
        params.actionTaken,
        params.ip ?? null,
        params.userAgent ?? null,
        params.requestId ?? null,
      ],
    );
  }
}
