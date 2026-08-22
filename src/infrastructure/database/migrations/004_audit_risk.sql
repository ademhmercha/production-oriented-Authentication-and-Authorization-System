-- Audit log and risk events.

CREATE TABLE audit_logs (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type  TEXT NOT NULL,
    user_id     UUID,
    client_id   TEXT,
    ip          TEXT,
    user_agent  TEXT,
    request_id  TEXT,
    metadata    JSONB NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_audit_logs_user_time ON audit_logs (user_id, created_at DESC);
CREATE INDEX idx_audit_logs_event_time ON audit_logs (event_type, created_at DESC);

CREATE TABLE risk_events (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      UUID,
    session_id   UUID,
    event_type   TEXT NOT NULL,
    level        TEXT NOT NULL CHECK (level IN ('low', 'medium', 'high')),
    score        INT NOT NULL DEFAULT 0,
    signals      JSONB NOT NULL DEFAULT '[]',
    action_taken TEXT NOT NULL,
    ip           TEXT,
    user_agent   TEXT,
    request_id   TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_risk_events_user_time ON risk_events (user_id, created_at DESC);
