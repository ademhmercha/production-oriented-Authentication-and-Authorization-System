-- Documents owned by users - demo protected resource for /api/v1.
CREATE TABLE IF NOT EXISTS documents (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title       text NOT NULL CHECK (char_length(title) BETWEEN 1 AND 200),
    content     text NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_documents_owner ON documents(owner_id);
