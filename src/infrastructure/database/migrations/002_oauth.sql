-- OAuth 2.0 clients and authorization codes.

CREATE TABLE oauth_clients (
    id                          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id                   TEXT NOT NULL UNIQUE,
    client_secret_hash          TEXT,
    name                        TEXT NOT NULL,
    client_type                 TEXT NOT NULL DEFAULT 'confidential'
                                CHECK (client_type IN ('confidential', 'public')),
    redirect_uris               TEXT[] NOT NULL DEFAULT '{}',
    allowed_scopes              TEXT[] NOT NULL DEFAULT '{}',
    grant_types                 TEXT[] NOT NULL DEFAULT '{}',
    token_endpoint_auth_method  TEXT NOT NULL DEFAULT 'client_secret_basic'
                                CHECK (token_endpoint_auth_method IN ('client_secret_basic', 'client_secret_post', 'none')),
    require_pkce                BOOLEAN NOT NULL DEFAULT TRUE,
    status                      TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at                  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Authorization codes are stored HASHED (never plaintext) and are single-use.
CREATE TABLE authorization_codes (
    id                     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code_hash              TEXT NOT NULL UNIQUE,
    client_id              UUID NOT NULL REFERENCES oauth_clients (id) ON DELETE CASCADE,
    user_id                UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    redirect_uri           TEXT NOT NULL,
    scope                  TEXT NOT NULL,
    nonce                  TEXT,
    code_challenge         TEXT,
    code_challenge_method  TEXT CHECK (code_challenge_method IN ('S256', 'plain')),
    expires_at             TIMESTAMPTZ NOT NULL,
    consumed_at            TIMESTAMPTZ,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_auth_codes_user ON authorization_codes (user_id);
