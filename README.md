# Identity Platform — Production-Oriented Authentication & Authorization System

A centralized **Authentication & Authorization platform** built with
**Express.js + TypeScript**, implementing the OAuth 2.0 / OpenID Connect building
blocks a real production system needs — without a third-party IdP.

```
                       +--------------------+
   clients ----------> |    api-gateway     |  JWT verify (JWKS), scopes,
        :3000          |      (:3000)       |  rate limit, anti-spoof headers
                       +---------+----------+
              +------------------+------------------+
              v                                     v
   +--------------------+               +--------------------+
   |    auth-server     |               |    resource-api    |
   |      (:3001)       |               |      (:3002)       |
   | authn+oauth2+mfa+  |               |  zero-trust /api   |
   | rbac+admin+docs    |               +--------------------+
   +---------+----------+
             v
   +---------+----+   +-------+
   |   postgres   |  | redis |  sessions cache - rate limits - MFA
   |    (:5432)   |   |(:6379)|  challenges - risk signals - jti denylist
   +--------------+   +-------+
```

## Security features

| Area | Implementation |
|---|---|
| Password storage | Argon2id (64 MB, t=3, p=4) + policy checks + common-password denylist |
| Tokens | EdDSA (Ed25519) JWTs, kid-bearing headers, keys wrapped AES-256-GCM under a KMS master key; rotation supported |
| Key distribution | Public JWKS at `/.well-known/jwks.json`; gateway verifies remotely (no shared secrets) |
| Revocation | Refresh-token chains with reuse detection (revokes whole family + session); Redis jti denylist makes stateless access-token revocation immediate at the gateway and auth-server |
| OAuth2 | Authorization Code + PKCE (S256 enforced), client_credentials for services, hashed single-use codes with replay response, RFC 7662 introspection, RFC 7009 revocation, `no-store` token responses |
| OIDC | Discovery document, id_token (aud=client_id, nonce echo, scope-gated claims), UserInfo endpoint |
| Sessions | Server-side sessions cached in Redis, revocable, TTL-bounded |
| MFA | TOTP enrollment/verification, login challenges in Redis (attempt-limited), QR provisioning |
| RBAC | Roles -> permissions -> scopes; permission claims embedded in tokens; guarded admin API |
| Risk engine | Rules-based scoring (failed logins, IP frequency, new device) driving deny / step-up-MFA / allow |
| Rate limiting | Redis fixed-window per bucket (login/register/forgot/token/authorize/api/gateway) |
| Audit | Append-only audit log with secret redaction; queryable via `audit:read` |
| Edge contract | Gateway strips inbound identity headers and injects verified ones; resource-api requires shared-secret proof of origin |
| Transport/runtime | helmet security headers, strict CORS allow-list, zod-validated env config, fail-fast startup |

## Quick start (Docker)

```powershell
# 1. Configure secrets (.env is gitignored)
node -e "console.log('KMS_MASTER_KEY='+require('crypto').randomBytes(32).toString('base64'))" >> .env
node -e "console.log('GATEWAY_SHARED_SECRET='+require('crypto').randomBytes(32).toString('base64'))" >> .env

# 2. Boot the stack (migrations + seeds run automatically)
docker compose up -d --build

# 3. Use it
#    Auth server ....... http://localhost:3001  (Swagger UI: /docs)
#    Gateway ........... http://localhost:3000  (protected /api/v1)
#    Mail inbox ........ http://localhost:8025  (MailHog UI)
```

Bootstrap admin: the seed creates `admin@auth.local` and prints a one-time password
(or set `ADMIN_PASSWORD` in `.env` before the first boot).

## Local development

```powershell
npm install
docker compose up -d postgres redis mailhog   # infra only
cp .env.example .env                          # then edit as needed

npm run migrate
npm run seed          # roles/permissions/scopes/bootstrap admin
npm run keys:generate # signing key pair (only if ./keys is empty)

npm run dev:auth      # :3001
npm run dev:gateway   # :3000
npm run dev:resource  # :3002
```

## Testing

```powershell
npm test            # unit + integration (46 tests)
npm run lint
npm run typecheck
npm run build
```

Integration tests boot the real apps against Postgres/Redis: the full login
pipeline, lockout, refresh rotation + theft detection, RBAC guards, MFA
lifecycle, OAuth flows, gateway edge security and resource ownership isolation.

## API surface (interactive spec at `/docs`)

- `POST /auth/register`, `POST /auth/verify-email`, `POST /auth/login`
  (`mfa_required` challenge flow), `POST /auth/mfa/challenge`
- `GET /auth/me`, `POST /auth/logout`, `POST /auth/forgot-password`,
  `POST /auth/reset-password`
- `POST /mfa/enroll`, `POST /mfa/verify`, `POST /mfa/disable`
- `GET /oauth/authorize` (JSON code issuance), `POST /oauth/token`
  (authorization_code + PKCE, client_credentials), `POST /oauth/introspect`,
  `POST /oauth/revoke`
- `GET /.well-known/openid-configuration`, `GET /.well-known/jwks.json`,
  `GET /userinfo`
- `GET/PUT /admin/users|roles|clients...` (permission-guarded),
  `GET /admin/audit`
- Via gateway: `GET/POST /api/v1/documents`, `DELETE /api/v1/documents/:id`,
  `GET /api/v1/me`

## Configuration

All configuration comes from environment variables validated by zod at startup —
see [`.env.example`](.env.example) for every variable with comments.
Key production settings:

- `KMS_MASTER_KEY` (**required in production**) – wraps Ed25519 signing keys at rest
- `GATEWAY_SHARED_SECRET` – proof-of-origin between gateway and resource API
- `CORS_ORIGINS` – strict allow-list of browser origins
- `JWT_ISSUER` – logical issuer embedded in tokens and checked by verifiers

## Production hardening checklist

- [ ] Terminate TLS at the edge (or mesh mTLS); set `TRUST_PROXY` correctly
- [ ] mTLS or private subnet between gateway and services (shared secret is defense-in-depth, not the only wall)
- [ ] Swap `LocalKeyProvider` for AWS KMS / Azure KV / GCP KMS / Vault (`KMS_PROVIDER`)
- [ ] Rotate signing keys periodically (`rotateSigningKey`); JWKS serves old + new during rollover
- [ ] Real SMTP provider instead of MailHog (`EMAIL_PROVIDER=smtp`)
- [ ] Ship pino logs + audit log to a SIEM; alert on `REFRESH_TOKEN_REUSE_DETECTED`, `USER_LOCKED`, risk HIGH events
- [ ] Set tight per-bucket rate limits and consider WAF/DDoS protection in front of the gateway
- [ ] Run Postgres backups + test restores; Redis persistence enabled by compose
- [ ] CI running lint/typecheck/build/test on every PR
