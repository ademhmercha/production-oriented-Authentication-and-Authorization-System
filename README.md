# Identity Platform — Authentication & Authorization System

![CI](https://github.com/ademhmercha/production-oriented-Authentication-and-Authorization-System/actions/workflows/ci.yml/badge.svg)
![Node](https://img.shields.io/badge/node-%3E%3D20-339933?logo=nodedotjs&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-blue)

Centralized AuthN/AuthZ platform built with **Express.js + TypeScript**: OAuth 2.0 / OIDC,
EdDSA JWTs, refresh rotation with theft detection, RBAC, TOTP MFA, risk engine and a
zero-trust API gateway — no third-party IdP.

## Architecture

```
                        +--------------------+
   clients ----------> |    api-gateway     |  verifies JWTs against JWKS,
        :3000          |      (:3000)       |  enforces scopes, strips/injects
                        +---------+----------+  identity headers
               +------------------+------------------+
               v                                     v
    +--------------------+               +--------------------+
    |    auth-server     |               |    resource-api    |
    |      (:3001)       |               |      (:3002)       |
    | authn + oauth2 +   |               |  zero-trust API:   |
    | mfa + rbac + admin |               |  trusts NO caller  |
    +---------+----------+               |  directly          |
              v                          +--------------------+
    +---------+----+   +-------+
    |   postgres   |  | redis |  sessions - rate limits - MFA challenges
    |    (:5432)   |   |(:6379)|  risk signals - jti denylist
    +--------------+   +-------+
```

**How a request flows:**

1. **Login/identity** — everything identity-related lives in `auth-server`: registration +
   email verification, login (Argon2id), lockout, password reset, MFA enrollment and
   challenges, role assignment. Successful auth issues an **access token (Ed25519 JWT)**
   plus a **refresh token** bound to a server-side session.
2. **Edge verification** — `api-gateway` never shares signing keys with anyone. It fetches
   public keys from the auth-server's **JWKS endpoint** (`/.well-known/jwks.json`) and
   verifies signature, issuer, audience and revocation (Redis jti denylist) itself.
3. **Zero trust downstream** — the gateway **strips** any inbound `X-User-*` headers
   (spoofing is impossible) and re-injects only verified claims (`X-User-Id`,
   `X-User-Scopes`, `X-User-Roles`, `X-Token-Sid`). It also proves its own origin to
   internal services with a shared secret.
4. **Resource APIs** — `resource-api` accepts requests *only* via the gateway (origin
   secret + verified identity headers) and enforces scope-based authorization per route
   plus row-level ownership (users see only their data).
5. **State** — Postgres is the source of truth (users, clients, codes, refresh chains,
   audit log); Redis holds ephemeral state: sessions cache, rate-limit windows, MFA
   challenges, risk signals and the token-revocation denylist.

**Why this shape:** services scale and fail independently; tokens are self-contained so
the gateway adds no auth round-trips; revocation stays *immediate* despite stateless JWTs
via the Redis denylist; new resource services can be added without touching auth code —
they just trust the gateway contract.

## Security essentials

- Passwords: Argon2id + policy + common-password denylist
- Tokens: Ed25519 JWTs, signing keys AES-256-GCM-wrapped under `KMS_MASTER_KEY`, rotatable
- Refresh chains: single-use rotation; **replay of an old token revokes the whole family
  and session** (theft detection)
- OAuth2/OIDC: Authorization Code + PKCE (S256 enforced), client_credentials for machines,
  introspection (RFC 7662), revocation (RFC 7009), discovery + id_token
- RBAC: roles -> permissions -> scopes embedded in tokens; guarded admin API
- Rate limiting on every sensitive bucket; append-only audit log with secret redaction

## Quick start

```powershell
# secrets (.env is gitignored)
node -e "console.log('KMS_MASTER_KEY='+require('crypto').randomBytes(32).toString('base64'))" >> .env
node -e "console.log('GATEWAY_SHARED_SECRET='+require('crypto').randomBytes(32).toString('base64'))" >> .env

docker compose up -d --build     # migrations + seeds run automatically

# auth-server http://localhost:3001 (Swagger at /docs)
# gateway     http://localhost:3000 (/api/v1)
# MailHog     http://localhost:8025
```

Seed admin: `admin@auth.local` (one-time password printed by the seed, or set
`ADMIN_PASSWORD` in `.env`).

## Verify & test

```powershell
npm test                              # 46 unit + integration tests
powershell -File scripts\verify-all.ps1   # 28 live checks against the running stack
```

Configuration comes from zod-validated env vars — see [`.env.example`](.env.example).
Production must set `KMS_MASTER_KEY`; recommended extras: TLS at the edge, real SMTP,
managed KMS/Vault, SIEM shipping of audit events.
