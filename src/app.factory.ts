/**
 * Auth Server application factory.
 *
 * Composition root for the Authorization Server: wires infrastructure
 * (Postgres, Redis, KMS, email) into module services and mounts routes.
 * Kept as a pure factory so tests can build isolated instances with
 * overridden dependencies.
 */
import express, { Express } from 'express';
import helmet from 'helmet';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import { loadConfig } from './config';
import { logger } from './common/logger';
import { requestIdMiddleware } from './common/middleware/request-id';
import { errorHandler, notFoundHandler } from './common/middleware/error-handler';
import { createHealthRouter } from './modules/health/health.routes';
import { Database } from './infrastructure/database/pool';
import { RedisService } from './infrastructure/redis/redis.service';
import { KeyManagementService } from './modules/keys/kms.types';
import { createKeysRoutes } from './modules/keys/keys.routes';
import { AuditLogService } from './modules/audit/audit.service';
import { EmailProvider } from './modules/email/email.types';
import { UserRepository } from './modules/users/user.repository';
import { EmailTokenService } from './modules/users/email-token.service';
import { UserService } from './modules/users/user.service';
import { AuthService } from './modules/auth/auth.service';
import { JwtService } from './modules/tokens/jwt.service';
import { RefreshTokenService } from './modules/tokens/refresh-token.service';
import { SessionRepository } from './modules/sessions/session.repository';
import { MfaService } from './modules/mfa/mfa.service';
import { RulesRiskEngine } from './modules/risk/rules-risk.engine';
import { RiskEventRepository } from './modules/risk/risk-event.repository';
import { createAuthRoutes } from './modules/auth/auth.routes';
import { createMfaRoutes } from './modules/mfa/mfa.routes';
import { RbacRepository } from './modules/roles/rbac.repository';
import { createAdminRoutes } from './modules/roles/admin.routes';
import { ClientRepository } from './modules/clients/client.repository';
import { createClientsRoutes } from './modules/clients/clients.routes';
import { AuthorizationCodeRepository } from './modules/oauth/authorization-code.repository';
import { OAuthService } from './modules/oauth/oauth.service';
import { TokenRevocationService } from './modules/tokens/token-revocation';
import { createOAuthRoutes } from './modules/oauth/oauth.routes';
import { createOidcRoutes } from './modules/oauth/oidc.routes';
import { createDiscoveryRoutes } from './modules/oauth/discovery.routes';

export interface Services {
  db: Database;
  redis: RedisService;
  kms: KeyManagementService;
  audit: AuditLogService;
  jwt: JwtService;
  users: UserRepository;
  userService: UserService;
  authService: AuthService;
  mfa: MfaService;
}

export interface AuthServerDeps {
  db: Database;
  redis: RedisService;
  kms: KeyManagementService;
  email: EmailProvider;
  /** Override for tests; defaults to the Postgres-backed sink. */
  audit?: AuditLogService;
}

export function buildServices(deps: AuthServerDeps): Services {
  const config = loadConfig();

  const audit = deps.audit ?? AuditLogService.withDefaults(deps.db);
  const users = new UserRepository(deps.db);
  const emailTokens = new EmailTokenService(deps.db);
  const userService = new UserService(users, emailTokens, audit, deps.email);

  const jwt = new JwtService(deps.kms, {
    issuer: config.JWT_ISSUER,
    audience: config.JWT_AUDIENCE,
    defaultTtlSeconds: config.ACCESS_TOKEN_TTL,
  });
  const refreshTokens = new RefreshTokenService(deps.db);
  const sessions = new SessionRepository(deps.db, deps.redis);
  const mfa = new MfaService(deps.db, deps.kms, deps.redis);
  const riskEngine = new RulesRiskEngine(deps.redis);
  const riskEvents = new RiskEventRepository(deps.db);

  const authService = new AuthService(
    users,
    sessions,
    refreshTokens,
    jwt,
    mfa,
    riskEngine,
    riskEvents,
    audit,
    emailTokens,
    deps.email,
    deps.redis,
  );

  return {
    db: deps.db,
    redis: deps.redis,
    kms: deps.kms,
    audit,
    jwt,
    users,
    userService,
    authService,
    mfa,
  };
}

export function createAuthServer(deps: AuthServerDeps): Express {
  const services = buildServices(deps);
  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', 1);

  // Security headers (helmet) + strict CORS allow-list.
  app.use(helmet());
  app.use(
    cors({
      origin: loadConfig().corsOriginsList,
      credentials: true,
      methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    }),
  );

  app.use(requestIdMiddleware());
  // JSON for API endpoints + urlencoded for OAuth2 form posts (RFC 6749 §4.1.3).
  app.use(express.json({ limit: '100kb' }));
  app.use(express.urlencoded({ extended: false, limit: '100kb' }));
  app.use(cookieParser());

  // Public key material for JWT verification (JWKS).
  app.use(createKeysRoutes(services.kms));

  // Authentication + MFA endpoints.
  app.use('/auth', createAuthRoutes(services.authService, services.userService, services.jwt, services.redis));
  app.use('/mfa', createMfaRoutes(services.mfa, services.audit, services.jwt, services.authService));

  // Admin RBAC + user management (permission-guarded).
  const rbac = new RbacRepository(services.db);
  app.use('/admin', createAdminRoutes(rbac, services.audit, services.jwt));

  // OAuth2 client administration.
  const clientsRepo = new ClientRepository(services.db);
  app.use('/admin/clients', createClientsRoutes(clientsRepo, services.audit, services.jwt));

  // OAuth2 protocol endpoints.
  const codes = new AuthorizationCodeRepository(services.db);
  const tokenRevocation = new TokenRevocationService(services.redis);
  services.jwt.setRevocationChecker((jti) => tokenRevocation.isRevoked(jti));
  const oauth = new OAuthService(
    clientsRepo,
    codes,
    services.jwt,
    new RefreshTokenService(services.db),
    new SessionRepository(services.db, services.redis),
    services.users,
    services.audit,
    tokenRevocation,
  );
  app.use('/oauth', createOAuthRoutes(oauth, services.jwt, clientsRepo, services.audit, services.redis));

  // OIDC discovery + userinfo.
  app.use(createDiscoveryRoutes());
  app.use(createOidcRoutes(services.users, services.jwt));

  // Health/readiness probes (liveness + dependency checks).
  app.use('/health', createHealthRouter({
    readinessChecks: {
      postgres: () => services.db.ping(),
      redis: () => services.redis.ping(),
      kms: async () => {
        await services.kms.getCurrentSigningKey();
      },
    },
  }));

  return app;
}

/** Finalizes the app: 404 + central error handling must be registered last. */
export function finalizeApp(app: Express): void {
  app.use(notFoundHandler);
  app.use(errorHandler(logger));
}
