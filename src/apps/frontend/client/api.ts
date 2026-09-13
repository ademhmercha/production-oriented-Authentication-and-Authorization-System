/** Minimal JSON API client for the identity platform.
 *
 * Talks to the auth-server (authBase) and the api-gateway (apiBase). When a
 * public base URL is empty the request goes to the same origin, relying on
 * ingress routing. On 401 the client attempts a refresh-token rotation once
 * before giving up.
 */
import { readConfig } from './config.js';
import { getAccessToken, getRefreshToken, clearTokens, setTokens } from './tokens.js';

export interface ApiErrorBody {
  error: string;
  message: string;
  details?: unknown;
  request_id?: string;
}

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly details?: unknown;
  readonly requestId?: string;

  constructor(status: number, body: ApiErrorBody) {
    super(body.message || body.error || `Request failed (${status})`);
    this.name = 'ApiError';
    this.status = status;
    this.code = body.error;
    this.details = body.details;
    this.requestId = body.request_id;
  }
}

/** Token bundle returned by login, MFA challenge resolution and refresh. */
export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token: string;
  refresh_expires_at?: string;
  scope: string;
  roles?: string[];
}

export interface SessionUser {
  id: string;
  email: string;
  status: string;
}

function baseFor(api: 'auth' | 'api'): string {
  const cfg = readConfig();
  return api === 'api' ? cfg.apiBase : cfg.authBase;
}

async function parseBody(res: Response): Promise<unknown> {
  const text = await res.text();
  if (!text) return undefined;
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

interface RequestOptions {
  api?: 'auth' | 'api';
  method?: string;
  body?: unknown;
  /** Include a Bearer token (defaults to true). */
  bearer?: boolean;
  /** Allow a single refresh-on-401 retry (defaults to true). */
  allowRefresh?: boolean;
  /** Override the refresh token when rotating (internal). */
  refreshToken?: string;
}

export async function apiRequest<T>(path: string, opts: RequestOptions = {}): Promise<T> {
  const {
    api = 'auth',
    method = 'GET',
    body,
    bearer = true,
    allowRefresh = true,
  } = opts;

  const headers: Record<string, string> = { Accept: 'application/json' };
  const token = bearer ? getAccessToken() : null;
  if (token) headers.Authorization = `Bearer ${token}`;
  if (body !== undefined) headers['Content-Type'] = 'application/json';

  const res = await fetch(`${baseFor(api)}${path}`, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
    credentials: 'same-origin',
  });

  if (res.status === 401 && allowRefresh && !opts.refreshToken) {
    const refreshed = await tryRefresh();
    if (refreshed) return apiRequest<T>(path, { ...opts, allowRefresh: false });
    clearTokens();
    throw new ApiError(res.status, await parseBody(res).catch(() => ({ error: 'UNAUTHENTICATED', message: 'Session expired' })) as ApiErrorBody);
  }

  const payload = await parseBody(res).catch(() => undefined);
  if (!res.ok) {
    throw new ApiError(res.status, (payload ?? { error: 'REQUEST_FAILED', message: `Request failed (${res.status})` }) as ApiErrorBody);
  }
  return payload as T;
}

async function tryRefresh(): Promise<boolean> {
  const refresh = getRefreshToken();
  if (!refresh) return false;
  try {
    const res = await fetch(`${baseFor('auth')}/auth/refresh`, {
      method: 'POST',
      headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
      body: JSON.stringify({ refresh_token: refresh }),
      credentials: 'same-origin',
    });
    if (!res.ok) return false;
    const body = (await res.json()) as TokenResponse;
    setTokens(body.access_token, body.refresh_token);
    return true;
  } catch {
    return false;
  }
}

// ---- Domain helpers -------------------------------------------------------

export async function login(email: string, password: string): Promise<TokenResponse & { mfa_required?: boolean; mfa_challenge_id?: string; user?: SessionUser }> {
  return apiRequest('/auth/login', { method: 'POST', body: { email, password }, bearer: false });
}

export async function verifyMfa(challengeId: string, code: string): Promise<TokenResponse> {
  return apiRequest('/mfa/verify', { method: 'POST', body: { mfa_challenge_id: challengeId, code }, bearer: false });
}

export async function register(payload: {
  email: string;
  password: string;
  first_name?: string;
  last_name?: string;
}): Promise<{ user: SessionUser & { first_name?: string | null; last_name?: string | null; mfa_required: boolean } }> {
  return apiRequest('/auth/register', { method: 'POST', body: payload, bearer: false });
}

export async function verifyEmail(token: string): Promise<{ status: string }> {
  return apiRequest('/auth/verify-email', { method: 'POST', body: { token }, bearer: false });
}

export async function forgotPassword(email: string): Promise<{ status: string }> {
  return apiRequest('/auth/forgot-password', { method: 'POST', body: { email }, bearer: false });
}

export async function resetPassword(token: string, password: string): Promise<{ status: string }> {
  return apiRequest('/auth/reset-password', { method: 'POST', body: { token, password }, bearer: false });
}

export async function logout(refreshToken: string): Promise<{ status: string; revoked_sessions?: number }> {
  return apiRequest('/auth/logout', { method: 'POST', body: { refresh_token: refreshToken } });
}

export async function fetchMe(): Promise<{
  id: string;
  email: string;
  first_name?: string | null;
  last_name?: string | null;
  status: string;
  roles: string[];
  permissions: string[];
  mfa_enabled: boolean;
}> {
  return apiRequest('/auth/me');
}

/** Gateway identity echo (proxied to the resource API). */
export async function fetchGatewayIdentity(): Promise<{
  userId?: string;
  clientId?: string;
  scopes: string[];
  roles: string[];
  requestId?: string;
}> {
  return apiRequest('/api/v1/me', { api: 'api' });
}

export async function enrollTotp(): Promise<{ otpauth_url: string; qr_data_url: string }> {
  return apiRequest('/mfa/enroll', { method: 'POST', body: {} });
}

export async function confirmTotp(code: string): Promise<{ status: string }> {
  return apiRequest('/mfa/verify', { method: 'POST', body: { code }, allowRefresh: false });
}

export async function disableTotp(code: string): Promise<{ status: string }> {
  return apiRequest('/mfa/disable', { method: 'POST', body: { code }, allowRefresh: false });
}