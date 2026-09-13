/** Runtime configuration injected by the frontend server at /config.js. */

export interface AppConfig {
  /** Base URL for auth-server calls (empty = same origin). */
  authBase: string;
  /** Base URL for api-gateway calls (empty = same origin). */
  apiBase: string;
  version: string;
}

declare global {
  interface Window {
    __APP_CONFIG__?: Partial<AppConfig>;
  }
}

export function readConfig(): AppConfig {
  const raw = window.__APP_CONFIG__ ?? {};
  return {
    authBase: (raw.authBase ?? '').replace(/\/+$/, ''),
    apiBase: (raw.apiBase ?? '').replace(/\/+$/, ''),
    version: raw.version ?? 'dev',
  };
}