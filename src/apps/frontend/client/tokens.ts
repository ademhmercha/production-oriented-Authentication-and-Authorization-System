/** Token persistence for the SPA.
 *
 * The platform intentionally does not use cookies - tokens are returned in
 * the JSON body and must be presented via the Authorization header. The SPA
 * therefore keeps them in localStorage. This trade-off (XSS-accessible) is
 * acceptable for a demo UI; a hardened deployment would serve the SPA from
 * the auth-server and set httpOnly cookies instead.
 */

const ACCESS_KEY = 'identity.access_token';
const REFRESH_KEY = 'identity.refresh_token';

export function getAccessToken(): string | null {
  return localStorage.getItem(ACCESS_KEY);
}

export function getRefreshToken(): string | null {
  return localStorage.getItem(REFRESH_KEY);
}

export function setTokens(accessToken: string, refreshToken: string): void {
  localStorage.setItem(ACCESS_KEY, accessToken);
  localStorage.setItem(REFRESH_KEY, refreshToken);
}

export function clearTokens(): void {
  localStorage.removeItem(ACCESS_KEY);
  localStorage.removeItem(REFRESH_KEY);
}

export function hasAccessToken(): boolean {
  return getAccessToken() !== null;
}