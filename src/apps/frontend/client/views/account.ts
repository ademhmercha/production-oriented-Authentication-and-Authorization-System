/** Account dashboard: verified identity, roles/scopes and MFA management. */

import { el, toast, disableButton } from '../ui.js';
import { fetchMe, fetchGatewayIdentity, logout, enrollTotp, confirmTotp, disableTotp } from '../api.js';
import { getRefreshToken, clearTokens, hasAccessToken } from '../tokens.js';
import type { RouteContext, ViewFactory } from '../router.js';

interface Profile {
  id: string;
  email: string;
  first_name?: string | null;
  last_name?: string | null;
  status: string;
  roles: string[];
  permissions: string[];
  mfa_enabled: boolean;
}

interface GatewayIdentity {
  userId?: string;
  scopes: string[];
  roles: string[];
  requestId?: string;
}

export function makeAccount(ctx: RouteContext): Node {
  const root = el('div', { class: 'account' });

  if (!hasAccessToken()) {
    ctx.navigate('/login');
    return root;
  }

  const loading = el('div', { class: 'account__placeholder card--enter' },
    el('div', { class: 'spinner spinner--lg' }),
    el('p', {}, 'Loading your session…'),
  );
  root.appendChild(loading);

  void Promise.all([fetchMe(), fetchGatewayIdentity()])
    .then(async ([profile, gateway]) => {
      while (root.firstChild) root.removeChild(root.firstChild);
      render(ctx, root, () => void reload(ctx, root), profile, gateway);
    })
    .catch((err: unknown) => {
      const message = err instanceof Error ? err.message : 'Could not load profile';
      toast(message, 'error');
      clearTokens();
      ctx.navigate('/login');
    });

  return root;
}

async function reload(ctx: RouteContext, root: HTMLElement): Promise<void> {
  try {
    const [profile, gateway] = await Promise.all([fetchMe(), fetchGatewayIdentity()]);
    while (root.firstChild) root.removeChild(root.firstChild);
    render(ctx, root, () => void reload(ctx, root), profile, gateway);
  } catch (err: unknown) {
    toast(err instanceof Error ? err.message : 'Could not refresh profile', 'error');
  }
}

function render(
  ctx: RouteContext,
  root: HTMLElement,
  reload: () => void,
  profile: Profile,
  gateway: GatewayIdentity,
): void {
  const displayName = [profile.first_name, profile.last_name].filter(Boolean).join(' ') || profile.email;

  const header = el('header', { class: 'account__head card--enter' },
    el('div', { class: 'avatar' }, profile.email.slice(0, 2).toUpperCase()),
    el('div', { class: 'account__who' },
      el('h1', { class: 'account__name' }, displayName),
      el('p', { class: 'account__email' }, profile.email),
    ),
    el('div', { class: 'account__actions' },
      el('button', { class: 'btn btn--ghost', type: 'button', id: 'logout-btn' }, 'Sign out'),
    ),
  );

  const statusPill = el('span', { class: `pill pill--${profile.status === 'active' ? 'ok' : 'warn'}` }, profile.status);

  const identityCard = el('section', { class: 'card' },
    el('div', { class: 'card__row' },
      el('h2', { class: 'card__title' }, 'Identity (auth-server)'),
      statusPill,
    ),
    el('dl', { class: 'kv' },
      el('div', { class: 'kv__row' }, el('dt', {}, 'User ID'), el('dd', { class: 'mono' }, profile.id)),
      el('div', { class: 'kv__row' }, el('dt', {}, 'MFA'), el('dd', {}, profile.mfa_enabled ? 'Enabled' : 'Not enrolled')),
      el('div', { class: 'kv__row' }, el('dt', {}, 'Roles'), el('dd', {}, profile.roles.map((r) => el('span', { class: 'chip' }, r)))),
      el('div', { class: 'kv__row' },
        el('dt', {}, 'Permissions'),
        el('dd', {}, profile.permissions.length
          ? profile.permissions.map((p) => el('span', { class: 'chip chip--dim' }, p))
          : el('span', { class: 'muted' }, 'None'))),
    ),
  );

  const gatewayCard = el('section', { class: 'card' },
    el('h2', { class: 'card__title' }, 'Identity via gateway'),
    el('p', { class: 'card__hint' }, 'Returned by the zero-trust resource API after gateway token verification.'),
    el('dl', { class: 'kv' },
      el('div', { class: 'kv__row' }, el('dt', {}, 'Subject (X-User-Id)'), el('dd', { class: 'mono' }, gateway.userId ?? '—')),
      el('div', { class: 'kv__row' }, el('dt', {}, 'Scopes'), el('dd', {}, gateway.scopes.map((s) => el('span', { class: 'chip chip--primary' }, s)))),
      el('div', { class: 'kv__row' },
        el('dt', {}, 'Roles'),
        el('dd', {}, gateway.roles.length ? gateway.roles.map((r) => el('span', { class: 'chip' }, r)) : el('span', { class: 'muted' }, 'None'))),
      el('div', { class: 'kv__row' }, el('dt', {}, 'Request ID'), el('dd', { class: 'mono' }, gateway.requestId ?? '—')),
    ),
  );

  const mfaCard = el('section', { class: 'card' });
  renderMfaCard(mfaCard, profile, reload);

  root.append(header, identityCard, gatewayCard, mfaCard);

  root.querySelector<HTMLButtonElement>('#logout-btn')?.addEventListener('click', () => void doLogout(ctx));
}

async function doLogout(ctx: RouteContext): Promise<void> {
  const refresh = getRefreshToken();
  try {
    if (refresh) await logout(refresh);
  } catch {
    // Best-effort: clear locally regardless of server outcome.
  }
  clearTokens();
  toast('Signed out', 'info');
  ctx.navigate('/login');
}

function renderMfaCard(card: HTMLElement, profile: Profile, reload: () => void): void {
  while (card.firstChild) card.removeChild(card.firstChild);
  card.appendChild(el('h2', { class: 'card__title' }, 'Multi-factor authentication'));

  if (profile.mfa_enabled) {
    const form = el('form', { class: 'mfa-form', novalidate: '' },
      el('p', { class: 'card__hint' }, 'TOTP is active on this account. To remove it, enter the current code.'),
      el('div', { class: 'field-row' },
        el('label', { class: 'field' },
          el('span', { class: 'field__label' }, 'Six-digit code'),
          el('input', { class: 'input', type: 'tel', name: 'code', inputmode: 'numeric', pattern: '[0-9]*', maxlength: '6', required: '' }),
        ),
        el('button', { class: 'btn btn--danger mfa-ctrl', type: 'submit' }, 'Disable'),
      ),
    );
    form.addEventListener('submit', (e) => {
      e.preventDefault();
      const code = form.querySelector<HTMLInputElement>('input[name="code"]')?.value.trim() ?? '';
      const btn = form.querySelector<HTMLButtonElement>('button[type="submit"]');
      if (!btn) return;
      disableButton(btn, true);
      void disableTotp(code)
        .then(() => {
          toast('MFA disabled', 'success');
          reload();
        })
        .catch((err: unknown) => {
          toast(err instanceof Error ? err.message : 'Could not disable MFA', 'error');
          disableButton(btn, false);
        });
    });
    card.appendChild(form);
    return;
  }

  const enrollBtn = el('button', { class: 'btn btn--primary', type: 'button' }, 'Enroll TOTP');
  card.appendChild(enrollBtn);
  card.appendChild(el('p', { class: 'card__hint' }, 'Add an authenticator app for second-factor verification on sign in.'));

  enrollBtn.addEventListener('click', () => {
    disableButton(enrollBtn, true);
    void enrollTotp()
      .then(({ otpauth_url, qr_data_url }) => renderEnroll(card, otpauth_url, qr_data_url, reload))
      .catch((err: unknown) => {
        toast(err instanceof Error ? err.message : 'Enrollment failed', 'error');
        disableButton(enrollBtn, false);
      });
  });
}

function renderEnroll(card: HTMLElement, otpauthUrl: string, qrDataUrl: string, reload: () => void): void {
  while (card.firstChild) card.removeChild(card.firstChild);
  card.appendChild(el('h2', { class: 'card__title' }, 'Scan with your authenticator'));
  card.appendChild(el('img', { class: 'qr', src: qrDataUrl, alt: 'TOTP QR code' }));
  card.appendChild(
    el('p', { class: 'card__hint mono', style: 'word-break:break-all;font-size:.78rem' }, otpauthUrl.replace(/^otpauth:\/\/[^?]+\?/, '')),
  );

  const form = el('form', { class: 'mfa-form', novalidate: '' },
    el('div', { class: 'field-row' },
      el('label', { class: 'field' },
        el('span', { class: 'field__label' }, 'Six-digit code'),
        el('input', { class: 'input', type: 'tel', name: 'code', inputmode: 'numeric', pattern: '[0-9]*', maxlength: '6', required: '' }),
      ),
      el('button', { class: 'btn btn--primary mfa-ctrl', type: 'submit' }, 'Verify & enable'),
    ),
  );
  form.addEventListener('submit', (e) => {
    e.preventDefault();
    const code = form.querySelector<HTMLInputElement>('input[name="code"]')?.value.trim() ?? '';
    const btn = form.querySelector<HTMLButtonElement>('button[type="submit"]');
    if (!btn) return;
    disableButton(btn, true);
    void confirmTotp(code)
      .then(async () => {
        toast('MFA enabled', 'success');
        reload();
      })
      .catch((err: unknown) => {
        toast(err instanceof Error ? err.message : 'Verification failed', 'error');
        disableButton(btn, false);
      });
  });
  card.appendChild(form);
}

export const accountView: ViewFactory = async (ctx) => makeAccount(ctx);