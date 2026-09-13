/** Password recovery view: request a reset token, then set a new password. */

import { el, toast, bindForm, disableButton, inputError } from '../ui.js';
import { forgotPassword, resetPassword } from '../api.js';
import type { RouteContext, ViewFactory } from '../router.js';

export function makeReset(ctx: RouteContext): Node {
  const stageToken = ctx.params.get('token') ?? '';
  const root = el('div', { class: 'auth' });

  if (stageToken) return makeResetConfirm(ctx, root, stageToken);

  const form = el(
    'form',
    { class: 'card card--enter', id: 'forgot-form', novalidate: '' },
    el('div', { class: 'card__brand' }, el('span', { class: 'brand-mark' }, '◈'), el('span', { class: 'brand-name' }, 'Identity Platform')),
    el('h1', { class: 'card__title' }, 'Reset your password'),
    el('p', { class: 'card__subtitle' }, 'Enter your email and we will send you a reset token via email inbox.'),
    el('label', { class: 'field' },
      el('span', { class: 'field__label' }, 'Email'),
      el('input', { class: 'input', type: 'email', name: 'email', placeholder: 'you@example.com', required: '', autocomplete: 'email' as string }),
    ),
    el('button', { class: 'btn btn--primary btn--block', type: 'submit' },
      el('span', { class: 'spinner', 'aria-hidden': 'true' }),
      el('span', { class: 'btn__label' }, 'Send reset code'),
    ),
    el('div', { class: 'card__footer' },
      el('button', { class: 'link', type: 'button' }, 'Back to sign in'),
    ),
  );

  const emailInput = form.querySelector<HTMLInputElement>('input[name="email"]');
  const submitBtn = form.querySelector<HTMLButtonElement>('button[type="submit"]');

  form.querySelector<HTMLButtonElement>('.card__footer button')?.addEventListener('click', () => ctx.navigate('/login'));

  bindForm(form, async (data) => {
    if (emailInput && data.email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(data.email)) {
      inputError(emailInput, 'Enter a valid email address');
      return;
    }
    if (emailInput) inputError(emailInput, null);
    if (submitBtn) disableButton(submitBtn, true);
    try {
      await forgotPassword(data.email);
      toast('If that email exists, a reset code is on its way', 'info');
      ctx.navigate(`/reset?token=&${new URLSearchParams({ email: data.email })}`);
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Request failed';
      toast(message, 'error');
    } finally {
      if (submitBtn) disableButton(submitBtn, false);
    }
  });

  root.appendChild(form);
  return root;
}

function makeResetConfirm(ctx: RouteContext, root: HTMLElement, token: string): Node {
  const form = el(
    'form',
    { class: 'card card--enter', id: 'reset-form', novalidate: '' },
    el('div', { class: 'card__brand' }, el('span', { class: 'brand-mark' }, '◈'), el('span', { class: 'brand-name' }, 'Identity Platform')),
    el('h1', { class: 'card__title' }, 'Choose a new password'),
    el('p', { class: 'card__subtitle' }, 'Enter the reset token from your email and choose a new strong password.'),
    el('label', { class: 'field' },
      el('span', { class: 'field__label' }, 'Reset token'),
      el('input', { class: 'input', type: 'text', name: 'token', value: token, required: '', autocomplete: 'off' as string }),
    ),
    el('label', { class: 'field' },
      el('span', { class: 'field__label' }, 'New password'),
      el('input', { class: 'input', type: 'password', name: 'password', placeholder: 'At least 12 characters', required: '', autocomplete: 'new-password' as string }),
    ),
    el('button', { class: 'btn btn--primary btn--block', type: 'submit' },
      el('span', { class: 'spinner', 'aria-hidden': 'true' }),
      el('span', { class: 'btn__label' }, 'Reset password'),
    ),
    el('div', { class: 'card__footer' },
      el('button', { class: 'link', type: 'button' }, 'Back to sign in'),
    ),
  );

  const submitBtn = form.querySelector<HTMLButtonElement>('button[type="submit"]');
  form.querySelector<HTMLButtonElement>('.card__footer button')?.addEventListener('click', () => ctx.navigate('/login'));

  bindForm(form, async (data) => {
    if (submitBtn) disableButton(submitBtn, true);
    try {
      await resetPassword(data.token, data.password);
      toast('Password reset — sign in with your new password', 'success');
      ctx.navigate('/login');
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Reset failed';
      toast(message, 'error');
    } finally {
      if (submitBtn) disableButton(submitBtn, false);
    }
  });

  root.appendChild(form);
  return root;
}

export const resetView: ViewFactory = async (ctx) => makeReset(ctx);