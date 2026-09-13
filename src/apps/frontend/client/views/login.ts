/** Login view. */

import { el, toast, bindForm, disableButton, inputError } from '../ui.js';
import { login } from '../api.js';
import { setTokens } from '../tokens.js';
import type { RouteContext, ViewFactory } from '../router.js';

export function makeLogin(ctx: RouteContext): Node {
  const root = el('div', { class: 'auth' });

  const form = el(
    'form',
    { class: 'card card--enter', id: 'login-form', novalidate: '' },
    el('div', { class: 'card__brand' }, el('span', { class: 'brand-mark' }, '◈'), el('span', { class: 'brand-name' }, 'Identity Platform')),
    el('h1', { class: 'card__title' }, 'Sign in'),
    el('p', { class: 'card__subtitle' }, 'Welcome back. Sign in to continue.'),
    el('label', { class: 'field' },
      el('span', { class: 'field__label' }, 'Email'),
      el('input', { class: 'input', type: 'email', name: 'email', placeholder: 'you@example.com', required: '', autocomplete: 'email' as string }),
    ),
    el('label', { class: 'field' },
      el('span', { class: 'field__label' }, 'Password'),
      el('input', { class: 'input', type: 'password', name: 'password', placeholder: '••••••••••••', required: '', autocomplete: 'current-password' as string }),
    ),
    el('button', { class: 'btn btn--primary btn--block', type: 'submit' },
      el('span', { class: 'spinner', 'aria-hidden': 'true' }),
      el('span', { class: 'btn__label' }, 'Sign in'),
    ),
    el('div', { class: 'card__footer' },
      el('span', {}, "Don't have an account?"),
      el('button', { class: 'link', type: 'button' }, 'Create one'),
    ),
    el('div', { class: 'card__footer card__footer--tight' },
      el('button', { class: 'link', type: 'button' }, 'Forgot password?'),
    ),
  );

  const emailInput = form.querySelector<HTMLInputElement>('input[name="email"]');
  const submitBtn = form.querySelector<HTMLButtonElement>('button[type="submit"]');

  const footerLinks = form.querySelectorAll<HTMLButtonElement>('.card__footer button');
  footerLinks[0].addEventListener('click', () => ctx.navigate('/register'));
  footerLinks[1].addEventListener('click', () => ctx.navigate('/reset'));

  bindForm(form, async (data) => {
    if (emailInput && data.email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(data.email)) {
      inputError(emailInput, 'Enter a valid email address');
      return;
    }
    if (emailInput) inputError(emailInput, null);
    if (submitBtn) disableButton(submitBtn, true);
    try {
      const res = await login(data.email, data.password);
      if (res.mfa_required && res.mfa_challenge_id) {
        ctx.navigate(`/mfa?challenge=${encodeURIComponent(res.mfa_challenge_id)}`);
        return;
      }
      setTokens(res.access_token, res.refresh_token);
      toast('Signed in successfully', 'success');
      ctx.navigate('/account');
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Sign in failed';
      toast(message, 'error');
    } finally {
      if (submitBtn) disableButton(submitBtn, false);
    }
  });

  root.appendChild(form);
  return root;
}

export const loginView: ViewFactory = async (ctx) => makeLogin(ctx);