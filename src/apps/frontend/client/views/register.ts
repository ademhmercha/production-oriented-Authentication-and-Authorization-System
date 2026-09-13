/** Registration view with password strength meter. */

import { el, toast, bindForm, disableButton, inputError } from '../ui.js';
import { register } from '../api.js';
import type { RouteContext, ViewFactory } from '../router.js';

const METER_LABELS = ['Too weak', 'Weak', 'Fair', 'Good', 'Strong'];

function scorePassword(password: string): number {
  let score = 0;
  if (password.length >= 12) score += 1;
  if (password.length >= 16) score += 1;
  if (/[a-z]/.test(password) && /[A-Z]/.test(password)) score += 1;
  if (/\d/.test(password)) score += 1;
  if (/[^A-Za-z0-9]/.test(password)) score += 1;
  return Math.min(score, 4);
}

export function makeRegister(ctx: RouteContext): Node {
  const root = el('div', { class: 'auth' });

  const form = el(
    'form',
    { class: 'card card--enter', id: 'register-form', novalidate: '' },
    el('div', { class: 'card__brand' }, el('span', { class: 'brand-mark' }, '◈'), el('span', { class: 'brand-name' }, 'Identity Platform')),
    el('h1', { class: 'card__title' }, 'Create your account'),
    el('p', { class: 'card__subtitle' }, 'Register to access protected resources.'),
    el('div', { class: 'field-row' },
      el('label', { class: 'field' },
        el('span', { class: 'field__label' }, 'First name'),
        el('input', { class: 'input', type: 'text', name: 'first_name', placeholder: 'Ada', autocomplete: 'given-name' as string }),
      ),
      el('label', { class: 'field' },
        el('span', { class: 'field__label' }, 'Last name'),
        el('input', { class: 'input', type: 'text', name: 'last_name', placeholder: 'Lovelace', autocomplete: 'family-name' as string }),
      ),
    ),
    el('label', { class: 'field' },
      el('span', { class: 'field__label' }, 'Email'),
      el('input', { class: 'input', type: 'email', name: 'email', placeholder: 'you@example.com', required: '', autocomplete: 'email' as string }),
    ),
    el('label', { class: 'field' },
      el('span', { class: 'field__label' }, 'Password'),
      el('input', { class: 'input', type: 'password', name: 'password', placeholder: 'At least 12 characters', required: '', autocomplete: 'new-password' as string }),
      el('div', { class: 'meter' },
        el('div', { class: 'meter__bar', 'data-level': '0' }),
        el('div', { class: 'meter__label' }, METER_LABELS[0]),
      ),
    ),
    el('button', { class: 'btn btn--primary btn--block', type: 'submit' },
      el('span', { class: 'spinner', 'aria-hidden': 'true' }),
      el('span', { class: 'btn__label' }, 'Create account'),
    ),
    el('div', { class: 'card__footer' },
      el('span', {}, 'Already have an account?'),
      el('button', { class: 'link', type: 'button' }, 'Sign in'),
    ),
  );

  const passwordInput = form.querySelector<HTMLInputElement>('input[name="password"]');
  const meterBar = form.querySelector<HTMLElement>('.meter__bar');
  const meterLabel = form.querySelector<HTMLElement>('.meter__label');
  const emailInput = form.querySelector<HTMLInputElement>('input[name="email"]');
  const submitBtn = form.querySelector<HTMLButtonElement>('button[type="submit"]');

  passwordInput?.addEventListener('input', () => {
    const level = scorePassword(passwordInput.value);
    if (meterBar) meterBar.dataset.level = String(level);
    if (meterLabel) meterLabel.textContent = passwordInput.value ? METER_LABELS[level] : METER_LABELS[0];
  });

  form.querySelector<HTMLButtonElement>('.card__footer button')?.addEventListener('click', () => ctx.navigate('/login'));

  bindForm(form, async (data) => {
    if (emailInput && data.email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(data.email)) {
      inputError(emailInput, 'Enter a valid email address');
      return;
    }
    if (emailInput) inputError(emailInput, null);
    if (passwordInput && scorePassword(data.password) < 2) {
      inputError(passwordInput, 'Password must be at least 12 characters with upper, lower and digits.');
      return;
    }
    if (passwordInput) inputError(passwordInput, null);
    if (submitBtn) disableButton(submitBtn, true);
    try {
      await register({
        email: data.email,
        password: data.password,
        first_name: data.first_name ?? undefined,
        last_name: data.last_name ?? undefined,
      });
      toast('Registration submitted — check your inbox for a verification link', 'success');
      ctx.navigate('/login');
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Registration failed';
      toast(message, 'error');
    } finally {
      if (submitBtn) disableButton(submitBtn, false);
    }
  });

  root.appendChild(form);
  return root;
}

export const registerView: ViewFactory = async (ctx) => makeRegister(ctx);