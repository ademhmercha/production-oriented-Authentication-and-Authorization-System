/** MFA (TOTP) challenge view. */

import { el, toast, bindForm, disableButton } from '../ui.js';
import { verifyMfa } from '../api.js';
import { setTokens } from '../tokens.js';
import type { RouteContext, ViewFactory } from '../router.js';

export function makeMfa(ctx: RouteContext): Node {
  const challengeId = ctx.params.get('challenge') ?? '';

  const root = el('div', { class: 'auth' });

  const form = el(
    'form',
    { class: 'card card--enter', id: 'mfa-form', novalidate: '' },
    el('div', { class: 'card__brand' }, el('span', { class: 'brand-mark' }, '◈'), el('span', { class: 'brand-name' }, 'Identity Platform')),
    el('h1', { class: 'card__title' }, 'Two-factor authentication'),
    el('p', { class: 'card__subtitle' }, 'Enter the 6-digit code from your authenticator app.'),
    el('label', { class: 'field' },
      el('span', { class: 'field__label' }, 'Six-digit code'),
      el('div', { class: 'otp' },
        ...Array.from({ length: 6 }, () => el('input', { class: 'otp__box', type: 'tel', inputmode: 'numeric', pattern: '[0-9]*', maxlength: '1' })),
      ),
    ),
    el('button', { class: 'btn btn--primary btn--block', type: 'submit' },
      el('span', { class: 'spinner', 'aria-hidden': 'true' }),
      el('span', { class: 'btn__label' }, 'Verify'),
    ),
    el('div', { class: 'card__footer' },
      el('button', { class: 'link', type: 'button' }, 'Back to sign in'),
    ),
  );

  const boxes = Array.from(form.querySelectorAll<HTMLInputElement>('.otp__box'));
  const submitBtn = form.querySelector<HTMLButtonElement>('button[type="submit"]');

  // Auto-advance between OTP boxes and auto-submit on the 6th digit.
  boxes.forEach((box, i) => {
    box.addEventListener('input', () => {
      box.value = box.value.replace(/\D/g, '').slice(0, 1);
      if (box.value && i < boxes.length - 1) boxes[i + 1].focus();
      if (i === boxes.length - 1 && box.value && boxes.every((b) => b.value)) form.requestSubmit();
    });
    box.addEventListener('keydown', (e) => {
      if (e.key === 'Backspace' && !box.value && i > 0) boxes[i - 1].focus();
    });
    box.addEventListener('paste', (e) => {
      e.preventDefault();
      const text = e.clipboardData?.getData('text').replace(/\D/g, '').slice(0, 6) ?? '';
      text.split('').forEach((ch, idx) => {
        if (idx < boxes.length) {
          boxes[idx].value = ch;
          if (idx === boxes.length - 1) form.requestSubmit();
          else if (idx < boxes.length - 1) boxes[idx + 1].focus();
        }
      });
    });
  });

  form.querySelector<HTMLButtonElement>('.card__footer button')?.addEventListener('click', () => ctx.navigate('/login'));

  bindForm(form, async () => {
    const code = boxes.map((b) => b.value).join('');
    if (code.length !== 6) return;
    if (submitBtn) disableButton(submitBtn, true);
    try {
      const res = await verifyMfa(challengeId, code);
      setTokens(res.access_token, res.refresh_token);
      toast('Authenticated', 'success');
      ctx.navigate('/account');
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Verification failed';
      toast(message, 'error');
      boxes.forEach((b) => (b.value = ''));
      boxes[0]?.focus();
    } finally {
      if (submitBtn) disableButton(submitBtn, false);
    }
  });

  root.appendChild(form);
  requestAnimationFrame(() => boxes[0]?.focus());
  return root;
}

export const mfaView: ViewFactory = async (ctx) => makeMfa(ctx);