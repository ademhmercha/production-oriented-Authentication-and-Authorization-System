/** Tiny DOM utilities: element builder, toasts, view transitions. */

export function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Record<string, string | number | boolean | null | undefined> = {},
  ...children: (Node | string | (Node | string)[])[]
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value === null || value === undefined || value === false) continue;
    if (key === 'class') node.setAttribute('class', String(value));
    else if (key === 'dataset') continue;
    else if (key.startsWith('on') && typeof value === 'function') {
      (node as unknown as Record<string, unknown>)[key] = value;
    } else if (value === true) node.setAttribute(key, '');
    else node.setAttribute(key, String(value));
  }
  const append = (child: Node | string): void => {
    if (child instanceof Node) node.appendChild(child);
    else node.appendChild(document.createTextNode(child));
  };
  for (const child of children) {
    if (Array.isArray(child)) child.forEach(append);
    else append(child);
  }
  return node;
}

export function clear(parent: HTMLElement): void {
  while (parent.firstChild) parent.removeChild(parent.firstChild);
}

export type ToastKind = 'success' | 'error' | 'info';

const TOAST_ICONS: Record<ToastKind, string> = {
  success: '✓',
  error: '✕',
  info: 'ℹ',
};

export function toast(message: string, kind: ToastKind = 'info'): void {
  const host = (document.getElementById('toasts') as HTMLElement | null) ?? mountToasts();
  const t = el(
    'div',
    { class: `toast toast--${kind}` },
    el('span', { class: 'toast__icon' }, TOAST_ICONS[kind]),
    el('span', { class: 'toast__msg' }, message),
  );
  host.appendChild(t);
  requestAnimationFrame(() => t.classList.add('toast--visible'));
  window.setTimeout(() => {
    t.classList.remove('toast--visible');
    window.setTimeout(() => t.remove(), 350);
  }, 4000);
}

function mountToasts(): HTMLElement {
  const host = el('div', { id: 'toasts', class: 'toasts' });
  document.body.appendChild(host);
  return host;
}

export function setPageTitle(title: string): void {
  document.title = title;
}

/** Fade the old view out, swap, fade the new one in. */
export async function transitionView(host: HTMLElement, build: () => Node): Promise<void> {
  host.classList.add('view--leaving');
  await delay(220);
  clear(host);
  host.classList.remove('view--leaving');
  host.appendChild(build());
  host.classList.add('view--active');
  requestAnimationFrame(() => requestAnimationFrame(() => host.classList.remove('view--active')));
}

export function delay(ms: number): Promise<void> {
  return new Promise((resolve) => window.setTimeout(resolve, ms));
}

export function formData(form: HTMLFormElement): Record<string, string> {
  const out: Record<string, string> = {};
  for (const field of new FormData(form).entries()) {
    const [name, value] = field as [string, string];
    if (value !== '') out[name] = value;
  }
  return out;
}

export function disableButton(button: HTMLButtonElement, busy: boolean): void {
  button.disabled = busy;
  button.classList.toggle('is-busy', busy);
  const spinner = (button as HTMLButtonElement & { querySelector: (s: string) => Element | null }).querySelector('.spinner');
  if (spinner) spinner.setAttribute('aria-hidden', String(busy));
}

export function bindForm(
  form: HTMLFormElement,
  onSubmit: (data: Record<string, string>) => void | Promise<void>,
): void {
  form.addEventListener('submit', (event) => {
    event.preventDefault();
    void onSubmit(formData(form));
  });
}

export function inputError(input: HTMLInputElement, message: string | null): void {
  input.classList.toggle('input--error', message !== null);
  input.setAttribute('aria-invalid', message !== null ? 'true' : 'false');
}