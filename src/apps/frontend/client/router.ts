/** Hash-based router for the SPA. Views are lazy-loaded on navigation. */

export interface RouteContext {
  params: URLSearchParams;
  navigate: (path: string) => void;
}

export type ViewFactory = (ctx: RouteContext) => Promise<Node>;

export class Router {
  private host: HTMLElement;
  private routes = new Map<string, ViewFactory>();
  private readonly defaultRoute = '/login';

  constructor(host: HTMLElement) {
    this.host = host;
  }

  register(path: string, factory: ViewFactory): void {
    this.routes.set(path, factory);
  }

  start(): void {
    window.addEventListener('hashchange', () => void this.render());
    void this.render();
  }

  navigate(path: string): void {
    if (window.location.hash === `#${path}`) void this.render();
    else window.location.hash = path;
  }

  private parse(): { path: string; params: URLSearchParams } {
    const hash = window.location.hash.slice(1).replace(/^\/+/, '') || this.defaultRoute;
    const [pathPart, queryPart] = hash.split('?');
    const normalized = `/${(pathPart ?? '').replace(/\/+$/, '') || ''}`;
    return { path: normalized, params: new URLSearchParams(queryPart ?? '') };
  }

  private async render(): Promise<void> {
    const { path, params } = this.parse();

    // Default route for logged-in users.
    const factory = this.routes.get(path);
    if (!factory) {
      window.location.hash = this.defaultRoute;
      return;
    }

    // Redirect authenticated users away from auth screens.
    const publicOnly = ['/login', '/register'].includes(path);
    const haveToken = localStorage.getItem('identity.access_token') !== null;
    if (publicOnly && haveToken) {
      window.location.hash = '/account';
      return;
    }

    try {
      const view = await factory({ params, navigate: (p) => this.navigate(p) });
      this.host.classList.add('view--leaving');
      window.setTimeout(() => {
        this.host.classList.remove('view--leaving');
        while (this.host.firstChild) this.host.removeChild(this.host.firstChild);
        this.host.appendChild(view);
        this.host.classList.add('view--enter');
        requestAnimationFrame(() => requestAnimationFrame(() => this.host.classList.remove('view--enter')));
      }, 180);
    } catch {
      // View failures are surfaced as toasts by each screen; the shell stays.
    }
  }
}