/** SPA entrypoint: register routes and boot the router. */

import { Router } from './router.js';
import { loginView } from './views/login.js';
import { registerView } from './views/register.js';
import { mfaView } from './views/mfa.js';
import { resetView } from './views/reset.js';
import { accountView } from './views/account.js';
import { hasAccessToken } from './tokens.js';

const host = document.getElementById('app');
if (!host) throw new Error('Missing #app mount point');

const router = new Router(host);

router.register('/login', loginView);
router.register('/register', registerView);
router.register('/mfa', mfaView);
router.register('/reset', resetView);
router.register('/account', accountView);

// Bootstrap: land authenticated users on the dashboard.
if (hasAccessToken() && (!location.hash || location.hash === '#' || location.hash === '#/login')) {
  location.hash = '/account';
}

router.start();