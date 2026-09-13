import request from 'supertest';
import { resetConfigCache } from '../../src/config';
import { createFrontendApp } from '../../src/apps/frontend/server';

describe('frontend app', () => {
  beforeEach(() => resetConfigCache());

  it('serves a liveness probe', async () => {
    const app = createFrontendApp();
    const res = await request(app).get('/healthz');
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ status: 'ok', service: 'frontend' });
  });

  it('serves runtime config for the SPA', async () => {
    const app = createFrontendApp();
    const res = await request(app).get('/config.js');
    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toContain('javascript');
    expect(res.text).toContain('window.__APP_CONFIG__');
    expect(res.text).toContain('authBase');
  });

  it('serves the SPA shell at the root', async () => {
    const app = createFrontendApp();
    const res = await request(app).get('/');
    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toContain('text/html');
    expect(res.text).toContain('<div class="app" id="app"></div>');
  });

  it('falls back to the shell for client-side routes', async () => {
    const app = createFrontendApp();
    const res = await request(app).get('/account');
    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toContain('text/html');
  });

  it('rejects POSTs it does not own with the error envelope', async () => {
    const app = createFrontendApp();
    const res = await request(app).post('/auth/login').send({});
    expect(res.status).toBe(404);
    expect(res.body.error).toBeDefined();
  });
});