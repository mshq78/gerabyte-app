import type { Express } from 'express';
import request from 'supertest';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { loadEnv, setEnvForTests } from '../../config/env.js';
import { APP_ORIGIN, setupTestApp, teardownTestApp } from '../../testing/harness.js';

/**
 * A platform serves one deployment on several hostnames. Every one of them is
 * our own page, so a request carrying one as its Origin is same-origin in the
 * only sense CSRF cares about — but the check compared against a single exact
 * string, so the others came back 403 and the login button looked dead.
 *
 * The allowlist is explicit. `*.vercel.app` would trust anyone's deployment.
 */
const ALIAS = 'https://gerabyte-app-team.vercel.app';
const STRANGER = 'https://gerabyte-app-evil.vercel.app';

let app: Express;
let original: ReturnType<typeof loadEnv>;

beforeAll(async () => {
  ({ app } = await setupTestApp());
  original = loadEnv(process.env);
  setEnvForTests({ ...original, APP_ORIGIN_ALIASES: [ALIAS] });
});

afterAll(async () => {
  setEnvForTests(original);
  await teardownTestApp();
});

const csrf = { 'X-Requested-With': 'gerabyte' } as const;

describe('accepted origins', () => {
  it('accepts the canonical origin', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .set(csrf)
      .set('Origin', APP_ORIGIN)
      .send({ phone: '09120000001', password: 'whatever-wrong' });
    // Past the origin check: it reaches validation or credentials, not 403.
    expect(res.status).not.toBe(403);
  });

  it('accepts an alias the platform also serves this app on', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .set(csrf)
      .set('Origin', ALIAS)
      .send({ phone: '09120000001', password: 'whatever-wrong' });
    expect(res.status).not.toBe(403);
  });

  it('still refuses an origin that is not ours', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .set(csrf)
      .set('Origin', STRANGER)
      .send({ phone: '09120000001', password: 'whatever-wrong' });
    expect(res.status).toBe(403);
    expect(res.body.error.code).toBe('CSRF_FAILED');
  });

  it('still refuses a request with no CSRF header at all', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .set('Origin', APP_ORIGIN)
      .send({ phone: '09120000001', password: 'whatever-wrong' });
    expect(res.status).toBe(403);
  });

  it('checks the Referer against the same list when Origin is absent', async () => {
    const accepted = await request(app)
      .post('/api/auth/login')
      .set(csrf)
      .set('Referer', `${ALIAS}/login`)
      .send({ phone: '09120000001', password: 'whatever-wrong' });
    expect(accepted.status).not.toBe(403);

    const refused = await request(app)
      .post('/api/auth/login')
      .set(csrf)
      .set('Referer', `${STRANGER}/login`)
      .send({ phone: '09120000001', password: 'whatever-wrong' });
    expect(refused.status).toBe(403);
  });
});
