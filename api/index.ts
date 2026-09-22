import { loadEnv } from '../server/config/env.js';

/**
 * Vercel entry. The only vendor-specific file in the backend: it exports the
 * same Express app the plain Node entry runs, so nothing about the application
 * depends on Vercel.
 */

/**
 * Preview deployments get a fresh URL per branch, so APP_ORIGIN cannot be a
 * fixed project-wide value for them. Vercel hands us the branch URL, which is
 * the one a pull request links to and the one a reviewer actually opens, so we
 * adopt it as this deployment's origin.
 *
 * Only for previews, and only when nothing else set APP_ORIGIN: staging and
 * production always carry an explicit value, and an unset origin there must
 * still fail validation rather than be guessed from a request.
 */
function adoptPreviewOrigin(): void {
  if (process.env.VERCEL_ENV !== 'preview') return;
  if (process.env.APP_ORIGIN) return;
  const host = process.env.VERCEL_BRANCH_URL ?? process.env.VERCEL_URL;
  if (host) process.env.APP_ORIGIN = `https://${host}`;
}

adoptPreviewOrigin();

/**
 * Vercel answers on several hostnames for the same deployment: the project
 * domain, the team-scoped alias the dashboard links to, and the per-branch
 * URL. All of them serve this app, so a request from any of them is
 * same-origin — but CSRF compares against one exact string, so the others
 * were being refused with a 403 that looks, from the browser, like the login
 * button simply not working.
 *
 * Only hostnames the platform tells us are ours. Never a wildcard: anyone can
 * deploy to *.vercel.app.
 */
function adoptPlatformAliases(): void {
  const aliases = [
    process.env.VERCEL_PROJECT_PRODUCTION_URL,
    process.env.VERCEL_BRANCH_URL,
    process.env.VERCEL_URL,
  ]
    .filter((host): host is string => Boolean(host))
    .map((host) => `https://${host}`);

  if (aliases.length === 0) return;
  const existing = process.env.APP_ORIGIN_ALIASES ? process.env.APP_ORIGIN_ALIASES.split(',') : [];
  process.env.APP_ORIGIN_ALIASES = [...new Set([...existing, ...aliases])].join(',');
}

adoptPlatformAliases();

// Environment validation runs at module load, so a misconfigured deployment
// fails on the first cold start rather than serving broken requests.
loadEnv();

// Imported dynamically, and only now: `server/app` pulls in the logger, which
// reads the validated environment while it is being constructed. A static
// import is hoisted above everything above this line, so the logger would run
// before adoptPreviewOrigin() had a chance to fill APP_ORIGIN in.
const { createApp, defaultDatabase } = await import('../server/app.js');

const app = createApp({ db: defaultDatabase() });

export default app;
