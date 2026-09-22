import { z } from 'zod';

/**
 * Every environment variable the server reads, validated once at boot.
 * A missing or malformed value is a startup failure, never a runtime surprise.
 *
 * Only VITE_* variables reach the browser; nothing in here is exposed to it.
 */
const bool = (dflt: boolean) =>
  z
    .enum(['0', '1', 'true', 'false'])
    .optional()
    .transform((v) => (v === undefined ? dflt : v === '1' || v === 'true'));

const envSchema = z
  .object({
    NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
    PORT: z.coerce.number().int().min(1).max(65535).default(4000),

    /** Pooled connection for the running app (PgBouncer on Neon). */
    DATABASE_URL: z.string().min(1, 'DATABASE_URL is required'),
    /** Direct connection, used only by migrations. Never at request time. */
    DATABASE_URL_UNPOOLED: z.string().min(1).optional(),

    /** Exact origin the SPA is served from; CSRF and CORS are checked against it. */
    APP_ORIGIN: z.url(),
    /**
     * Other origins this same app is served from, comma separated.
     *
     * A platform gives one deployment several hostnames. Every one of them
     * serves our own page, so a request carrying one of them as its Origin is
     * same-origin in the only sense CSRF cares about. This is an explicit
     * list, never a wildcard: `*.vercel.app` would trust anyone's deployment.
     */
    APP_ORIGIN_ALIASES: z
      .string()
      .optional()
      .transform((v) =>
        (v ?? '')
          .split(',')
          .map((o) => o.trim().replace(/\/$/, ''))
          .filter((o) => o.length > 0)
      ),

    /** Secret for the OTP HMAC. Rotating it invalidates every code in flight. */
    OTP_HMAC_SECRET: z.string().min(32, 'OTP_HMAC_SECRET must be at least 32 characters'),
    /** Secret for hashing session tokens at rest. Rotating it logs everyone out. */
    SESSION_HASH_SECRET: z.string().min(32, 'SESSION_HASH_SECRET must be at least 32 characters'),
    /** Salt for the IP hashes written to the audit log, so raw IPs are never stored. */
    IP_HASH_SECRET: z.string().min(16, 'IP_HASH_SECRET must be at least 16 characters'),

    SMS_PROVIDER: z.enum(['console', 'kavenegar']).default('console'),
    KAVENEGAR_API_KEY: z.string().min(1).optional(),
    KAVENEGAR_OTP_TEMPLATE: z.string().min(1).optional(),

    /** Dev-only escape hatch: accept 000000 as a valid code. Never in production. */
    ALLOW_DEV_OTP: bool(false),
    /** Staging-only: lets a build ship with the mock API adapters still wired in. */
    ALLOW_MOCK_STAGING: bool(false),
    /** Staging-only: sends X-Robots-Tag: noindex on every response. */
    DEPLOY_ENV: z.enum(['local', 'staging', 'production']).default('local'),

    LOG_LEVEL: z
      .enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent'])
      .default('info'),
    /** Number of proxy hops to trust for the client IP. Vercel sits behind one. */
    TRUST_PROXY_HOPS: z.coerce.number().int().min(0).max(5).default(0),
  })
  .superRefine((env, ctx) => {
    // The security gates key off DEPLOY_ENV, not NODE_ENV.
    //
    // Vercel sets NODE_ENV=production for every deployment, staging included,
    // so gating on it would either block a staging deploy entirely or force us
    // to lie about NODE_ENV and lose the production build optimisations.
    // DEPLOY_ENV is ours, it is explicit, and it says what we actually mean.
    if (env.DEPLOY_ENV === 'production') {
      if (env.ALLOW_DEV_OTP) {
        ctx.addIssue({
          code: 'custom',
          path: ['ALLOW_DEV_OTP'],
          message: 'ALLOW_DEV_OTP must never be enabled in production',
        });
      }
      if (env.SMS_PROVIDER === 'console') {
        ctx.addIssue({
          code: 'custom',
          path: ['SMS_PROVIDER'],
          message: 'SMS_PROVIDER=console would print OTP codes to the log in production',
        });
      }
      if (!env.APP_ORIGIN.startsWith('https://')) {
        ctx.addIssue({
          code: 'custom',
          path: ['APP_ORIGIN'],
          message: 'APP_ORIGIN must be https in production',
        });
      }
    }
    if (env.SMS_PROVIDER === 'kavenegar' && !env.KAVENEGAR_API_KEY) {
      ctx.addIssue({
        code: 'custom',
        path: ['KAVENEGAR_API_KEY'],
        message: 'KAVENEGAR_API_KEY is required when SMS_PROVIDER=kavenegar',
      });
    }
  });

export type Env = z.infer<typeof envSchema>;

let cached: Env | null = null;

/** Parse and cache the environment. Throws a readable error and exits on failure. */
export function loadEnv(source: NodeJS.ProcessEnv = process.env): Env {
  const parsed = envSchema.safeParse(source);
  if (!parsed.success) {
    const lines = parsed.error.issues.map(
      (i) => `  - ${i.path.join('.') || '(root)'}: ${i.message}`
    );
    throw new Error(`Invalid environment configuration:\n${lines.join('\n')}`);
  }
  return parsed.data;
}

export function env(): Env {
  if (!cached) cached = loadEnv();
  return cached;
}

/** Test helper: force a specific environment for the process. */
export function setEnvForTests(value: Env): void {
  cached = value;
}

/** True only for a real production deployment, whatever NODE_ENV says. */
export const isProductionDeployment = () => env().DEPLOY_ENV === 'production';

/** True anywhere the app is served over https: every deployment. */
export const isDeployed = () => env().DEPLOY_ENV !== 'local';
