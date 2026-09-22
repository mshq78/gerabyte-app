import type { NextFunction, Request, Response } from 'express';
import helmet from 'helmet';
import { env, isProductionDeployment } from '../../config/env.js';
import { forbidden } from '../errors.js';

/** The header a browser cannot set cross-origin without a preflight we never answer. */
export const CSRF_HEADER = 'x-requested-with';
export const CSRF_HEADER_VALUE = 'gerabyte';

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

export function securityHeaders() {
  return helmet({
    contentSecurityPolicy: {
      useDefaults: false,
      directives: {
        'default-src': ["'self'"],
        'script-src': ["'self'"],
        // Tailwind and the chart library both inject style attributes at runtime.
        'style-src': ["'self'", "'unsafe-inline'"],
        'img-src': ["'self'", 'data:'],
        'font-src': ["'self'"],
        // Same-origin only: the API is served from the app's own origin.
        'connect-src': ["'self'"],
        'object-src': ["'none'"],
        'base-uri': ["'self'"],
        'form-action': ["'self'"],
        'frame-ancestors': ["'none'"],
        'upgrade-insecure-requests': [],
      },
    },
    crossOriginEmbedderPolicy: false,
    crossOriginOpenerPolicy: { policy: 'same-origin' },
    crossOriginResourcePolicy: { policy: 'same-origin' },
    referrerPolicy: { policy: 'same-origin' },
    hsts: { maxAge: 63_072_000, includeSubDomains: true, preload: false },
    frameguard: { action: 'deny' },
    noSniff: true,
    xssFilter: false,
    hidePoweredBy: true,
  });
}

/** Headers helmet does not set for us. */
export function extraSecurityHeaders() {
  return (_req: Request, res: Response, next: NextFunction) => {
    res.setHeader(
      'Permissions-Policy',
      'accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()'
    );
    // Anything that is not the real production deployment must stay out of
    // search results.
    if (!isProductionDeployment()) {
      res.setHeader('X-Robots-Tag', 'noindex, nofollow');
    }
    next();
  };
}

/**
 * Every origin this app is actually served from: the canonical one, plus any
 * alias the platform also answers on. All of them are our own page, which is
 * the only thing CSRF is asking about.
 */
export function isOwnOrigin(origin: string): boolean {
  const { APP_ORIGIN, APP_ORIGIN_ALIASES } = env();
  return origin === APP_ORIGIN || APP_ORIGIN_ALIASES.includes(origin);
}

/**
 * Same-origin only. There is no cross-origin client, so rather than emitting
 * permissive CORS headers we simply refuse anything whose Origin is not ours.
 */
export function sameOriginOnly() {
  return (req: Request, res: Response, next: NextFunction) => {
    const origin = req.get('origin');
    if (origin && !isOwnOrigin(origin)) {
      next(forbidden('CSRF_FAILED'));
      return;
    }
    if (origin) {
      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Access-Control-Allow-Credentials', 'true');
      res.setHeader('Vary', 'Origin');
    }
    next();
  };
}

/**
 * CSRF defence, two independent checks on every state-changing request:
 *
 *  1. `X-Requested-With: gerabyte`. A cross-site form or img cannot set a custom
 *     header, and fetch/XHR that does triggers a preflight we never answer.
 *  2. Origin (or Referer, when Origin is absent) must equal APP_ORIGIN.
 *
 * Either failing is a 403. This is on top of SameSite=Lax on the cookie.
 */
export function csrfGuard() {
  return (req: Request, _res: Response, next: NextFunction) => {
    if (SAFE_METHODS.has(req.method)) {
      next();
      return;
    }

    if (req.get(CSRF_HEADER) !== CSRF_HEADER_VALUE) {
      next(forbidden('CSRF_FAILED'));
      return;
    }

    const origin = req.get('origin');
    if (origin) {
      if (!isOwnOrigin(origin)) {
        next(forbidden('CSRF_FAILED'));
        return;
      }
      next();
      return;
    }

    const referer = req.get('referer');
    if (referer) {
      try {
        if (!isOwnOrigin(new URL(referer).origin)) {
          next(forbidden('CSRF_FAILED'));
          return;
        }
        next();
        return;
      } catch {
        next(forbidden('CSRF_FAILED'));
        return;
      }
    }

    // Neither header present: a browser always sends one for a cross-site
    // state-changing request, so refuse rather than guess.
    next(forbidden('CSRF_FAILED'));
  };
}
