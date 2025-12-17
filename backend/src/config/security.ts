import { HelmetOptions } from 'helmet';
import { env, isDevelopment, isProduction } from '@config/env';

const parseOrigins = (value: string): string[] => {
  return value
    .split(',')
    .map((origin) => origin.trim())
    .filter(Boolean);
};

const normalizeOrigins = (origins: string[]): string[] => {
  const uniqueOrigins = new Set<string>();

  origins.forEach((origin) => {
    try {
      const normalized = new URL(origin).origin;
      uniqueOrigins.add(normalized);
    } catch {
      // Ignore invalid origins
    }
  });

  return Array.from(uniqueOrigins);
};

export const trustedOrigins = normalizeOrigins([...parseOrigins(env.corsOrigin), env.frontendUrl]);

const contentSecurityPolicy = isDevelopment()
  ? false
  : {
      useDefaults: false,
      directives: {
        defaultSrc: ["'self'"],
        baseUri: ["'self'"],
        scriptSrc: ["'self'", ...trustedOrigins],
        scriptSrcAttr: ["'none'"],
        styleSrc: ["'self'", 'https://fonts.googleapis.com', ...trustedOrigins],
        imgSrc: ["'self'", 'data:', ...trustedOrigins],
        connectSrc: ["'self'", ...trustedOrigins],
        fontSrc: ["'self'", 'https://fonts.gstatic.com'],
        frameAncestors: ["'none'"],
        formAction: ["'self'", ...trustedOrigins],
        objectSrc: ["'none'"],
      },
    };

export const helmetConfig: HelmetOptions = {
  contentSecurityPolicy,
  referrerPolicy: { policy: 'no-referrer' },
  frameguard: { action: 'deny' },
  crossOriginEmbedderPolicy: false,
  crossOriginOpenerPolicy: { policy: 'same-origin' },
  crossOriginResourcePolicy: { policy: 'same-site' },
  dnsPrefetchControl: { allow: false },
  permittedCrossDomainPolicies: { permittedPolicies: 'none' },
  hidePoweredBy: true,
  hsts: isProduction()
    ? { maxAge: 60 * 60 * 24 * 365, includeSubDomains: true, preload: true }
    : false,
};
