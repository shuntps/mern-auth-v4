import crypto from 'crypto';
import { type Request, type Response, type NextFunction } from 'express';
import { env } from '@config/env';
import redisClient from '@config/redis';
import logger from '@config/logger';
import { AuthenticationError, CsrfBlockedError } from '@utils/errors';
import { verifyRefreshToken } from '@services/token.service';

const CSRF_COOKIE_NAME = 'csrfToken';
const CSRF_FAILURE_PREFIX = 'csrf-fail:';
const CSRF_TOKEN_PREFIX = 'csrf-token:';
const CSRF_STORE_TTL_SECONDS = Math.min(env.csrfTokenTtl, Math.floor(env.cookieMaxAge / 1000));

type CsrfCookieBag = Record<typeof CSRF_COOKIE_NAME, string | undefined>;

const createToken = (): string => crypto.randomBytes(env.csrfTokenLength).toString('base64url');

const setTokenCookie = (res: Response, token: string): void => {
  res.cookie(CSRF_COOKIE_NAME, token, {
    // Intentionally httpOnly: false to allow SPA to send token via X-CSRF-Token header
    httpOnly: false,
    secure: env.cookieSecure,
    sameSite: env.cookieSameSite,
    maxAge: env.cookieMaxAge,
    path: '/',
  });
};

const getCsrfCookie = (req: Request): string | undefined => {
  const cookies = req.cookies as CsrfCookieBag | undefined;
  return cookies?.[CSRF_COOKIE_NAME];
};

const buildTokenKey = (token: string): string => `${CSRF_TOKEN_PREFIX}${token}`;

const storeToken = async (token: string): Promise<boolean> => {
  const key = buildTokenKey(token);
  const result = await redisClient.set(key, '1', 'EX', CSRF_STORE_TTL_SECONDS, 'NX');
  return result === 'OK';
};

const deleteToken = async (token: string): Promise<void> => {
  const key = buildTokenKey(token);
  await redisClient.del(key);
};

const tokenExists = async (token: string): Promise<boolean> => {
  const key = buildTokenKey(token);
  const exists = await redisClient.exists(key);
  return exists === 1;
};

const logCsrfFailure = async (req: Request, reason: string): Promise<void> => {
  const key = `${CSRF_FAILURE_PREFIX}${req.ip ?? 'unknown'}`;
  const context = extractUserContext(req);
  try {
    const failures = await redisClient.incr(key);
    await redisClient.expire(key, env.loginAttemptTtl);
    logger.warn('CSRF validation failed', {
      ip: req.ip,
      method: req.method,
      path: req.path,
      reason,
      failures,
      ua: req.get('user-agent') ?? 'unknown',
      userId: context.userId,
      sessionId: context.sessionId,
      metric: 'csrf_failure',
    });
  } catch (error) {
    logger.warn('CSRF failure logging skipped (Redis error)', {
      ip: req.ip,
      method: req.method,
      path: req.path,
      reason,
      userId: context.userId,
      sessionId: context.sessionId,
      error,
    });
  }
};

const hasExceededCsrfFailures = async (req: Request): Promise<boolean> => {
  const key = `${CSRF_FAILURE_PREFIX}${req.ip ?? 'unknown'}`;
  try {
    const failures = await redisClient.get(key);
    if (!failures) return false;
    const count = Number(failures);
    return Number.isFinite(count) && count >= env.csrfFailureThreshold;
  } catch (error) {
    logger.warn('CSRF failure threshold check skipped (Redis error)', {
      ip: req.ip,
      method: req.method,
      path: req.path,
      error,
    });
    return false;
  }
};

const extractUserContext = (req: Request): { userId?: string; sessionId?: string } => {
  const refreshToken = req.cookies.refreshToken as string | undefined;
  if (!refreshToken) return {};
  try {
    const payload = verifyRefreshToken(refreshToken);
    return { userId: payload.sub, sessionId: payload.sessionId };
  } catch {
    return {};
  }
};

export const refreshCsrfToken = (res: Response): string => {
  const token = createToken();
  setTokenCookie(res, token);
  res.locals.csrfToken = token;
  void storeToken(token);
  return token;
};

export const issueCsrfToken = (req: Request, res: Response, next: NextFunction): void => {
  const existing = getCsrfCookie(req);
  const token = existing ?? createToken();
  if (!existing) {
    setTokenCookie(res, token);
  }
  void storeToken(token); // idempotent set refreshes TTL
  res.locals.csrfToken = token;
  next();
};

export const verifyCsrfToken = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  const userContext = extractUserContext(req);

  if (await hasExceededCsrfFailures(req)) {
    logger.warn('CSRF validation blocked after repeated failures', {
      ip: req.ip,
      method: req.method,
      path: req.path,
      ua: req.get('user-agent') ?? 'unknown',
      userId: userContext.userId,
      sessionId: userContext.sessionId,
      metric: 'csrf_blocked',
    });
    res.setHeader('Retry-After', env.loginAttemptTtl.toString());
    throw new CsrfBlockedError('errors.csrf.blocked', env.loginAttemptTtl);
  }

  const cookieToken = getCsrfCookie(req);
  const headerToken = req.get('x-csrf-token') ?? '';

  if (!cookieToken || !headerToken || cookieToken !== headerToken) {
    await logCsrfFailure(req, 'mismatch');
    throw new AuthenticationError('errors.csrf.invalid');
  }

  const exists = await tokenExists(cookieToken);
  if (!exists) {
    await logCsrfFailure(req, 'missing-store');
    throw new AuthenticationError('errors.csrf.invalid');
  }

  if (env.csrfRotateOnVerify) {
    void deleteToken(cookieToken);
    refreshCsrfToken(res); // rotate on successful verification to reduce replay window
    logger.debug('CSRF token rotated after verification', {
      ip: req.ip,
      method: req.method,
      path: req.path,
      userId: userContext.userId,
      sessionId: userContext.sessionId,
      metric: 'csrf_rotated',
    });
  }
  next();
};
