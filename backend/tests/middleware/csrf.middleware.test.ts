import { describe, expect, it, beforeEach, vi } from 'vitest';

vi.mock('@config/logger', () => ({
  __esModule: true,
  default: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  },
}));

vi.mock('@config/redis', () => {
  const store = new Map<string, { value: string; ttl?: number }>();

  const set = vi.fn((key: string, value: string, mode?: string, ttl?: number, nx?: string) => {
    const isNx = nx === 'NX';
    const hasKey = store.has(key);
    const shouldSet = !isNx || !hasKey;
    if (!shouldSet) return Promise.resolve(null);

    const expiresInSeconds = mode === 'EX' ? ttl : undefined;
    store.set(key, { value, ttl: expiresInSeconds });
    return Promise.resolve('OK');
  });

  const get = vi.fn((key: string) => Promise.resolve(store.get(key)?.value ?? null));

  const exists = vi.fn((key: string) => Promise.resolve(store.has(key) ? 1 : 0));

  const del = vi.fn((key: string) => {
    const deleted = store.delete(key);
    return Promise.resolve(deleted ? 1 : 0);
  });

  const incr = vi.fn((key: string) => {
    const current = Number(store.get(key)?.value ?? '0');
    const next = current + 1;
    store.set(key, { value: next.toString() });
    return Promise.resolve(next);
  });

  const expire = vi.fn((key: string, ttl: number) => {
    const entry = store.get(key);
    if (!entry) return Promise.resolve(0);
    store.set(key, { ...entry, ttl });
    return Promise.resolve(1);
  });

  return {
    __esModule: true,
    default: {
      set,
      get,
      exists,
      del,
      incr,
      expire,
      _store: store,
    },
  };
});

import type { Request, Response, NextFunction } from 'express';
import { env } from '@config/env';
import redisClient from '@config/redis';
import { issueCsrfToken, verifyCsrfToken } from '@middleware/csrf.middleware';
import { CsrfBlockedError } from '@utils/errors';

interface MockReqOptions {
  cookies?: Record<string, string>;
  headers?: Record<string, string>;
  ip?: string;
  method?: string;
  path?: string;
}

interface MockResponse {
  cookies: Record<string, string>;
  locals: Record<string, unknown>;
  cookie: ReturnType<typeof vi.fn>;
  setHeader: ReturnType<typeof vi.fn>;
}

const createMockReq = (options: MockReqOptions = {}): Request => {
  const headers = Object.fromEntries(
    Object.entries(options.headers ?? {}).map(([key, value]) => [key.toLowerCase(), value])
  );
  return {
    cookies: options.cookies ?? {},
    ip: options.ip ?? '127.0.0.1',
    method: options.method ?? 'GET',
    path: options.path ?? '/',
    get: (name: string) => headers[name.toLowerCase()],
  } as unknown as Request;
};

const createMockRes = (): MockResponse => {
  const cookies: Record<string, string> = {};
  const locals: Record<string, unknown> = {};
  const res: MockResponse = {
    cookies,
    locals,
    cookie: vi.fn((name: string, value: string) => {
      cookies[name] = value;
      return res;
    }) as ReturnType<typeof vi.fn>,
    setHeader: vi.fn(),
  };
  return res;
};

const flushPromises = async (): Promise<void> => {
  await new Promise((resolve) => {
    setImmediate(resolve);
  });
};

describe('csrf.middleware', () => {
  const redis = redisClient as unknown as {
    _store: Map<string, { value: string; ttl?: number }>;
    set: ReturnType<typeof vi.fn>;
    exists: ReturnType<typeof vi.fn>;
  };

  beforeEach(() => {
    redis._store.clear();
    vi.clearAllMocks();
  });

  const tokenKey = (token: string): string => `csrf-token:${token}`;

  it('issues, verifies, and rotates CSRF tokens', async () => {
    const resIssue = createMockRes();
    const reqIssue = createMockReq();
    const nextIssue = vi.fn() as NextFunction;

    issueCsrfToken(reqIssue, resIssue as unknown as Response, nextIssue);
    await flushPromises();

    const issuedToken = resIssue.locals.csrfToken;
    if (typeof issuedToken !== 'string') {
      throw new Error('CSRF token was not issued');
    }
    expect(resIssue.cookies.csrfToken).toBe(issuedToken);
    expect(redis._store.has(tokenKey(issuedToken))).toBe(true);

    const resVerify = createMockRes();
    const reqVerify = createMockReq({
      cookies: { csrfToken: issuedToken },
      headers: { 'x-csrf-token': issuedToken },
      method: 'POST',
      path: '/auth/login',
      ip: '192.0.2.1',
    });
    const nextVerify = vi.fn() as NextFunction;

    await verifyCsrfToken(reqVerify, resVerify as unknown as Response, nextVerify);
    await flushPromises();

    const rotatedToken = resVerify.locals.csrfToken;
    if (typeof rotatedToken !== 'string') {
      throw new Error('CSRF token did not rotate');
    }
    expect(rotatedToken).not.toBe(issuedToken);
    expect(resVerify.cookies.csrfToken).toBe(rotatedToken);
    expect(redis._store.has(tokenKey(issuedToken))).toBe(false);
    expect(redis._store.has(tokenKey(rotatedToken))).toBe(true);
    expect(nextVerify).toHaveBeenCalledTimes(1);
  });

  it('uses NX when storing tokens to avoid overwriting existing entries', async () => {
    const resIssue = createMockRes();
    const reqIssue = createMockReq();

    issueCsrfToken(reqIssue, resIssue as unknown as Response, vi.fn() as NextFunction);
    await flushPromises();

    const token = resIssue.locals.csrfToken;
    if (typeof token !== 'string') {
      throw new Error('CSRF token was not issued');
    }
    const key = tokenKey(token);
    const initialEntry = redis._store.get(key);

    const reqRepeat = createMockReq({ cookies: { csrfToken: token } });
    const resRepeat = createMockRes();
    issueCsrfToken(reqRepeat, resRepeat as unknown as Response, vi.fn() as NextFunction);
    await flushPromises();

    const repeatedEntry = redis._store.get(key);
    expect(repeatedEntry).toEqual(initialEntry);
    expect(redis.set).toHaveBeenCalledWith(key, '1', 'EX', expect.any(Number), 'NX');
  });

  it('blocks verification when CSRF failure threshold is reached', async () => {
    const failureKey = 'csrf-fail:203.0.113.5';
    redis._store.set(failureKey, { value: env.csrfFailureThreshold.toString() });

    const reqVerify = createMockReq({
      cookies: { csrfToken: 'stale' },
      headers: { 'x-csrf-token': 'stale' },
      ip: '203.0.113.5',
    });
    const resVerify = createMockRes();

    await expect(
      verifyCsrfToken(reqVerify, resVerify as unknown as Response, vi.fn() as NextFunction)
    ).rejects.toBeInstanceOf(CsrfBlockedError);
    expect(resVerify.setHeader).toHaveBeenCalledWith('Retry-After', env.loginAttemptTtl.toString());

    await verifyCsrfToken(
      reqVerify,
      resVerify as unknown as Response,
      vi.fn() as NextFunction
    ).catch((error: unknown) => {
      if (error instanceof CsrfBlockedError) {
        expect(error.code).toBe('CSRF_BLOCKED');
        return;
      }
      throw error;
    });
  });
});
