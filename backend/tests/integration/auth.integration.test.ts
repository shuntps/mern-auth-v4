import type { Express } from 'express';
import supertest from 'supertest';
import type { Response as SupertestResponse } from 'supertest';
import { describe, beforeAll, afterAll, beforeEach, it, expect, vi } from 'vitest';
import mongoose from 'mongoose';
import { MongoMemoryServer } from 'mongodb-memory-server';

vi.mock('@config/logger', () => ({
  __esModule: true,
  default: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  },
}));

let lastVerificationToken: string | undefined;

vi.mock('@services/email.service', () => ({
  __esModule: true,
  sendVerificationEmail: vi.fn((email: string, token: string) => {
    void email; // suppress unused in mock
    lastVerificationToken = token;
    return Promise.resolve();
  }),
  sendPasswordResetEmail: vi.fn(() => Promise.resolve()),
  sendPasswordChangedEmail: vi.fn(() => Promise.resolve()),
  sendWelcomeEmail: vi.fn(() => Promise.resolve()),
}));

vi.mock('@config/redis', () => {
  const store = new Map<string, { value: string; expiresAt?: number }>();
  const scriptRegistry = new Map<string, string>();
  let scriptCounter = 0;

  const now = (): number => Date.now();

  const getEntry = (key: string): string | null => {
    const entry = store.get(key);
    if (!entry) return null;
    if (entry.expiresAt && entry.expiresAt <= now()) {
      store.delete(key);
      return null;
    }
    return entry.value;
  };

  const set = vi.fn(
    (
      key: string,
      value: string,
      mode?: string,
      ttlSeconds?: number,
      nx?: string
    ): Promise<'OK' | null> => {
      const isNx = nx === 'NX';
      if (isNx && store.has(key)) {
        return Promise.resolve(null);
      }
      const expiresAt = mode === 'EX' && ttlSeconds ? now() + ttlSeconds * 1000 : undefined;
      store.set(key, { value, expiresAt });
      return Promise.resolve('OK');
    }
  );

  const get = vi.fn((key: string) => Promise.resolve(getEntry(key)));

  const del = vi.fn((keys: string | string[]) => {
    const list = Array.isArray(keys) ? keys : [keys];
    let deleted = 0;
    for (const key of list) {
      deleted += store.delete(key) ? 1 : 0;
    }
    return Promise.resolve(deleted);
  });

  const mget = vi.fn((keys: string[]) => Promise.resolve(keys.map((key) => getEntry(key))));

  const exists = vi.fn((key: string) => Promise.resolve(store.has(key) ? 1 : 0));

  const expire = vi.fn((key: string, ttl: number) => {
    const entry = store.get(key);
    if (!entry) return Promise.resolve(0);
    store.set(key, { ...entry, expiresAt: now() + ttl * 1000 });
    return Promise.resolve(1);
  });

  const pexpire = vi.fn((key: string, ttlMs: number) => {
    const entry = store.get(key);
    if (!entry) return Promise.resolve(0);
    store.set(key, { ...entry, expiresAt: now() + ttlMs });
    return Promise.resolve(1);
  });

  const incr = vi.fn((key: string) => {
    const current = Number(getEntry(key) ?? '0');
    const next = current + 1;
    store.set(key, { value: next.toString() });
    return Promise.resolve(next);
  });

  const pttl = vi.fn((key: string) => {
    const entry = store.get(key);
    if (!entry?.expiresAt) return Promise.resolve(-1);
    return Promise.resolve(Math.max(entry.expiresAt - now(), 0));
  });

  const allocateScriptSha = (script: string): string => {
    const existing = scriptRegistry.get(script);
    if (existing) return existing;
    const sha = `mock-sha-${String(scriptCounter++)}`;
    scriptRegistry.set(script, sha);
    return sha;
  };

  const handleEvalSha = async (
    sha: string,
    args: string[]
  ): Promise<[number, number] | [string | false, number] | null> => {
    const scriptEntry = Array.from(scriptRegistry.entries()).find(([, value]) => value === sha);
    if (!scriptEntry) return Promise.reject(new Error('NOSCRIPT')); // mimic Redis NOSCRIPT

    const [script] = scriptEntry;
    // Increment script shape: EVALSHA sha 1 key resetFlag windowMs
    if (script.includes('INCR')) {
      const [key, resetFlag, windowMsString] = args.slice(1) as [string, string, string]; // args[0] is key count "1"
      const windowMs = Number(windowMsString);
      const currentValue = getEntry(key);
      const ttlMs = await pttl(key);

      if (!currentValue || ttlMs <= 0) {
        store.set(key, { value: '1', expiresAt: now() + windowMs });
        return Promise.resolve([1, windowMs]);
      }

      const totalHits = Number(currentValue) + 1;
      if (resetFlag === '1') {
        store.set(key, { value: totalHits.toString(), expiresAt: now() + windowMs });
        return Promise.resolve([totalHits, windowMs]);
      }

      const remaining = await pttl(key);
      store.set(key, { value: totalHits.toString(), expiresAt: now() + remaining });
      return Promise.resolve([totalHits, remaining]);
    }

    // Get script shape: EVALSHA sha 1 key
    if (script.includes('GET') && script.includes('PTTL')) {
      const key = args[1];
      if (typeof key !== 'string') return Promise.reject(new Error('Invalid key for GET'));
      const value = getEntry(key);
      const ttlMs = await pttl(key);
      return Promise.resolve([value ?? false, ttlMs]);
    }

    return Promise.resolve(null);
  };

  const scan = vi.fn(
    (cursor: string, _match: string, pattern: string, _count: string, count: string) => {
      const regex = new RegExp(`^${pattern.replace(/\*/g, '.*')}$`);
      const keys = Array.from(store.keys()).filter((key) => regex.test(key));
      const start = Number(cursor);
      const size = Number(count);
      const batch = keys.slice(start, start + size);
      const nextCursor = start + size >= keys.length ? '0' : (start + size).toString();
      return Promise.resolve([nextCursor, batch]);
    }
  );

  const call = vi.fn((command: string, ...args: [string, ...string[]]) => {
    const cmd = command.toUpperCase();
    if (cmd === 'INCR') {
      const key = args[0];
      if (!key) return Promise.reject(new Error('INCR requires key'));
      return incr(key);
    }
    if (cmd === 'DECR') {
      const key = args[0];
      const current = Number(getEntry(key) ?? '0') - 1;
      store.set(key, { value: current.toString() });
      return Promise.resolve(current);
    }
    if (cmd === 'PTTL') {
      const key = args[0];
      if (!key) return Promise.reject(new Error('PTTL requires key'));
      return pttl(key);
    }
    if (cmd === 'PEXPIRE') {
      const [key, ttl] = args;
      if (!key || typeof ttl === 'undefined')
        return Promise.reject(new Error('PEXPIRE requires key and ttl'));
      return pexpire(key, Number(ttl));
    }
    if (cmd === 'EXPIRE') {
      const [key, ttl] = args;
      if (!key || typeof ttl === 'undefined')
        return Promise.reject(new Error('EXPIRE requires key and ttl'));
      return expire(key, Number(ttl));
    }
    if (cmd === 'DEL') return del(args);
    if (cmd === 'SCRIPT' && args[0] === 'LOAD') {
      const sha = allocateScriptSha(args[1] ?? '');
      return Promise.resolve(sha);
    }
    if (cmd === 'EVALSHA') {
      const [sha, ...rest] = args;
      if (!sha) return Promise.reject(new Error('EVALSHA requires sha'));
      return handleEvalSha(sha, rest);
    }
    return Promise.resolve(null);
  });

  return {
    __esModule: true,
    default: {
      set,
      get,
      del,
      mget,
      scan,
      incr,
      expire,
      pexpire,
      pttl,
      exists,
      call,
      _store: store,
    },
  };
});

const getCookieValue = (cookies: string[] | undefined, name: string): string | undefined => {
  if (!cookies) return undefined;
  const target = cookies.find((cookie) => cookie.startsWith(`${name}=`));
  return target ? target.split(';')[0] : undefined;
};

const extractTokenFromCookie = (cookie: string | undefined): string | undefined => {
  if (!cookie) return undefined;
  const [, value] = cookie.split('=');
  return value;
};

const getSetCookieHeader = (response: SupertestResponse): string[] => {
  const setCookieHeader = response.header['set-cookie'] as string | string[] | undefined;
  if (!setCookieHeader) return [];
  return Array.isArray(setCookieHeader) ? setCookieHeader : [setCookieHeader];
};

interface RegisterResponseBody {
  status?: string;
  data?: {
    user?: { email?: string };
    accessToken?: string;
    csrfToken?: string;
  };
}

interface ValidationErrorResponse {
  status: string;
  details: unknown[];
}

const isValidationErrorResponse = (body: unknown): body is ValidationErrorResponse => {
  if (!body || typeof body !== 'object') return false;
  const candidate = body as { status?: unknown; details?: unknown };
  return candidate.status === 'error' && Array.isArray(candidate.details);
};

describe('auth integration', () => {
  let app: Express;
  let agent: ReturnType<typeof supertest>;
  let mongo: MongoMemoryServer;

  beforeAll(async () => {
    process.env.NODE_ENV = 'test';
    process.env.JWT_ACCESS_SECRET = 'test-access';
    process.env.JWT_REFRESH_SECRET = 'test-refresh';
    process.env.COOKIE_MAX_AGE = '604800000';
    process.env.CSRF_TOKEN_TTL = '604800';
    process.env.CSRF_ROTATE_ON_VERIFY = 'true';
    process.env.CSRF_TOKEN_LENGTH = '32';

    mongo = await MongoMemoryServer.create();
    process.env.MONGODB_URI = mongo.getUri();

    const databaseModule = (await import('../../src/config/database')) as {
      connectDatabase: () => Promise<void>;
    };
    const roleModule = (await import('../../src/models/role.model')) as {
      seedDefaultRoles: () => Promise<void>;
    };
    const appModule = (await import('../../src/index')) as {
      createApp: () => Express;
    };

    await databaseModule.connectDatabase();
    await roleModule.seedDefaultRoles();

    app = appModule.createApp();
    agent = supertest(app);
  });

  afterAll(async () => {
    await mongoose.connection.close();
    await mongo.stop();
  });

  beforeEach(async () => {
    lastVerificationToken = undefined;

    const connection = mongoose.connection;
    if (!connection.db) throw new Error('Database connection not established');
    const collections = await connection.db.collections();
    for (const collection of collections) {
      await collection.deleteMany({});
    }
    const roleModule: typeof import('../../src/models/role.model') =
      await import('../../src/models/role.model');
    const seedDefaultRoles: () => Promise<void> = roleModule.seedDefaultRoles;
    await seedDefaultRoles();

    const redisModule: typeof import('@config/redis') = await import('@config/redis');
    const redisStore = redisModule.default as unknown as {
      _store: Map<string, { value: string }>;
    };
    redisStore._store.clear();
  });

  it('registers, logs in, and issues cookies with CSRF token', async () => {
    const csrfRes = await agent.get('/api/auth/csrf-token');
    const csrfCookie = getCookieValue(getSetCookieHeader(csrfRes), 'csrfToken');
    const csrfToken = extractTokenFromCookie(csrfCookie);

    const uniqueId = Date.now().toString();

    const registerRes = await agent
      .post('/api/auth/register')
      .set('Cookie', csrfCookie ? [csrfCookie] : [])
      .set('x-csrf-token', csrfToken ?? '')
      .send({
        email: `user-${uniqueId}@example.com`,
        password: 'Password123!',
        firstName: 'Test',
        lastName: 'User',
      });

    const registerBody = registerRes.body as RegisterResponseBody;

    expect(registerRes.status).toBe(201);
    expect(registerBody.data?.user?.email).toBeTruthy();
    expect(registerBody.data?.accessToken).toBeTruthy();
    expect(registerBody.data?.csrfToken).toBeTruthy();

    const cookies = getSetCookieHeader(registerRes);
    expect(getCookieValue(cookies, 'accessToken')).toBeTruthy();
    expect(getCookieValue(cookies, 'refreshToken')).toBeTruthy();
  });

  it('changes password when authenticated with refresh token and rotates cookies', async () => {
    const csrfRes = await agent.get('/api/auth/csrf-token');
    const csrfCookie = getCookieValue(getSetCookieHeader(csrfRes), 'csrfToken');
    const csrfToken = extractTokenFromCookie(csrfCookie);

    const email = `user-${Date.now().toString()}@example.com`;

    const registerRes = await agent
      .post('/api/auth/register')
      .set('Cookie', csrfCookie ? [csrfCookie] : [])
      .set('x-csrf-token', csrfToken ?? '')
      .send({
        email,
        password: 'Password123!',
        firstName: 'Test',
        lastName: 'User',
      });

    const registerCookies = getSetCookieHeader(registerRes);
    const refreshCookie = getCookieValue(registerCookies, 'refreshToken');
    const csrfCookieAfterRegister = getCookieValue(registerCookies, 'csrfToken') ?? csrfCookie;
    const csrfTokenAfterRegister = extractTokenFromCookie(csrfCookieAfterRegister) ?? csrfToken;

    const cookiesForChange = [refreshCookie, csrfCookieAfterRegister].filter(
      (cookie): cookie is string => typeof cookie === 'string'
    );

    const changeRes = await agent
      .post('/api/auth/change-password')
      .set('Cookie', cookiesForChange)
      .set('x-csrf-token', csrfTokenAfterRegister ?? '')
      .send({
        oldPassword: 'Password123!',
        newPassword: 'NewPassword123!',
      });

    expect(changeRes.status).toBe(200);
    const changeCookies = getSetCookieHeader(changeRes);
    expect(changeCookies.some((cookie) => cookie.startsWith('accessToken=;'))).toBe(true);
    expect(changeCookies.some((cookie) => cookie.startsWith('refreshToken=;'))).toBe(true);
  });

  it('returns validation errors through the centralized handler on register', async () => {
    const csrfRes = await agent.get('/api/auth/csrf-token');
    const csrfCookie = getCookieValue(getSetCookieHeader(csrfRes), 'csrfToken');
    const csrfToken = extractTokenFromCookie(csrfCookie);

    const res = await agent
      .post('/api/auth/register')
      .set('Cookie', csrfCookie ? [csrfCookie] : [])
      .set('x-csrf-token', csrfToken ?? '')
      .send({
        email: 'invalid-email',
        password: 'short',
        firstName: '',
        lastName: '',
      });

    expect(res.status).toBe(400);
    expect(isValidationErrorResponse(res.body)).toBe(true);
    if (!isValidationErrorResponse(res.body)) return;

    expect(res.body.details.length).toBeGreaterThan(0);
  });

  it('throttles register requests after exceeding auth rate limit', async () => {
    const csrfRes = await agent.get('/api/auth/csrf-token');
    const csrfCookie = getCookieValue(getSetCookieHeader(csrfRes), 'csrfToken');
    const csrfToken = extractTokenFromCookie(csrfCookie);

    const makeRegister = (idx: number): Promise<SupertestResponse> =>
      agent
        .post('/api/auth/register')
        .set('Cookie', csrfCookie ? [csrfCookie] : [])
        .set('x-csrf-token', csrfToken ?? '')
        .send({
          email: `ratelimit-${idx.toString()}-${Date.now().toString()}@example.com`,
          password: 'Password123!',
          firstName: 'Rate',
          lastName: 'Limit',
        });

    const attempts = await Promise.all([
      makeRegister(1),
      makeRegister(2),
      makeRegister(3),
      makeRegister(4),
      makeRegister(5),
      makeRegister(6),
    ]);

    const lastResponse = attempts.at(-1);
    const statusCounts = attempts.reduce<Record<number, number>>((acc, resp) => {
      acc[resp.status] = (acc[resp.status] ?? 0) + 1;
      return acc;
    }, {});

    expect(lastResponse?.status).toBe(429);
    expect(statusCounts[429]).toBeGreaterThan(0);
  });

  it('returns IP history for an authenticated user', async () => {
    const csrfRes = await agent.get('/api/auth/csrf-token');
    const csrfCookie = getCookieValue(getSetCookieHeader(csrfRes), 'csrfToken');
    const csrfToken = extractTokenFromCookie(csrfCookie);

    const email = `ip-history-${Date.now().toString()}@example.com`;

    const registerRes = await agent
      .post('/api/auth/register')
      .set('Cookie', csrfCookie ? [csrfCookie] : [])
      .set('x-csrf-token', csrfToken ?? '')
      .send({
        email,
        password: 'Password123!',
        firstName: 'IP',
        lastName: 'Test',
      });

    const registerCookies = getSetCookieHeader(registerRes);
    const refreshCookie = getCookieValue(registerCookies, 'refreshToken');
    const csrfCookieAfterRegister = getCookieValue(registerCookies, 'csrfToken') ?? csrfCookie;
    const csrfTokenAfterRegister = extractTokenFromCookie(csrfCookieAfterRegister) ?? csrfToken;

    const cookiesForIpHistory = [refreshCookie, csrfCookieAfterRegister].filter(
      (cookie): cookie is string => typeof cookie === 'string'
    );

    const ipHistoryRes = await agent
      .get('/api/users/activity/ip-history')
      .set('Cookie', cookiesForIpHistory)
      .set('x-csrf-token', csrfTokenAfterRegister ?? '');

    expect(ipHistoryRes.status).toBe(200);
    const ipHistory = (ipHistoryRes.body as { data?: { ipHistory?: unknown } }).data?.ipHistory;
    expect(Array.isArray(ipHistory)).toBe(true);
    expect((ipHistory as unknown[] | undefined)?.length ?? 0).toBeGreaterThan(0);
  });

  it('requires email verification before login and succeeds after verification', async () => {
    const csrfRes = await agent.get('/api/auth/csrf-token');
    const csrfCookie = getCookieValue(getSetCookieHeader(csrfRes), 'csrfToken');
    const csrfToken = extractTokenFromCookie(csrfCookie);

    const email = `user-${Date.now().toString()}@example.com`;

    const registerRes = await agent
      .post('/api/auth/register')
      .set('Cookie', csrfCookie ? [csrfCookie] : [])
      .set('x-csrf-token', csrfToken ?? '')
      .send({
        email,
        password: 'Password123!',
        firstName: 'Test',
        lastName: 'User',
      });

    const initialLogin = await agent
      .post('/api/auth/login')
      .set('Cookie', csrfCookie ? [csrfCookie] : [])
      .set('x-csrf-token', csrfToken ?? '')
      .send({ email, password: 'Password123!' });

    expect(initialLogin.status).toBe(401);

    const registerCookies = getSetCookieHeader(registerRes);
    const csrfCookieAfterRegister = getCookieValue(registerCookies, 'csrfToken') ?? csrfCookie;
    const csrfTokenAfterRegister = extractTokenFromCookie(csrfCookieAfterRegister) ?? csrfToken;

    const verificationRes = await agent
      .post('/api/auth/verify-email')
      .set('Cookie', csrfCookieAfterRegister ? [csrfCookieAfterRegister] : [])
      .set('x-csrf-token', csrfTokenAfterRegister ?? '')
      .send({ token: lastVerificationToken ?? '' });

    expect(verificationRes.status).toBe(200);

    const loginCsrfRes = await agent.get('/api/auth/csrf-token');
    const loginCsrfCookie = getCookieValue(getSetCookieHeader(loginCsrfRes), 'csrfToken');
    const loginCsrfToken = extractTokenFromCookie(loginCsrfCookie);

    const loginRes = await agent
      .post('/api/auth/login')
      .set('Cookie', loginCsrfCookie ? [loginCsrfCookie] : [])
      .set('x-csrf-token', loginCsrfToken ?? '')
      .send({ email, password: 'Password123!' });

    expect(loginRes.status).toBe(200);
    const loginCookies = getSetCookieHeader(loginRes);
    expect(getCookieValue(loginCookies, 'accessToken')).toBeTruthy();
    expect(getCookieValue(loginCookies, 'refreshToken')).toBeTruthy();
  });
});
