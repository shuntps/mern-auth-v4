import crypto from 'crypto';
import redisClient from '@config/redis';
import logger from '@config/logger';
import { env } from '@config/env';
import { AppError } from '@utils/errors';

export interface SessionMetadata {
  ip?: string;
  userAgent?: string;
  browser?: string;
  os?: string;
  device?: string;
}

export interface SessionRecord extends SessionMetadata {
  sessionId: string;
  userId: string;
  refreshToken: string;
  createdAt: string;
  updatedAt: string;
  expiresAt: string;
}

export type Session = SessionRecord;

const buildSessionKey = (userId: string, sessionId: string): string => {
  return `session:${userId}:${sessionId}`;
};

const nowIso = (): string => new Date().toISOString();

const ttlSeconds = env.redisSessionTtl;

const generateSessionId = (): string => {
  return crypto.randomBytes(env.sessionIdLength).toString('hex');
};

export const createSession = async (
  userId: string,
  refreshToken: string,
  metadata: SessionMetadata = {}
): Promise<SessionRecord> => {
  const sessionId = generateSessionId();
  const createdAt = nowIso();
  const expiresAt = new Date(Date.now() + ttlSeconds * 1000).toISOString();

  const record: SessionRecord = {
    sessionId,
    userId,
    refreshToken,
    createdAt,
    updatedAt: createdAt,
    expiresAt,
    ...metadata,
  };

  const key = buildSessionKey(userId, sessionId);

  try {
    await redisClient.set(key, JSON.stringify(record), 'EX', ttlSeconds);
    return record;
  } catch (error) {
    throw new AppError('errors.sessionCreateFailed', 500, false, error);
  }
};

export const getSession = async (
  userId: string,
  sessionId: string
): Promise<SessionRecord | null> => {
  const key = buildSessionKey(userId, sessionId);
  const raw = await redisClient.get(key);
  return raw ? (JSON.parse(raw) as SessionRecord) : null;
};

export const refreshSession = async (
  userId: string,
  sessionId: string,
  newRefreshToken: string
): Promise<SessionRecord> => {
  const existing = await getSession(userId, sessionId);
  if (!existing) {
    throw new AppError('errors.sessionNotFound', 404);
  }

  const updated: SessionRecord = {
    ...existing,
    refreshToken: newRefreshToken,
    updatedAt: nowIso(),
    expiresAt: new Date(Date.now() + ttlSeconds * 1000).toISOString(),
  };

  const key = buildSessionKey(userId, sessionId);

  try {
    await redisClient.set(key, JSON.stringify(updated), 'EX', ttlSeconds);
    return updated;
  } catch (error) {
    throw new AppError('errors.sessionRefreshFailed', 500, false, error);
  }
};

export const revokeSession = async (
  userId: string,
  sessionId: string,
  reason?: string
): Promise<void> => {
  const key = buildSessionKey(userId, sessionId);
  try {
    await redisClient.del(key);
    logger.info('Session revoked', { userId, sessionId, reason: reason ?? 'unspecified' });
  } catch (error) {
    throw new AppError('errors.sessionRevokeFailed', 500, false, error);
  }
};

export const revokeAllUserSessions = async (userId: string, reason?: string): Promise<void> => {
  const keys = await scanKeys(`session:${userId}:*`);
  if (keys.length === 0) return;
  try {
    await redisClient.del(keys);
    logger.info('All user sessions revoked', { userId, reason: reason ?? 'unspecified' });
  } catch (error) {
    throw new AppError('errors.sessionRevokeAllFailed', 500, false, error);
  }
};

export const getActiveUserSessions = async (userId: string): Promise<SessionRecord[]> => {
  const keys = await scanKeys(`session:${userId}:*`);
  if (keys.length === 0) return [];

  const results = await redisClient.mget(keys);
  return results
    .filter((value): value is string => Boolean(value))
    .map((value) => JSON.parse(value) as SessionRecord);
};

const scanKeys = async (pattern: string): Promise<string[]> => {
  const keys: string[] = [];
  let cursor = '0';
  do {
    const [nextCursor, batch] = await redisClient.scan(cursor, 'MATCH', pattern, 'COUNT', 100);
    cursor = nextCursor;
    keys.push(...batch);
  } while (cursor !== '0');
  return keys;
};
