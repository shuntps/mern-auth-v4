import Redis from 'ioredis';
import logger from './logger';
import { env } from './env';

/**
 * Redis client instance with retry logic
 */
const redis = new Redis({
  host: env.redisHost,
  port: env.redisPort,
  password: env.redisPassword || undefined,
  db: env.redisDb,
  retryStrategy: (times: number): number | null => {
    const delay = Math.min(times * 50, 2000);
    if (times > 10) {
      logger.error('Redis connection retry limit reached');
      return null;
    }
    logger.warn(`Retrying Redis connection in ${delay.toString()}ms (attempt ${times.toString()})`);
    return delay;
  },
  reconnectOnError: (err: Error): boolean | 1 | 2 => {
    const targetError = 'READONLY';
    if (err.message.includes(targetError)) {
      // Reconnect on READONLY errors
      return true;
    }
    return false;
  },
  maxRetriesPerRequest: 3,
  enableReadyCheck: true,
  enableOfflineQueue: true,
});

/**
 * Redis connection event handlers
 */
redis.on('connect', () => {
  logger.info('Redis client connecting...');
});

redis.on('ready', () => {
  logger.info(`Redis connected: ${env.redisHost}:${env.redisPort.toString()}`);
  logger.info(`Redis database: ${env.redisDb.toString()}`);
});

redis.on('error', (error: Error) => {
  logger.error('Redis error:', error);
});

redis.on('close', () => {
  logger.warn('Redis connection closed');
});

redis.on('reconnecting', (ms: number) => {
  logger.info(`Redis reconnecting in ${ms.toString()}ms`);
});

redis.on('end', () => {
  logger.warn('Redis connection ended');
});

/**
 * Gracefully disconnect from Redis
 */
export const disconnectRedis = (): void => {
  try {
    void redis.quit();
    logger.info('Redis connection closed gracefully');
  } catch (error) {
    logger.error('Error closing Redis connection:', error);
    redis.disconnect();
  }
};

/**
 * Check if Redis is connected
 */
export const isRedisConnected = (): boolean => {
  return redis.status === 'ready';
};

/**
 * Get Redis connection status
 */
export const getRedisStatus = (): string => {
  return redis.status;
};

/**
 * Handle graceful shutdown
 */
process.on('SIGINT', () => {
  disconnectRedis();
});

process.on('SIGTERM', () => {
  disconnectRedis();
});

export default redis;
