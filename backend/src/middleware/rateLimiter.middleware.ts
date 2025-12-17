/**
 * Rate Limiting Middleware Configuration
 * Uses Redis (ioredis) for distributed rate limiting
 */

import rateLimit, { type Options } from 'express-rate-limit';
import RedisStore, { type RedisReply } from 'rate-limit-redis';
import type { Request } from 'express';
import redisClient from '@config/redis';
import logger from '@config/logger';
import { env } from '@config/env';

/**
 * Typed request body for email-based endpoints
 */
interface EmailBody {
  email?: string;
}

/**
 * Redis store factory (ioredis-compatible, fully typed)
 */
const createRedisStore = (prefix: string): Options['store'] => {
  return new RedisStore({
    sendCommand: (command: string, ...args: string[]): Promise<RedisReply> => {
      return redisClient.call(command, ...args) as Promise<RedisReply>;
    },
    prefix,
  });
};

/**
 * Safely extract email from request body
 */
const getEmailFromBody = (req: Request): string =>
  (req.body as EmailBody | undefined)?.email ?? 'unknown';

/**
 * General API rate limiter
 * 100 requests per 15 minutes
 */
export const generalLimiter = rateLimit({
  store: createRedisStore('rl:general:'),
  windowMs: env.rateLimitWindowMs,
  max: env.rateLimitMaxRequests,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    logger.warn('General rate limit exceeded', {
      ip: req.ip,
      path: req.path,
    });

    res.status(429).json({
      status: 'error',
      message: 'Too many requests, please try again later.',
    });
  },
});

/**
 * Authentication endpoints rate limiter
 * 5 requests per 15 minutes
 */
export const authLimiter = rateLimit({
  store: createRedisStore('rl:auth:'),
  windowMs: env.authRateLimitWindowMs,
  max: env.authRateLimitMaxRequests,
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: false,
  handler: (req, res) => {
    logger.warn('Auth rate limit exceeded', {
      ip: req.ip,
      path: req.path,
    });

    res.status(429).json({
      status: 'error',
      message: 'Too many authentication attempts, please try again later.',
    });
  },
});

/**
 * Login attempts rate limiter
 * 5 attempts per 15 minutes
 */
export const loginLimiter = rateLimit({
  store: createRedisStore('rl:login:'),
  windowMs: env.loginRateLimitWindowMs,
  max: env.loginRateLimitMaxAttempts,
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true,
  handler: (req, res) => {
    logger.warn('Login rate limit exceeded', {
      ip: req.ip,
      email: getEmailFromBody(req),
    });

    res.status(429).json({
      status: 'error',
      message: 'Too many login attempts, please try again later.',
    });
  },
});

/**
 * Password reset rate limiter
 * 3 requests per hour
 */
export const passwordResetLimiter = rateLimit({
  store: createRedisStore('rl:password-reset:'),
  windowMs: env.passwordResetRateLimitWindowMs,
  max: env.passwordResetRateLimitMaxRequests,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    logger.warn('Password reset rate limit exceeded', {
      ip: req.ip,
      email: getEmailFromBody(req),
    });

    res.status(429).json({
      status: 'error',
      message: 'Too many password reset requests, please try again later.',
    });
  },
});
