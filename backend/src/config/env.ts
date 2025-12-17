import { config } from 'dotenv';
import path from 'path';

// Load environment variables
config({ path: path.resolve(process.cwd(), '.env') });

/**
 * Environment configuration object with type safety
 */
export const env = {
  // Server
  nodeEnv: process.env.NODE_ENV ?? 'development',
  port: parseInt(process.env.PORT ?? '5000', 10),
  apiBasePath: process.env.API_BASE_PATH ?? '/api',

  // Database
  mongodbUri: process.env.MONGODB_URI ?? 'mongodb://localhost:27017/mern-auth-v4',
  mongodbPoolSize: parseInt(process.env.MONGODB_POOL_SIZE ?? '10', 10),
  mongodbConnectionTimeout: parseInt(process.env.MONGODB_CONNECTION_TIMEOUT ?? '30', 10),
  mongodbAutoIndex: process.env.MONGODB_AUTO_INDEX === 'true',

  // Redis
  redisHost: process.env.REDIS_HOST ?? 'localhost',
  redisPort: parseInt(process.env.REDIS_PORT ?? '6379', 10),
  redisPassword: process.env.REDIS_PASSWORD ?? '',
  redisDb: parseInt(process.env.REDIS_DB ?? '0', 10),
  redisSessionTtl: parseInt(process.env.REDIS_SESSION_TTL ?? '604800', 10),

  // JWT
  jwtAccessSecret: process.env.JWT_ACCESS_SECRET ?? 'change-this-secret',
  jwtRefreshSecret: process.env.JWT_REFRESH_SECRET ?? 'change-this-secret',
  jwtAccessExpiresIn: process.env.JWT_ACCESS_EXPIRES_IN ?? '15m',
  jwtRefreshExpiresIn: process.env.JWT_REFRESH_EXPIRES_IN ?? '7d',

  // Cookies
  cookieMaxAge: parseInt(process.env.COOKIE_MAX_AGE ?? '604800000', 10),
  cookieSecure: process.env.COOKIE_SECURE === 'true',
  cookieSameSite: (process.env.COOKIE_SAME_SITE ?? 'lax') as 'strict' | 'lax' | 'none',

  // Frontend
  frontendUrl: process.env.FRONTEND_URL ?? 'http://localhost:5173',
  corsOrigin: process.env.CORS_ORIGIN ?? 'http://localhost:5173',

  // Email
  emailHost: process.env.EMAIL_HOST ?? 'smtp.gmail.com',
  emailPort: parseInt(process.env.EMAIL_PORT ?? '587', 10),
  emailSecure: process.env.EMAIL_SECURE === 'true',
  emailUser: process.env.EMAIL_USER ?? '',
  emailPassword: process.env.EMAIL_PASSWORD ?? '',
  emailFrom: process.env.EMAIL_FROM ?? 'MERN Auth <noreply@mernauth.com>',
  emailVerificationTtl: parseInt(process.env.EMAIL_VERIFICATION_TTL ?? '86400', 10),
  passwordResetTtl: parseInt(process.env.PASSWORD_RESET_TTL ?? '900', 10),

  // CORS
  corsCredentials: process.env.CORS_CREDENTIALS === 'true',

  // Rate Limiting
  rateLimitWindowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS ?? '900000', 10),
  rateLimitMaxRequests: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS ?? '100', 10),
  authRateLimitWindowMs: parseInt(process.env.AUTH_RATE_LIMIT_WINDOW_MS ?? '900000', 10),
  authRateLimitMaxRequests: parseInt(process.env.AUTH_RATE_LIMIT_MAX_REQUESTS ?? '5', 10),
  loginRateLimitWindowMs: parseInt(process.env.LOGIN_RATE_LIMIT_WINDOW_MS ?? '900000', 10),
  loginRateLimitMaxAttempts: parseInt(process.env.LOGIN_RATE_LIMIT_MAX_ATTEMPTS ?? '5', 10),
  passwordResetRateLimitWindowMs: parseInt(
    process.env.PASSWORD_RESET_RATE_LIMIT_WINDOW_MS ?? '3600000',
    10
  ),
  passwordResetRateLimitMaxRequests: parseInt(
    process.env.PASSWORD_RESET_RATE_LIMIT_MAX_REQUESTS ?? '3',
    10
  ),

  // Security
  bcryptRounds: parseInt(process.env.BCRYPT_ROUNDS ?? '10', 10),
  csrfTokenLength: parseInt(process.env.CSRF_TOKEN_LENGTH ?? '32', 10),
  sessionIdLength: parseInt(process.env.SESSION_ID_LENGTH ?? '32', 10),

  // File Uploads
  maxAvatarSize: parseInt(process.env.MAX_AVATAR_SIZE ?? '5242880', 10),
  allowedImageFormats: (process.env.ALLOWED_IMAGE_FORMATS ?? 'jpg,jpeg,png,webp').split(','),
  imageOutputSize: parseInt(process.env.IMAGE_OUTPUT_SIZE ?? '500', 10),
  uploadDir: process.env.UPLOAD_DIR ?? './uploads',

  // i18n
  supportedLanguages: (process.env.SUPPORTED_LANGUAGES ?? 'en,fr').split(','),
  defaultLanguage: process.env.DEFAULT_LANGUAGE ?? 'en',

  // Logging
  logLevel: process.env.LOG_LEVEL ?? 'info',
  logFormat: process.env.LOG_FORMAT ?? 'combined',

  // OAuth
  googleClientId: process.env.GOOGLE_CLIENT_ID ?? '',
  googleClientSecret: process.env.GOOGLE_CLIENT_SECRET ?? '',
  googleCallbackUrl:
    process.env.GOOGLE_CALLBACK_URL ?? 'http://localhost:5000/api/auth/google/callback',

  // 2FA
  twoFactorAppName: process.env.TWO_FACTOR_APP_NAME ?? 'MERN Auth v4',
  twoFactorIssuer: process.env.TWO_FACTOR_ISSUER ?? 'mernauth.com',

  // Cache
  cacheTtl: parseInt(process.env.CACHE_TTL ?? '3600', 10),
} as const;

/**
 * Validates required environment variables
 */
export const validateEnv = (): void => {
  const requiredVars = [
    'MONGODB_URI',
    'JWT_ACCESS_SECRET',
    'JWT_REFRESH_SECRET',
    'REDIS_HOST',
    'FRONTEND_URL',
  ];

  const missing = requiredVars.filter((varName) => !process.env[varName]);

  if (missing.length > 0) {
    throw new Error(`Missing required environment variables: ${missing.join(', ')}`);
  }

  if (
    process.env.NODE_ENV === 'production' &&
    (process.env.JWT_ACCESS_SECRET === 'change-this-secret' ||
      process.env.JWT_REFRESH_SECRET === 'change-this-secret')
  ) {
    throw new Error('JWT secrets must be changed in production environment');
  }
};

/**
 * Check if running in development mode
 */
export const isDevelopment = (): boolean => {
  return env.nodeEnv === 'development';
};

/**
 * Check if running in production mode
 */
export const isProduction = (): boolean => {
  return env.nodeEnv === 'production';
};

/**
 * Check if running in test mode
 */
export const isTest = (): boolean => {
  return env.nodeEnv === 'test';
};
