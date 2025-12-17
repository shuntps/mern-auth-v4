import express, { Express, Request, Response } from 'express';
import helmet from 'helmet';
import cors from 'cors';
import compression from 'compression';
import morgan from 'morgan';
import cookieParser from 'cookie-parser';
import { env, validateEnv, isDevelopment, isProduction, isTest } from '@config/env';
import { connectDatabase, getDatabaseStatus } from '@config/database';
import { getRedisStatus } from '@config/redis';
import logger from '@config/logger';
import passport from '@config/oauth';
import { errorHandler, notFoundHandler } from '@middleware/errorHandler';
import { touchLastActivity } from '@middleware/activity.middleware';
import { generalLimiter } from '@middleware/rateLimiter.middleware';
import routes from '@routes/index';
import { seedDefaultRoles } from '@models/role.model';

/**
 * Create and configure Express application
 */
export const createApp = (): Express => {
  const app = express();

  // Honor reverse proxy headers when deployed behind a proxy (HTTPS enforcement relies on this)
  if (isProduction()) {
    app.set('trust proxy', 1);
  }

  // Security middleware
  app.use(
    helmet({
      contentSecurityPolicy: isDevelopment() ? false : undefined,
      crossOriginEmbedderPolicy: false,
    })
  );

  // CORS configuration
  app.use(
    cors({
      origin: env.corsOrigin,
      credentials: true,
      methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token'],
    })
  );

  // Enforce HTTPS in production (expects `trust proxy` set when behind a proxy)
  app.use((req, res, next) => {
    if (!isProduction()) {
      next();
      return;
    }

    // Allow health checks and loopback hosts without HTTPS
    const host = req.get('host') ?? '';
    if (req.path === '/health' || host.includes('localhost') || host.startsWith('127.0.0.1')) {
      next();
      return;
    }

    const isSecure = req.secure || req.get('x-forwarded-proto') === 'https';
    if (isSecure) {
      next();
      return;
    }
    return res.status(400).json({ status: 'fail', message: 'Use HTTPS' });
  });

  // Compression middleware
  app.use(compression());

  // Body parsing middleware
  app.use(express.json({ limit: '10mb' }));
  app.use(express.urlencoded({ extended: true, limit: '10mb' }));

  // Cookie parser
  app.use(cookieParser());

  // Passport initialization for OAuth strategies
  app.use(passport.initialize());

  // Update last activity for authenticated requests (best-effort)
  app.use(touchLastActivity);

  // HTTP request logger
  if (isDevelopment()) {
    app.use(morgan('dev'));
  } else {
    app.use(morgan(env.logFormat));
  }

  // Apply general rate limiter to all routes
  app.use(generalLimiter);

  // API routes
  app.use(env.apiBasePath, routes);

  // Health check endpoint
  app.get('/health', (_req: Request, res: Response) => {
    const dbStatus = getDatabaseStatus();
    const redisStatus = getRedisStatus();

    res.json({
      status: 'ok',
      timestamp: new Date().toISOString(),
      environment: env.nodeEnv,
      database: {
        status: dbStatus.state,
        host: dbStatus.host,
        name: dbStatus.name,
      },
      redis: {
        status: redisStatus,
      },
    });
  });

  // API routes will be mounted here
  // app.use(env.apiBasePath, routes);

  // 404 handler - Must be BEFORE error handler
  app.use(notFoundHandler);

  // Centralized error handler - Must be LAST middleware
  app.use(errorHandler);

  return app;
};

/**
 * Start the server
 */
const startServer = async (): Promise<void> => {
  try {
    // Validate environment variables
    validateEnv();
    logger.info('Environment variables validated');

    // Connect to databases
    await connectDatabase();

    // Seed default roles
    await seedDefaultRoles();
    logger.info('Default roles seeded');

    // Create Express app
    const app = createApp();

    // Start listening
    const server = app.listen(env.port, () => {
      logger.info(`Server running on port ${env.port.toString()}`);
      logger.info(`Environment: ${env.nodeEnv}`);
      logger.info(`API Base Path: ${env.apiBasePath}`);
      logger.info(`CORS Origin: ${env.corsOrigin}`);
    });

    // Graceful shutdown
    const gracefulShutdown = (signal: string): void => {
      logger.info(`${signal} received, starting graceful shutdown...`);

      server.close(() => {
        logger.info('HTTP server closed');
        process.exit(0);
      });

      // Force shutdown after 10 seconds
      setTimeout(() => {
        logger.error('Forced shutdown after timeout');
        process.exit(1);
      }, 10000);
    };

    process.on('SIGTERM', () => {
      gracefulShutdown('SIGTERM');
    });
    process.on('SIGINT', () => {
      gracefulShutdown('SIGINT');
    });
  } catch (error) {
    logger.error('Failed to start server:', error);
    process.exit(1);
  }
};

// Start the server
if (!isTest()) {
  void startServer();
}
