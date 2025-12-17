import winston from 'winston';
import path from 'path';

const { combine, timestamp, printf, colorize, errors } = winston.format;

/**
 * Custom log format for better readability
 */
const customFormat = printf((info) => {
  const {
    level,
    message,
    timestamp: logTimestamp,
    stack,
  } = info as {
    level: string;
    message: string;
    timestamp: string;
    stack?: string;
  };
  if (stack) {
    return `${logTimestamp} [${level}]: ${message}\n${stack}`;
  }
  return `${logTimestamp} [${level}]: ${message}`;
});

/**
 * Determine log level based on environment
 */
const getLogLevel = (): string => {
  const level = process.env.LOG_LEVEL ?? 'info';
  return level;
};

/**
 * Create logs directory path
 */
const getLogsDir = (): string => {
  return path.join(process.cwd(), 'logs');
};

/**
 * Winston logger instance with file and console transports
 */
const logger = winston.createLogger({
  level: getLogLevel(),
  format: combine(
    errors({ stack: true }),
    timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    customFormat
  ),
  transports: [
    // Error logs - separate file
    new winston.transports.File({
      filename: path.join(getLogsDir(), 'error.log'),
      level: 'error',
      maxsize: 5242880, // 5MB
      maxFiles: 5,
    }),
    // Combined logs - all levels
    new winston.transports.File({
      filename: path.join(getLogsDir(), 'combined.log'),
      maxsize: 5242880, // 5MB
      maxFiles: 5,
    }),
  ],
  // Handle uncaught exceptions and rejections
  exceptionHandlers: [
    new winston.transports.File({
      filename: path.join(getLogsDir(), 'exceptions.log'),
    }),
  ],
  rejectionHandlers: [
    new winston.transports.File({
      filename: path.join(getLogsDir(), 'rejections.log'),
    }),
  ],
});

/**
 * Add console transport for development environment
 */
if (process.env.NODE_ENV !== 'production') {
  logger.add(
    new winston.transports.Console({
      format: combine(colorize(), timestamp({ format: 'HH:mm:ss' }), customFormat),
    })
  );
}

export default logger;
