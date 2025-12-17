/**
 * Centralized Error Handler Middleware
 * ALL errors in the application must flow through this handler
 */

import { Request, Response, NextFunction } from 'express';
import { AppError, NotFoundError } from '@utils/errors';
import logger from '@config/logger';
import { isDevelopment } from '@config/env';

/**
 * Express error handling middleware
 * Must be registered as the LAST middleware in the Express app
 */
export const errorHandler = (
  err: Error,
  req: Request,
  res: Response,
  _next: NextFunction
): void => {
  // Check if error is operational (trusted error)
  const isOperational = err instanceof AppError && err.isOperational;

  // Default error values
  let statusCode = 500;
  let message = 'Internal server error';

  // If it's an operational error, use its properties
  if (err instanceof AppError) {
    statusCode = err.statusCode;
    message = err.message;
  }

  // Log error with context
  const errorLog = {
    message: err.message,
    statusCode,
    isOperational,
    method: req.method,
    url: req.originalUrl,
    ip: req.ip,
    userAgent: req.get('user-agent'),
    stack: err.stack,
  };

  // Log operational errors as warnings, programming errors as errors
  if (isOperational) {
    logger.warn('Operational error occurred', errorLog);
  } else {
    logger.error('Programming error occurred', errorLog);
  }

  // Prepare error response
  interface ErrorResponse {
    status: string;
    message: string;
    details?: unknown;
    stack?: string;
  }

  // Use toJSON method for AppError instances to get consistent response format
  const errorResponse: ErrorResponse =
    err instanceof AppError
      ? (err.toJSON() as ErrorResponse)
      : {
          status: 'error',
          message,
        };

  // Include stack trace only in development mode and for programming errors
  if (isDevelopment() && !isOperational) {
    errorResponse.stack = err.stack;
  }

  // Send error response (void return to satisfy Express error handler signature)
  void (res.status(statusCode).json(errorResponse) as unknown);
};

/**
 * 404 Not Found handler
 * Should be registered BEFORE the error handler
 */
export const notFoundHandler = (req: Request, _res: Response, next: NextFunction): void => {
  const error = new NotFoundError(`Route not found: ${req.method} ${req.originalUrl}`);
  next(error);
};
