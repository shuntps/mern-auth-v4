export class AppError extends Error {
  public readonly statusCode: number;
  public readonly isOperational: boolean;
  public readonly code?: string;
  public readonly details?: unknown; // optional for validation info

  constructor(
    message: string,
    statusCode = 500,
    isOperational = true,
    details?: unknown,
    code?: string
  ) {
    super(message);
    this.statusCode = statusCode;
    this.isOperational = isOperational;
    this.details = details;
    this.code = code;

    Error.captureStackTrace(this, this.constructor);
    Object.setPrototypeOf(this, AppError.prototype);
  }

  toJSON(): { status: string; message: string; details?: unknown; code?: string } {
    const response: { status: string; message: string; details?: unknown; code?: string } = {
      status: 'error',
      message: this.message,
    };
    if (this.details !== undefined) {
      response.details = this.details;
    }
    if (this.code) {
      response.code = this.code;
    }
    return response;
  }
}

// Subclasses
export class ValidationError extends AppError {
  constructor(message = 'Validation failed', details?: unknown) {
    super(message, 400, true, details);
    Object.setPrototypeOf(this, ValidationError.prototype);
  }
}

export class AuthenticationError extends AppError {
  constructor(message = 'Authentication failed') {
    super(message, 401);
    Object.setPrototypeOf(this, AuthenticationError.prototype);
  }
}

export class CsrfBlockedError extends AppError {
  constructor(message = 'errors.csrf.blocked', retryAfterSeconds?: number) {
    super(
      message,
      429,
      true,
      {
        code: 'CSRF_BLOCKED',
        retryAfterSeconds,
      },
      'CSRF_BLOCKED'
    );
    Object.setPrototypeOf(this, CsrfBlockedError.prototype);
  }
}

export class AuthorizationError extends AppError {
  constructor(message = 'Access denied') {
    super(message, 403);
    Object.setPrototypeOf(this, AuthorizationError.prototype);
  }
}

export class NotFoundError extends AppError {
  constructor(message = 'Resource not found') {
    super(message, 404);
    Object.setPrototypeOf(this, NotFoundError.prototype);
  }
}

export class ConflictError extends AppError {
  constructor(message = 'Resource already exists') {
    super(message, 409);
    Object.setPrototypeOf(this, ConflictError.prototype);
  }
}
