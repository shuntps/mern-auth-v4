import { type TranslationKey, type TranslationParams } from '@config/i18n';

export class AppError extends Error {
  public readonly statusCode: number;
  public readonly isOperational: boolean;
  public readonly code?: string;
  public readonly details?: unknown; // optional for validation info
  public readonly messageKey: TranslationKey;
  public readonly params?: TranslationParams;

  constructor(
    messageKey: TranslationKey,
    statusCode = 500,
    isOperational = true,
    details?: unknown,
    code?: string,
    params?: TranslationParams
  ) {
    super(messageKey);
    this.statusCode = statusCode;
    this.isOperational = isOperational;
    this.details = details;
    this.code = code;
    this.messageKey = messageKey;
    this.params = params;

    Error.captureStackTrace(this, this.constructor);
    Object.setPrototypeOf(this, AppError.prototype);
  }

  toJSON(): {
    status: string;
    message: string;
    key: TranslationKey;
    details?: unknown;
    code?: string;
  } {
    const response: {
      status: string;
      message: string;
      key: TranslationKey;
      details?: unknown;
      code?: string;
    } = {
      status: 'error',
      message: this.message,
      key: this.messageKey,
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
  constructor(message: TranslationKey = 'errors.validationFailed', details?: unknown) {
    super(message, 400, true, details);
    Object.setPrototypeOf(this, ValidationError.prototype);
  }
}

export class AuthenticationError extends AppError {
  constructor(message: TranslationKey = 'errors.authenticationFailed') {
    super(message, 401);
    Object.setPrototypeOf(this, AuthenticationError.prototype);
  }
}

export class CsrfBlockedError extends AppError {
  constructor(message: TranslationKey = 'errors.csrfBlocked', retryAfterSeconds?: number) {
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
  constructor(message: TranslationKey = 'errors.accessDenied') {
    super(message, 403);
    Object.setPrototypeOf(this, AuthorizationError.prototype);
  }
}

export class NotFoundError extends AppError {
  constructor(message: TranslationKey = 'errors.notFound', details?: unknown) {
    super(message, 404, true, details);
    Object.setPrototypeOf(this, NotFoundError.prototype);
  }
}

export class ConflictError extends AppError {
  constructor(message: TranslationKey = 'errors.conflict') {
    super(message, 409);
    Object.setPrototypeOf(this, ConflictError.prototype);
  }
}
