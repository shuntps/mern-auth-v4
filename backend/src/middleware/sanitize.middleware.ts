import { type NextFunction, type Request, type Response } from 'express';

const sanitizeString = (value: string): string => {
  return value
    .replace(/<script[\s\S]*?>[\s\S]*?<\/script>/gi, '')
    .replace(/javascript:/gi, '')
    .replace(/on\w+\s*=\s*(['"]).*?\1/gi, '');
};

const sanitizeValue = (value: unknown): unknown => {
  if (Array.isArray(value)) {
    return value.map(sanitizeValue);
  }

  if (value && typeof value === 'object') {
    return Object.entries(value as Record<string, unknown>).reduce<Record<string, unknown>>(
      (acc, [key, val]) => {
        acc[key] = sanitizeValue(val);
        return acc;
      },
      {}
    );
  }

  if (typeof value === 'string') {
    return sanitizeString(value);
  }

  return value;
};

export const sanitizeRequest = (req: Request, _res: Response, next: NextFunction): void => {
  req.body = sanitizeValue(req.body);

  const sanitizedQuery = sanitizeValue(req.query);
  if (sanitizedQuery && typeof sanitizedQuery === 'object') {
    Object.assign(req.query as Record<string, unknown>, sanitizedQuery as Record<string, unknown>);
  }

  const sanitizedParams = sanitizeValue(req.params);
  if (sanitizedParams && typeof sanitizedParams === 'object') {
    Object.assign(
      req.params as Record<string, unknown>,
      sanitizedParams as Record<string, unknown>
    );
  }

  const sanitizedCookies = sanitizeValue(req.cookies);
  if (sanitizedCookies && typeof sanitizedCookies === 'object') {
    Object.assign(
      req.cookies as Record<string, unknown>,
      sanitizedCookies as Record<string, unknown>
    );
  }
  next();
};
