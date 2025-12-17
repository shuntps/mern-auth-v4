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
  req.query = sanitizeValue(req.query) as typeof req.query;
  req.params = sanitizeValue(req.params) as typeof req.params;
  req.cookies = sanitizeValue(req.cookies) as typeof req.cookies;
  next();
};
