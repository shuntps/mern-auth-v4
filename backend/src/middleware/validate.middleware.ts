import { type NextFunction, type Request, type Response } from 'express';
import { z } from 'zod';
import { ValidationError } from '@utils/errors';

type SchemaTarget = 'body' | 'query' | 'params' | 'headers' | 'cookies';

type SchemaMap = Partial<Record<SchemaTarget, z.ZodType>>;

interface ValidationIssue {
  location: SchemaTarget;
  path: string[];
  message: string;
  code: string;
}

const formatIssues = (
  location: SchemaTarget,
  issues: { path: (string | number | symbol)[]; message: string; code: string }[]
): ValidationIssue[] =>
  issues.map((issue) => ({
    location,
    path: issue.path.map((segment) => String(segment)),
    message: issue.message,
    code: issue.code,
  }));

const runParse = (
  schema: z.ZodType | undefined,
  value: unknown,
  location: SchemaTarget
): {
  data?: unknown;
  issues: ValidationIssue[];
} => {
  if (!schema) return { issues: [] };

  const result = schema.safeParse(value);
  if (result.success) {
    return { data: result.data, issues: [] };
  }

  return { issues: formatIssues(location, result.error.issues) };
};

export const validate =
  (schemas: SchemaMap) =>
  (req: Request, _res: Response, next: NextFunction): void => {
    const collectedIssues: ValidationIssue[] = [];

    const bodyResult = runParse(schemas.body, req.body, 'body');
    if (bodyResult.data !== undefined) req.body = bodyResult.data;
    collectedIssues.push(...bodyResult.issues);

    const queryResult = runParse(schemas.query, req.query, 'query');
    if (queryResult.data !== undefined) req.query = queryResult.data as typeof req.query;
    collectedIssues.push(...queryResult.issues);

    const paramsResult = runParse(schemas.params, req.params, 'params');
    if (paramsResult.data !== undefined) req.params = paramsResult.data as typeof req.params;
    collectedIssues.push(...paramsResult.issues);

    const headersResult = runParse(schemas.headers, req.headers, 'headers');
    if (headersResult.data !== undefined) req.headers = headersResult.data as typeof req.headers;
    collectedIssues.push(...headersResult.issues);

    const cookiesResult = runParse(schemas.cookies, req.cookies, 'cookies');
    if (cookiesResult.data !== undefined) req.cookies = cookiesResult.data as typeof req.cookies;
    collectedIssues.push(...cookiesResult.issues);

    if (collectedIssues.length > 0) {
      next(new ValidationError('Validation failed', collectedIssues));
      return;
    }

    next();
  };
