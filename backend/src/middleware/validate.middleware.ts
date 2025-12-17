import { type NextFunction, type Request, type Response } from 'express';
import { z } from 'zod';
import { ValidationError } from '@utils/errors';
import i18n, { type TranslateFn, type TranslationKey } from '@config/i18n';

type SchemaTarget = 'body' | 'query' | 'params' | 'headers' | 'cookies';

type SchemaMap = Partial<Record<SchemaTarget, z.ZodType>>;

interface ValidationIssue {
  location: SchemaTarget;
  path: string[];
  message: string;
  key: TranslationKey;
  code: string;
}

const formatIssues = (
  location: SchemaTarget,
  issues: { path: (string | number | symbol)[]; message: string; code: string }[],
  translate: TranslateFn
): ValidationIssue[] =>
  issues.map((issue) => ({
    location,
    path: issue.path.map((segment) => String(segment)),
    key: issue.message as TranslationKey,
    message: translate(issue.message as TranslationKey),
    code: issue.code,
  }));

const runParse = (
  schema: z.ZodType | undefined,
  value: unknown,
  location: SchemaTarget,
  translate: TranslateFn
): {
  data?: unknown;
  issues: ValidationIssue[];
} => {
  if (!schema) return { issues: [] };

  const result = schema.safeParse(value);
  if (result.success) {
    return { data: result.data, issues: [] };
  }

  return { issues: formatIssues(location, result.error.issues, translate) };
};

export const validate =
  (schemas: SchemaMap) =>
  (req: Request, _res: Response, next: NextFunction): void => {
    const translate: TranslateFn = req.t ?? i18n.getTranslator(req.locale);
    const collectedIssues: ValidationIssue[] = [];

    const bodyResult = runParse(schemas.body, req.body, 'body', translate);
    if (bodyResult.data !== undefined) req.body = bodyResult.data;
    collectedIssues.push(...bodyResult.issues);

    const queryResult = runParse(schemas.query, req.query, 'query', translate);
    if (queryResult.data !== undefined) req.query = queryResult.data as typeof req.query;
    collectedIssues.push(...queryResult.issues);

    const paramsResult = runParse(schemas.params, req.params, 'params', translate);
    if (paramsResult.data !== undefined) req.params = paramsResult.data as typeof req.params;
    collectedIssues.push(...paramsResult.issues);

    const headersResult = runParse(schemas.headers, req.headers, 'headers', translate);
    if (headersResult.data !== undefined) req.headers = headersResult.data as typeof req.headers;
    collectedIssues.push(...headersResult.issues);

    const cookiesResult = runParse(schemas.cookies, req.cookies, 'cookies', translate);
    if (cookiesResult.data !== undefined) req.cookies = cookiesResult.data as typeof req.cookies;
    collectedIssues.push(...cookiesResult.issues);

    if (collectedIssues.length > 0) {
      next(new ValidationError('errors.validationFailed', collectedIssues));
      return;
    }

    next();
  };
