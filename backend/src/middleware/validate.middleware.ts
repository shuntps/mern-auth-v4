import { type NextFunction, type Request, type Response } from 'express';
import { ZodError, type ZodType } from 'zod';
import { ValidationError } from '@utils/errors';

export const validate =
  (schema: ZodType) =>
  (req: Request, _res: Response, next: NextFunction): void => {
    try {
      schema.parse(req.body);
      next();
    } catch (err) {
      if (err instanceof ZodError) {
        const details = err.issues.map((issue) => ({
          path: issue.path,
          message: issue.message,
          code: issue.code,
        }));
        next(new ValidationError('Validation failed', details));
        return;
      }
      next(err as Error);
    }
  };
