import type { Request, Response, NextFunction, RequestHandler } from 'express';

/**
 * Wraps async controllers to catch errors and forward them to centralized errorHandler.
 *
 * CRITICAL: Apply at CONTROLLER level ONLY, never at route level.
 *
 * ✅ CORRECT (controller-level):
 * export const register = asyncHandler(async (req, res, next) => { ... });
 *
 * ❌ WRONG (route-level):
 * router.post('/register', asyncHandler(authController.register));
 *
 * Ensures all async errors propagate to centralized error handler even with Express 5's native async support.
 */
export const asyncHandler =
  (fn: RequestHandler): RequestHandler =>
  (req: Request, res: Response, next: NextFunction) =>
    Promise.resolve(fn(req, res, next)).catch(next);
