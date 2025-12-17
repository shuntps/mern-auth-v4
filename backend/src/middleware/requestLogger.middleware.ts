import { type NextFunction, type Request, type Response } from 'express';
import logger from '@config/logger';

export const requestLogger = (req: Request, res: Response, next: NextFunction): void => {
  const start = Date.now();
  res.on('finish', () => {
    const durationMs = Date.now() - start;
    const userId = res.locals.auth?.userId ?? 'anonymous';
    const sessionId = res.locals.auth?.sessionId ?? 'n/a';
    const userAgent = req.get('user-agent') ?? 'unknown';
    const ip = res.locals.clientIp ?? req.ip ?? 'unknown';
    const fingerprint = res.locals.requestFingerprint ?? 'n/a';

    logger.info(
      `${req.method} ${req.originalUrl} ${res.statusCode.toString()} ${durationMs.toString()}ms ip=${ip} user=${userId} session=${sessionId} fp=${fingerprint} ua="${userAgent}"`
    );
  });
  next();
};
