import { type NextFunction, type Request, type Response } from 'express';
import { buildRequestFingerprint, getClientIp } from '@utils/request';

export const attachRequestFingerprint = (req: Request, res: Response, next: NextFunction): void => {
  const clientIp = getClientIp(req);
  res.locals.clientIp = clientIp;
  res.locals.requestFingerprint = buildRequestFingerprint(req);
  next();
};
