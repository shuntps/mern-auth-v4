import { type NextFunction, type Request, type Response } from 'express';
import User from '@models/user.model';
import { verifyAccessToken } from '@services/token.service';

const ACTIVITY_UPDATE_INTERVAL_MS = 60_000;

const extractAccessToken = (req: Request): string | undefined => {
  const cookies = req.cookies as Record<string, string | undefined> | undefined;
  const cookieToken = cookies?.accessToken;
  if (cookieToken) {
    return cookieToken;
  }

  const authHeader = req.get('authorization');
  if (!authHeader) {
    return undefined;
  }

  const [scheme, token] = authHeader.split(' ');
  if (scheme?.toLowerCase() !== 'bearer' || !token) {
    return undefined;
  }

  return token;
};

export const touchLastActivity = async (
  req: Request,
  _res: Response,
  next: NextFunction
): Promise<void> => {
  if (req.path === '/health' || req.method === 'OPTIONS') {
    next();
    return;
  }

  const token = extractAccessToken(req);
  if (!token) {
    next();
    return;
  }

  try {
    const payload = verifyAccessToken(token);
    const user = await User.findById(payload.sub).select('lastActivity ipHistory');
    if (!user) {
      next();
      return;
    }

    const now = new Date();
    const lastActivity = user.lastActivity ? user.lastActivity.getTime() : 0;
    const shouldUpdateTimestamp = now.getTime() - lastActivity >= ACTIVITY_UPDATE_INTERVAL_MS;

    const ip = req.ip;
    const ipHistory = user.ipHistory;
    const shouldUpdateIp = ip ? !ipHistory.includes(ip) : false;

    if (!shouldUpdateTimestamp && !shouldUpdateIp) {
      next();
      return;
    }

    if (shouldUpdateTimestamp) {
      user.lastActivity = now;
    }

    if (ip) {
      user.ipHistory = [ip, ...ipHistory.filter((entry) => entry !== ip)].slice(0, 10);
    }

    await user.save({ validateModifiedOnly: true });
  } catch {
    // Best-effort update; ignore token verification or persistence errors
  }

  next();
};
