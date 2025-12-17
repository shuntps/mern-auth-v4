import { type NextFunction, type Request, type Response } from 'express';
import { AuthenticationError } from '@utils/errors';
import { verifyAccessToken, verifyRefreshToken } from '@services/token.service';
import User from '@models/user.model';

const extractBearerToken = (req: Request): string | undefined => {
  const authHeader = req.get('authorization');
  if (!authHeader) return undefined;
  const match = authHeader.match(/^Bearer\s+(.+)$/i);
  return match?.[1];
};

const setAuthContext = (
  res: Response,
  context?: {
    userId: string;
    role?: string;
    sessionId?: string;
    accessToken?: string;
    refreshToken?: string;
  }
): void => {
  res.locals.auth = context;
};

export const authenticateRefreshToken = (req: Request, res: Response, next: NextFunction): void => {
  const { refreshToken } = req.cookies as Record<string, string | undefined>;

  if (!refreshToken) {
    throw new AuthenticationError('Not authenticated');
  }

  try {
    const payload = verifyRefreshToken(refreshToken);
    if (!payload.sessionId) {
      throw new AuthenticationError('Invalid session');
    }

    setAuthContext(res, {
      userId: payload.sub,
      sessionId: payload.sessionId,
      refreshToken,
    });

    next();
  } catch (error) {
    next(error as Error);
  }
};

export const authenticateAccessToken = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  const bearer = extractBearerToken(req);
  const cookieToken = (req.cookies as Record<string, string | undefined>).accessToken;
  const token = bearer ?? cookieToken;

  if (!token) {
    throw new AuthenticationError('Not authenticated');
  }

  try {
    const payload = verifyAccessToken(token);
    const user = await User.findById(payload.sub).select('passwordChangedAt isBanned');
    if (!user) {
      throw new AuthenticationError('User not found');
    }

    if (user.isBanned) {
      throw new AuthenticationError('Account is banned');
    }

    if (payload.iat && user.changedPasswordAfter(Number(payload.iat))) {
      throw new AuthenticationError('Password recently changed, please login again');
    }

    setAuthContext(res, {
      userId: payload.sub,
      role: payload.role,
      accessToken: token,
    });

    next();
  } catch (error) {
    next(error as Error);
  }
};

export const optionalAccessToken = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  const bearer = extractBearerToken(req);
  const cookieToken = (req.cookies as Record<string, string | undefined>).accessToken;
  const token = bearer ?? cookieToken;

  if (!token) {
    setAuthContext(res, undefined);
    next();
    return;
  }

  try {
    const payload = verifyAccessToken(token);
    const user = await User.findById(payload.sub).select('passwordChangedAt isBanned');
    if (!user || user.isBanned) {
      next();
      return;
    }

    if (payload.iat && user.changedPasswordAfter(Number(payload.iat))) {
      next();
      return;
    }

    setAuthContext(res, {
      userId: payload.sub,
      role: payload.role,
      accessToken: token,
    });
  } catch {
    // swallow errors for optional auth
  } finally {
    next();
  }
};
