import { type NextFunction, type Request, type Response } from 'express';
import { AuthenticationError } from '@utils/errors';
import { verifyRefreshToken } from '@services/token.service';

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

    res.locals.auth = {
      userId: payload.sub,
      sessionId: payload.sessionId,
      refreshToken,
    };

    next();
  } catch (error) {
    next(error as Error);
  }
};
