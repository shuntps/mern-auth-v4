import jwt, { type JwtPayload, type Secret, type SignOptions } from 'jsonwebtoken';
import { env } from '@config/env';
import { AuthenticationError, AppError } from '@utils/errors';

export type AccessTokenPayload = JwtPayload & {
  sub: string; // user id
  role: string;
  type: 'access';
};

export type RefreshTokenPayload = JwtPayload & {
  sub: string; // user id
  sessionId?: string;
  type: 'refresh';
};

const signToken = (
  payload: AccessTokenPayload | RefreshTokenPayload,
  secret: Secret,
  expiresIn: SignOptions['expiresIn']
): string => {
  try {
    return jwt.sign(payload, secret, { expiresIn });
  } catch (error) {
    throw new AppError('errors.tokenGenerationFailed', 500, false, error);
  }
};

export const generateAccessToken = (userId: string, role: string): string => {
  const payload: AccessTokenPayload = {
    sub: userId,
    role,
    type: 'access',
  };
  const expiresIn = env.jwtAccessExpiresIn as SignOptions['expiresIn'];
  return signToken(payload, env.jwtAccessSecret, expiresIn);
};

export const generateRefreshToken = (userId: string, sessionId?: string): string => {
  const payload: RefreshTokenPayload = {
    sub: userId,
    sessionId,
    type: 'refresh',
  };
  const expiresIn = env.jwtRefreshExpiresIn as SignOptions['expiresIn'];
  return signToken(payload, env.jwtRefreshSecret, expiresIn);
};

const verifyToken = (token: string, secret: Secret): JwtPayload => {
  try {
    return jwt.verify(token, secret) as JwtPayload;
  } catch {
    throw new AuthenticationError('errors.tokenInvalid');
  }
};

export const verifyAccessToken = (token: string): AccessTokenPayload => {
  return verifyToken(token, env.jwtAccessSecret) as AccessTokenPayload;
};

export const verifyRefreshToken = (token: string): RefreshTokenPayload => {
  return verifyToken(token, env.jwtRefreshSecret) as RefreshTokenPayload;
};
