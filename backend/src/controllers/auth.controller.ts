import { type Request, type CookieOptions, type RequestHandler } from 'express';
import { asyncHandler } from '@utils/asyncHandler';
import { AuthenticationError } from '@utils/errors';
import { env } from '@config/env';
import { refreshCsrfToken } from '@middleware/csrf.middleware';
import {
  registerAndAuthenticate,
  loginUser,
  refreshTokens,
  logoutSession,
  changePassword as changePasswordService,
  requestPasswordReset,
  resetPasswordWithToken,
  verifyEmailWithToken,
  getUserIpHistory,
} from '@services/auth.service';
import {
  registerSchema,
  loginSchema,
  forgotPasswordSchema,
  resetPasswordSchema,
  changePasswordSchema,
  verifyEmailSchema,
} from '@validators/auth.validators';
import { type SessionMetadata } from '@services/session.service';

const buildSessionMetadata = (req: Request): SessionMetadata => ({
  ip: req.ip,
  userAgent: req.get('user-agent') ?? undefined,
  browser: req.get('sec-ch-ua') ?? undefined,
  os: req.get('sec-ch-ua-platform') ?? undefined,
  device: req.get('sec-ch-ua-mobile') ?? undefined,
});

const buildCookieOptions = (maxAge: number): CookieOptions => ({
  httpOnly: true,
  secure: env.cookieSecure,
  sameSite: env.cookieSameSite,
  maxAge,
});

const accessCookieOptions = buildCookieOptions(env.cookieMaxAge);
const refreshCookieOptions = buildCookieOptions(env.cookieMaxAge);

export const register: RequestHandler = asyncHandler(async (req, res) => {
  const { email, password, firstName, lastName } = registerSchema.parse(req.body);
  const { accessToken, refreshToken, user } = await registerAndAuthenticate(
    { email, password, firstName, lastName },
    buildSessionMetadata(req)
  );

  const csrfToken = refreshCsrfToken(res);

  res
    .cookie('accessToken', accessToken, accessCookieOptions)
    .cookie('refreshToken', refreshToken, refreshCookieOptions)
    .status(201)
    .json({
      status: 'success',
      data: { user, accessToken, csrfToken },
    });
});

export const login: RequestHandler = asyncHandler(async (req, res) => {
  const { email, password } = loginSchema.parse(req.body);

  const { accessToken, refreshToken, user } = await loginUser(
    email,
    password,
    buildSessionMetadata(req)
  );

  const csrfToken = refreshCsrfToken(res);

  res
    .cookie('accessToken', accessToken, accessCookieOptions)
    .cookie('refreshToken', refreshToken, refreshCookieOptions)
    .status(200)
    .json({
      status: 'success',
      data: { accessToken, user, csrfToken },
    });
});

export const refreshToken: RequestHandler = asyncHandler(async (req, res) => {
  const { refreshToken } = req.cookies as Record<string, string | undefined>;
  if (!refreshToken) {
    throw new AuthenticationError('Refresh token missing');
  }

  const { accessToken, refreshToken: newRefreshToken } = await refreshTokens(refreshToken);

  res
    .cookie('accessToken', accessToken, accessCookieOptions)
    .cookie('refreshToken', newRefreshToken, refreshCookieOptions)
    .status(200)
    .json({
      status: 'success',
      data: {
        accessToken,
      },
    });
});

export const logout: RequestHandler = asyncHandler(async (req, res) => {
  const { refreshToken } = req.cookies as Record<string, string | undefined>;

  await logoutSession(refreshToken);

  res
    .clearCookie('accessToken')
    .clearCookie('refreshToken')
    .status(200)
    .json({ status: 'success' });
});

export const forgotPassword: RequestHandler = asyncHandler(async (req, res) => {
  const { email } = forgotPasswordSchema.parse(req.body);
  await requestPasswordReset(email);

  res.status(200).json({ status: 'success' });
});

export const resetPassword: RequestHandler = asyncHandler(async (req, res) => {
  const { token, newPassword } = resetPasswordSchema.parse(req.body);
  await resetPasswordWithToken(token, newPassword);

  res.status(200).json({ status: 'success' });
});

export const verifyEmail: RequestHandler = asyncHandler(async (req, res) => {
  const { token } = verifyEmailSchema.parse(req.body);
  const user = await verifyEmailWithToken(token);

  res.status(200).json({
    status: 'success',
    data: { user },
  });
});

export const getCsrfToken: RequestHandler = asyncHandler((_req, res) => {
  const token = res.locals.csrfToken;
  res.status(200).json({
    status: 'success',
    data: { csrfToken: token },
  });
});

export const changePassword: RequestHandler = asyncHandler(async (req, res) => {
  const { oldPassword, newPassword } = changePasswordSchema.parse(req.body);
  const authContext = res.locals.auth as { refreshToken?: unknown } | undefined;
  const refreshToken =
    typeof authContext?.refreshToken === 'string' ? authContext.refreshToken : undefined;

  await changePasswordService(refreshToken, oldPassword, newPassword);

  res
    .clearCookie('accessToken')
    .clearCookie('refreshToken')
    .clearCookie('csrfToken')
    .status(200)
    .json({ status: 'success' });
});

export const getIpHistory: RequestHandler = asyncHandler(async (_req, res) => {
  const authContext = res.locals.auth as { userId?: string } | undefined;
  if (!authContext?.userId) {
    throw new AuthenticationError('Not authenticated');
  }

  const ipHistory = await getUserIpHistory(authContext.userId);

  res.status(200).json({ status: 'success', data: { ipHistory } });
});
