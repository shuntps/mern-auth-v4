import { type CookieOptions, type RequestHandler } from 'express';
import { type z } from 'zod';
import { asyncHandler } from '@utils/asyncHandler';
import { AuthenticationError } from '@utils/errors';
import { env } from '@config/env';
import { refreshCsrfToken } from '@middleware/csrf.middleware';
import { buildSessionMetadata } from '@utils/request';
import {
  registerAndAuthenticate,
  loginUser,
  refreshTokens,
  logoutSession,
  changePassword as changePasswordService,
  startTwoFactorSetup,
  verifyTwoFactorSetup,
  disableTwoFactor as disableTwoFactorService,
  requestPasswordReset,
  resetPasswordWithToken,
  verifyEmailWithToken,
  getUserIpHistory,
  type AuthTokens,
  type AuthUser,
} from '@services/auth.service';
import {
  registerSchema,
  loginSchema,
  forgotPasswordSchema,
  resetPasswordSchema,
  changePasswordSchema,
  verifyEmailSchema,
  twoFactorVerifySchema,
  twoFactorDisableSchema,
} from '@validators/auth.validators';

type RegisterBody = z.infer<typeof registerSchema>;
type LoginBody = z.infer<typeof loginSchema>;
type ForgotPasswordBody = z.infer<typeof forgotPasswordSchema>;
type ResetPasswordBody = z.infer<typeof resetPasswordSchema>;
type VerifyEmailBody = z.infer<typeof verifyEmailSchema>;
type ChangePasswordBody = z.infer<typeof changePasswordSchema>;
type TwoFactorVerifyBody = z.infer<typeof twoFactorVerifySchema>;
type TwoFactorDisableBody = z.infer<typeof twoFactorDisableSchema>;

const buildCookieOptions = (maxAge: number): CookieOptions => ({
  httpOnly: true,
  secure: env.cookieSecure,
  sameSite: env.cookieSameSite,
  maxAge,
});

const accessCookieOptions = buildCookieOptions(env.cookieMaxAge);
const refreshCookieOptions = buildCookieOptions(env.cookieMaxAge);

const buildOAuthRedirectUrl = (params?: { error?: string }): string => {
  const url = new URL('/auth/callback', env.frontendUrl);
  if (params?.error) {
    url.searchParams.set('error', params.error);
  } else {
    url.searchParams.set('status', 'success');
  }
  return url.toString();
};

export const register: RequestHandler = asyncHandler(async (req, res) => {
  const { email, password, firstName, lastName } = req.body as RegisterBody;
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
  const { email, password, twoFactorCode } = req.body as LoginBody;

  const { accessToken, refreshToken, user } = await loginUser(
    email,
    password,
    buildSessionMetadata(req),
    twoFactorCode
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
    throw new AuthenticationError('errors.refreshTokenMissing');
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
  const { email } = req.body as ForgotPasswordBody;
  await requestPasswordReset(email);

  res.status(200).json({ status: 'success' });
});

export const resetPassword: RequestHandler = asyncHandler(async (req, res) => {
  const { token, newPassword } = req.body as ResetPasswordBody;
  await resetPasswordWithToken(token, newPassword);

  res.status(200).json({ status: 'success' });
});

export const verifyEmail: RequestHandler = asyncHandler(async (req, res) => {
  const { token } = req.body as VerifyEmailBody;
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
  const { oldPassword, newPassword } = req.body as ChangePasswordBody;
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
    throw new AuthenticationError('errors.notAuthenticated');
  }

  const ipHistory = await getUserIpHistory(authContext.userId);

  res.status(200).json({ status: 'success', data: { ipHistory } });
});

export const enableTwoFactor: RequestHandler = asyncHandler(async (_req, res) => {
  const authContext = res.locals.auth as { userId?: string } | undefined;
  if (!authContext?.userId) {
    throw new AuthenticationError('errors.notAuthenticated');
  }

  const setup = await startTwoFactorSetup(authContext.userId);

  res.status(200).json({ status: 'success', data: setup });
});

export const verifyTwoFactor: RequestHandler = asyncHandler(async (req, res) => {
  const authContext = res.locals.auth as { userId?: string } | undefined;
  if (!authContext?.userId) {
    throw new AuthenticationError('errors.notAuthenticated');
  }

  const { token } = req.body as TwoFactorVerifyBody;
  const user = await verifyTwoFactorSetup(authContext.userId, token);

  res.status(200).json({ status: 'success', data: { user } });
});

export const disableTwoFactor: RequestHandler = asyncHandler(async (req, res) => {
  const authContext = res.locals.auth as { userId?: string } | undefined;
  if (!authContext?.userId) {
    throw new AuthenticationError('errors.notAuthenticated');
  }

  const { token } = req.body as TwoFactorDisableBody;
  const user = await disableTwoFactorService(authContext.userId, token);

  res.status(200).json({ status: 'success', data: { user } });
});

type OAuthResult = AuthTokens & { user: AuthUser };

export const googleOAuthCallback: RequestHandler = asyncHandler((req, res) => {
  const authResult = req.user as OAuthResult | undefined;

  if (!authResult) {
    res.redirect(buildOAuthRedirectUrl({ error: 'google_auth_failed' }));
    return;
  }

  refreshCsrfToken(res);

  res
    .cookie('accessToken', authResult.accessToken, accessCookieOptions)
    .cookie('refreshToken', authResult.refreshToken, refreshCookieOptions)
    .redirect(buildOAuthRedirectUrl());
});
