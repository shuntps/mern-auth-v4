import { Router, type RequestHandler } from 'express';
import {
  authLimiter,
  loginLimiter,
  passwordResetLimiter,
} from '@middleware/rateLimiter.middleware';
import { issueCsrfToken, verifyCsrfToken } from '@middleware/csrf.middleware';
import { validate } from '@middleware/validate.middleware';
import { authenticateRefreshToken } from '@middleware/auth.middleware';
import { authorize } from '@middleware/authorize.middleware';
import passport, { isGoogleOAuthEnabled } from '@config/oauth';
import { env } from '@config/env';
import { type AuthenticateOptions } from 'passport';
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
import * as authController from '@controllers/auth.controller';

const router = Router();

const authenticate: (strategy: string, options: AuthenticateOptions) => RequestHandler = (
  strategy,
  options
) => passport.authenticate(strategy, options) as RequestHandler;

const googleAuthHandler = authenticate('google', {
  scope: ['profile', 'email'],
  session: false,
});

const googleAuthCallbackHandler = authenticate('google', {
  session: false,
  failureRedirect: `${env.frontendUrl}/auth/callback?error=google_auth_failed`,
});

router.get('/auth/csrf-token', authLimiter, issueCsrfToken, authController.getCsrfToken);

if (isGoogleOAuthEnabled) {
  router.get('/auth/google', authLimiter, googleAuthHandler);

  router.get(
    '/auth/google/callback',
    authLimiter,
    googleAuthCallbackHandler,
    authController.googleOAuthCallback
  );
}

router.post(
  '/auth/register',
  authLimiter,
  verifyCsrfToken,
  validate({ body: registerSchema }),
  authController.register
);
router.post(
  '/auth/verify-email',
  authLimiter,
  verifyCsrfToken,
  validate({ body: verifyEmailSchema }),
  authController.verifyEmail
);
router.post(
  '/auth/login',
  loginLimiter,
  verifyCsrfToken,
  validate({ body: loginSchema }),
  authController.login
);
router.post('/auth/logout', authLimiter, verifyCsrfToken, authController.logout);
router.post('/auth/refresh', authLimiter, verifyCsrfToken, authController.refreshToken);
router.post(
  '/auth/forgot-password',
  passwordResetLimiter,
  verifyCsrfToken,
  validate({ body: forgotPasswordSchema }),
  authController.forgotPassword
);
router.post(
  '/auth/reset-password',
  passwordResetLimiter,
  verifyCsrfToken,
  validate({ body: resetPasswordSchema }),
  authController.resetPassword
);
router.post(
  '/auth/change-password',
  authLimiter,
  verifyCsrfToken,
  authenticateRefreshToken,
  validate({ body: changePasswordSchema }),
  authController.changePassword
);

router.post(
  '/auth/2fa/enable',
  authLimiter,
  verifyCsrfToken,
  authenticateRefreshToken,
  authorize(),
  authController.enableTwoFactor
);

router.post(
  '/auth/2fa/verify',
  authLimiter,
  verifyCsrfToken,
  authenticateRefreshToken,
  authorize(),
  validate({ body: twoFactorVerifySchema }),
  authController.verifyTwoFactor
);

router.post(
  '/auth/2fa/disable',
  authLimiter,
  verifyCsrfToken,
  authenticateRefreshToken,
  authorize(),
  validate({ body: twoFactorDisableSchema }),
  authController.disableTwoFactor
);

router.get(
  '/users/activity/ip-history',
  authLimiter,
  verifyCsrfToken,
  authenticateRefreshToken,
  authorize(),
  authController.getIpHistory
);

export default router;
