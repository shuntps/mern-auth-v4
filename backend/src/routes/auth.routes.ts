import { Router } from 'express';
import {
  authLimiter,
  loginLimiter,
  passwordResetLimiter,
} from '@middleware/rateLimiter.middleware';
import { issueCsrfToken, verifyCsrfToken } from '@middleware/csrf.middleware';
import { validate } from '@middleware/validate.middleware';
import { authenticateRefreshToken } from '@middleware/auth.middleware';
import {
  registerSchema,
  loginSchema,
  forgotPasswordSchema,
  resetPasswordSchema,
  changePasswordSchema,
  verifyEmailSchema,
} from '@validators/auth.validators';
import * as authController from '@controllers/auth.controller';

const router = Router();

router.get('/auth/csrf-token', authLimiter, issueCsrfToken, authController.getCsrfToken);

router.post(
  '/auth/register',
  authLimiter,
  verifyCsrfToken,
  validate(registerSchema),
  authController.register
);
router.post(
  '/auth/verify-email',
  authLimiter,
  verifyCsrfToken,
  validate(verifyEmailSchema),
  authController.verifyEmail
);
router.post(
  '/auth/login',
  loginLimiter,
  verifyCsrfToken,
  validate(loginSchema),
  authController.login
);
router.post('/auth/logout', authLimiter, verifyCsrfToken, authController.logout);
router.post('/auth/refresh', authLimiter, verifyCsrfToken, authController.refreshToken);
router.post(
  '/auth/forgot-password',
  passwordResetLimiter,
  verifyCsrfToken,
  validate(forgotPasswordSchema),
  authController.forgotPassword
);
router.post(
  '/auth/reset-password',
  passwordResetLimiter,
  verifyCsrfToken,
  validate(resetPasswordSchema),
  authController.resetPassword
);
router.post(
  '/auth/change-password',
  authLimiter,
  verifyCsrfToken,
  authenticateRefreshToken,
  validate(changePasswordSchema),
  authController.changePassword
);

router.get(
  '/users/activity/ip-history',
  authLimiter,
  verifyCsrfToken,
  authenticateRefreshToken,
  authController.getIpHistory
);

export default router;
