import { Router } from 'express';
import { authLimiter } from '@middleware/rateLimiter.middleware';
import { verifyCsrfToken } from '@middleware/csrf.middleware';
import { authenticateRefreshToken } from '@middleware/auth.middleware';
import { authorize } from '@middleware/authorize.middleware';
import { validate } from '@middleware/validate.middleware';
import { updateProfileSchema, deleteAccountSchema } from '@validators/user.validators';
import * as userController from '@controllers/user.controller';

const router = Router();

router.get(
  '/users/profile',
  authLimiter,
  verifyCsrfToken,
  authenticateRefreshToken,
  authorize(),
  userController.getProfile
);

router.patch(
  '/users/profile',
  authLimiter,
  verifyCsrfToken,
  authenticateRefreshToken,
  authorize(),
  validate({ body: updateProfileSchema }),
  userController.updateProfile
);

router.delete(
  '/users/account',
  authLimiter,
  verifyCsrfToken,
  authenticateRefreshToken,
  authorize(),
  validate({ body: deleteAccountSchema }),
  userController.deleteAccount
);

export default router;
