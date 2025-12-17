import { type RequestHandler } from 'express';
import { type z } from 'zod';
import { asyncHandler } from '@utils/asyncHandler';
import { AuthenticationError } from '@utils/errors';
import {
  getProfile as getProfileService,
  updateProfile as updateProfileService,
  deleteAccount as deleteAccountService,
} from '@services/user.service';
import { updateProfileSchema, deleteAccountSchema } from '@validators/user.validators';

type UpdateProfileBody = z.infer<typeof updateProfileSchema>;
type DeleteAccountBody = z.infer<typeof deleteAccountSchema>;

const requireUserId = (res: Parameters<RequestHandler>[1]): string => {
  const authContext = res.locals.auth as { userId?: string } | undefined;
  if (!authContext?.userId) {
    throw new AuthenticationError('errors.notAuthenticated');
  }
  return authContext.userId;
};

export const getProfile: RequestHandler = asyncHandler(async (_req, res) => {
  const userId = requireUserId(res);
  const user = await getProfileService(userId);

  res.status(200).json({ status: 'success', data: { user } });
});

export const updateProfile: RequestHandler = asyncHandler(async (req, res) => {
  const userId = requireUserId(res);
  const { firstName, lastName } = req.body as UpdateProfileBody;
  const user = await updateProfileService(userId, { firstName, lastName });

  res.status(200).json({ status: 'success', data: { user } });
});

export const deleteAccount: RequestHandler = asyncHandler(async (req, res) => {
  const userId = requireUserId(res);
  const { password } = req.body as DeleteAccountBody;

  await deleteAccountService(userId, password);

  res
    .clearCookie('accessToken')
    .clearCookie('refreshToken')
    .clearCookie('csrfToken')
    .status(200)
    .json({ status: 'success' });
});
