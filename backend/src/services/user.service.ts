import User from '@models/user.model';
import { type IUser, type IUserResponse } from '@custom-types/user.types';
import { AuthenticationError, NotFoundError } from '@utils/errors';
import { revokeAllUserSessions } from './session.service';

const toUserResponse = (user: IUser): IUserResponse => ({
  id: user._id.toString(),
  email: user.email,
  firstName: user.firstName,
  lastName: user.lastName,
  role: user.role.toString(),
  isEmailVerified: user.isEmailVerified,
  isBanned: user.isBanned,
  avatar: user.avatar ?? undefined,
  twoFactorEnabled: user.twoFactorEnabled,
  lastLogin: user.lastLogin,
  createdAt: user.createdAt,
  updatedAt: user.updatedAt,
});

export const getProfile = async (userId: string): Promise<IUserResponse> => {
  const user = await User.findById(userId);
  if (!user) {
    throw new NotFoundError('errors.userNotFound');
  }

  return toUserResponse(user);
};

export const updateProfile = async (
  userId: string,
  updates: { firstName?: string; lastName?: string }
): Promise<IUserResponse> => {
  const user = await User.findById(userId);
  if (!user) {
    throw new NotFoundError('errors.userNotFound');
  }

  if (typeof updates.firstName === 'string') {
    user.firstName = updates.firstName;
  }

  if (typeof updates.lastName === 'string') {
    user.lastName = updates.lastName;
  }

  await user.save({ validateModifiedOnly: true });

  return toUserResponse(user);
};

export const deleteAccount = async (userId: string, password: string): Promise<void> => {
  const user = await User.findById(userId).select('+password');
  if (!user) {
    throw new NotFoundError('errors.userNotFound');
  }

  if (!user.password) {
    throw new AuthenticationError('errors.passwordRequired');
  }

  const isMatch = await user.comparePassword(password);
  if (!isMatch) {
    throw new AuthenticationError('errors.invalidCredentials');
  }

  await revokeAllUserSessions(userId);
  await User.deleteOne({ _id: userId });
};
