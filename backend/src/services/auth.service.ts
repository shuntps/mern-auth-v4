import bcrypt from 'bcrypt';
import crypto from 'crypto';
import QRCode from 'qrcode';
import speakeasy from 'speakeasy';
import redisClient from '@config/redis';
import { env } from '@config/env';
import User from '@models/user.model';
import { type IUser } from '@custom-types/user.types';
import { AppError, AuthenticationError, ConflictError } from '@utils/errors';
import {
  generateAccessToken,
  generateRefreshToken,
  verifyRefreshToken,
  type AccessTokenPayload,
  type RefreshTokenPayload,
} from './token.service';
import {
  createSession,
  getSession,
  refreshSession,
  revokeSession,
  revokeAllUserSessions,
  type SessionMetadata,
} from './session.service';
import {
  sendVerificationEmail,
  sendPasswordResetEmail,
  sendPasswordChangedEmail,
  sendWelcomeEmail,
} from './email.service';
import { ValidationError } from '@utils/errors';
import { type Profile as GoogleProfile } from 'passport-google-oauth20';

export interface AuthUser {
  id: string;
  email: string;
  firstName: string;
  lastName: string;
  role: string;
  isEmailVerified: boolean;
  twoFactorEnabled: boolean;
}

export interface AuthTokens {
  accessToken: string;
  refreshToken: string;
}

interface PasswordResetRecord {
  userId: string;
  createdAt: string;
}

const LOGIN_ATTEMPT_PREFIX = 'login-attempts:';

const PASSWORD_RESET_PREFIX = 'password-reset:';

const EMAIL_VERIFICATION_PREFIX = 'email-verify:';

const TWO_FACTOR_SETUP_PREFIX = 'twofactor-setup:';

const TWO_FACTOR_WINDOW = 1;

const buildPasswordResetKey = (tokenHash: string): string => `${PASSWORD_RESET_PREFIX}${tokenHash}`;

const buildEmailVerificationKey = (tokenHash: string): string =>
  `${EMAIL_VERIFICATION_PREFIX}${tokenHash}`;

const hashResetToken = (token: string): string =>
  crypto.createHash('sha256').update(token).digest('hex');

const buildLoginAttemptKey = (email: string): string => `${LOGIN_ATTEMPT_PREFIX}${email}`;

const buildTwoFactorSetupKey = (userId: string): string => `${TWO_FACTOR_SETUP_PREFIX}${userId}`;

interface TwoFactorSetupRecord {
  secret: string;
}

const mergeIpHistory = (existing: string[] | undefined, ip?: string): string[] => {
  const current = existing ?? [];
  if (!ip) return current;
  return [ip, ...current.filter((value) => value !== ip)].slice(0, 10);
};

const verifyTwoFactorToken = (secret: string, token: string): boolean =>
  speakeasy.totp.verify({ secret, token, encoding: 'base32', window: TWO_FACTOR_WINDOW });

const incrementFailedLoginAttempt = async (email: string): Promise<number> => {
  const key = buildLoginAttemptKey(email);
  const attempts = await redisClient.incr(key);
  await redisClient.expire(key, env.loginAttemptTtl);
  return attempts;
};

const clearFailedLoginAttempts = async (email: string): Promise<void> => {
  const key = buildLoginAttemptKey(email);
  await redisClient.del(key);
};

const createSessionAndTokens = async (
  user: IUser,
  metadata: SessionMetadata
): Promise<AuthTokens> => {
  const accessToken = generateAccessToken(user._id.toString(), user.role.toString());

  const session = await createSession(user._id.toString(), '', metadata);
  const refreshToken = generateRefreshToken(user._id.toString(), session.sessionId);
  await refreshSession(user._id.toString(), session.sessionId, refreshToken);

  return {
    accessToken,
    refreshToken,
  };
};

const createVerificationToken = async (userId: string): Promise<string> => {
  const token = crypto.randomBytes(env.csrfTokenLength).toString('hex');
  const tokenHash = hashResetToken(token);
  const record: PasswordResetRecord = {
    userId,
    createdAt: new Date().toISOString(),
  };

  await redisClient.set(
    buildEmailVerificationKey(tokenHash),
    JSON.stringify(record),
    'EX',
    env.emailVerificationTtl
  );

  return token;
};

const toAuthUser = (user: IUser): AuthUser => ({
  id: user._id.toString(),
  email: user.email,
  firstName: user.firstName,
  lastName: user.lastName,
  role: user.role.toString(),
  isEmailVerified: user.isEmailVerified,
  twoFactorEnabled: user.twoFactorEnabled,
});

export const registerUser = async (params: {
  email: string;
  password: string;
  firstName: string;
  lastName: string;
}): Promise<AuthUser> => {
  const normalizedEmail = params.email.toLowerCase();
  const existing = await User.findOne({ email: normalizedEmail });
  if (existing) {
    throw new ConflictError('User already exists');
  }

  const user = await User.create({
    email: normalizedEmail,
    password: params.password,
    firstName: params.firstName,
    lastName: params.lastName,
  });

  const verificationToken = await createVerificationToken(user._id.toString());
  await sendVerificationEmail(user.email, verificationToken);

  return toAuthUser(user);
};

export const registerAndAuthenticate = async (
  params: {
    email: string;
    password: string;
    firstName: string;
    lastName: string;
  },
  metadata: SessionMetadata
): Promise<AuthTokens & { user: AuthUser }> => {
  const normalizedEmail = params.email.toLowerCase();
  const existing = await User.findOne({ email: normalizedEmail });
  if (existing) {
    throw new ConflictError('User already exists');
  }

  const user = new User({
    email: normalizedEmail,
    password: params.password,
    firstName: params.firstName,
    lastName: params.lastName,
  });

  user.lastLogin = new Date();
  user.lastActivity = new Date();
  if (metadata.ip) {
    user.ipHistory = [metadata.ip];
  }

  await user.save();

  const verificationToken = await createVerificationToken(user._id.toString());
  await sendVerificationEmail(user.email, verificationToken);

  const tokens = await createSessionAndTokens(user, metadata);

  return {
    ...tokens,
    user: toAuthUser(user),
  };
};

export const loginUser = async (
  email: string,
  password: string,
  metadata: SessionMetadata,
  twoFactorCode?: string
): Promise<AuthTokens & { user: AuthUser }> => {
  const normalizedEmail = email.toLowerCase();
  const user = await User.findOne({ email: normalizedEmail }).select('+password +twoFactorSecret');
  if (!user || !user.password) {
    await incrementFailedLoginAttempt(normalizedEmail);
    throw new AuthenticationError('Invalid credentials');
  }

  if (user.isBanned) {
    await incrementFailedLoginAttempt(normalizedEmail);
    throw new AuthenticationError('Account is banned');
  }

  if (!user.isEmailVerified) {
    await incrementFailedLoginAttempt(normalizedEmail);
    throw new AuthenticationError('Email not verified');
  }

  const isMatch = await user.comparePassword(password);
  if (!isMatch) {
    await incrementFailedLoginAttempt(normalizedEmail);
    throw new AuthenticationError('Invalid credentials');
  }

  if (user.twoFactorEnabled) {
    if (!user.twoFactorSecret) {
      await incrementFailedLoginAttempt(normalizedEmail);
      throw new AuthenticationError('Two-factor authentication is not configured');
    }

    if (!twoFactorCode) {
      await incrementFailedLoginAttempt(normalizedEmail);
      throw new AuthenticationError('Two-factor code required');
    }

    const isTwoFactorValid = verifyTwoFactorToken(user.twoFactorSecret, twoFactorCode);
    if (!isTwoFactorValid) {
      await incrementFailedLoginAttempt(normalizedEmail);
      throw new AuthenticationError('Invalid two-factor code');
    }
  }

  await clearFailedLoginAttempts(normalizedEmail);

  user.lastLogin = new Date();
  user.lastActivity = new Date();
  user.ipHistory = mergeIpHistory(user.ipHistory, metadata.ip);
  await user.save({ validateModifiedOnly: true });

  const { accessToken, refreshToken } = await createSessionAndTokens(user, metadata);

  return {
    accessToken,
    refreshToken,
    user: toAuthUser(user),
  };
};

export const startTwoFactorSetup = async (
  userId: string
): Promise<{
  otpauthUrl: string;
  qrCodeDataUrl: string;
  secret: string;
}> => {
  const user = await User.findById(userId);
  if (!user) {
    throw new AuthenticationError('User not found');
  }

  if (user.twoFactorEnabled) {
    throw new ConflictError('Two-factor authentication is already enabled');
  }

  const secret = speakeasy.generateSecret({
    name: `${env.twoFactorAppName} (${user.email})`,
    issuer: env.twoFactorIssuer,
  });

  if (!secret.base32 || !secret.otpauth_url) {
    throw new AppError('Failed to generate two-factor secret', 500);
  }

  const pendingSecret: TwoFactorSetupRecord = { secret: secret.base32 };
  await redisClient.set(
    buildTwoFactorSetupKey(user._id.toString()),
    JSON.stringify(pendingSecret),
    'EX',
    env.twoFactorTempSecretTtl
  );

  const qrCodeDataUrl = await QRCode.toDataURL(secret.otpauth_url);

  return {
    otpauthUrl: secret.otpauth_url,
    qrCodeDataUrl,
    secret: secret.base32,
  };
};

export const verifyTwoFactorSetup = async (userId: string, token: string): Promise<AuthUser> => {
  const setupKey = buildTwoFactorSetupKey(userId);
  const rawSecret = await redisClient.get(setupKey);

  if (!rawSecret) {
    throw new AuthenticationError('Two-factor setup not found or expired');
  }

  const parsed = JSON.parse(rawSecret) as TwoFactorSetupRecord;
  const isValid = verifyTwoFactorToken(parsed.secret, token);
  if (!isValid) {
    throw new AuthenticationError('Invalid two-factor code');
  }

  const user = await User.findById(userId).select('+twoFactorSecret');
  if (!user) {
    await redisClient.del(setupKey);
    throw new AuthenticationError('User not found');
  }

  user.twoFactorEnabled = true;
  user.twoFactorSecret = parsed.secret;
  await user.save({ validateModifiedOnly: true });

  await redisClient.del(setupKey);

  return toAuthUser(user);
};

export const disableTwoFactor = async (userId: string, token: string): Promise<AuthUser> => {
  const user = await User.findById(userId).select('+twoFactorSecret');
  if (!user) {
    throw new AuthenticationError('User not found');
  }

  if (!user.twoFactorEnabled || !user.twoFactorSecret) {
    throw new ConflictError('Two-factor authentication is not enabled');
  }

  const isValid = verifyTwoFactorToken(user.twoFactorSecret, token);
  if (!isValid) {
    throw new AuthenticationError('Invalid two-factor code');
  }

  user.twoFactorEnabled = false;
  user.twoFactorSecret = undefined;
  await user.save({ validateModifiedOnly: true });

  await redisClient.del(buildTwoFactorSetupKey(userId));

  return toAuthUser(user);
};

export const refreshTokens = async (
  refreshToken: string
): Promise<AuthTokens & { payload: RefreshTokenPayload; user: AuthUser }> => {
  const payload = verifyRefreshToken(refreshToken);
  if (!payload.sessionId) {
    throw new AuthenticationError('Invalid refresh token');
  }

  const session = await getSession(payload.sub, payload.sessionId);
  if (!session) {
    throw new AuthenticationError('Session expired');
  }

  if (session.refreshToken !== refreshToken) {
    await revokeSession(payload.sub, payload.sessionId, 'refresh-token-mismatch');
    throw new AuthenticationError('Session token mismatch');
  }

  const user = await User.findById(payload.sub);
  if (!user) {
    throw new AuthenticationError('User not found');
  }

  const accessToken = generateAccessToken(user._id.toString(), user.role.toString());
  const newRefreshToken = generateRefreshToken(user._id.toString(), payload.sessionId);
  await refreshSession(payload.sub, payload.sessionId, newRefreshToken);

  return {
    accessToken,
    refreshToken: newRefreshToken,
    payload,
    user: toAuthUser(user),
  };
};

export const logoutSession = async (refreshToken?: string): Promise<void> => {
  if (!refreshToken) return;
  const payload = verifyRefreshToken(refreshToken);
  if (payload.sessionId) {
    await revokeSession(payload.sub, payload.sessionId, 'logout');
  }
};

export const requestPasswordReset = async (email: string): Promise<void> => {
  const normalizedEmail = email.toLowerCase();
  const user = await User.findOne({ email: normalizedEmail });
  if (!user) {
    return; // Do not reveal whether the email exists
  }

  const token = crypto.randomBytes(env.csrfTokenLength).toString('hex');
  const tokenHash = hashResetToken(token);
  const record: PasswordResetRecord = {
    userId: user._id.toString(),
    createdAt: new Date().toISOString(),
  };

  const key = buildPasswordResetKey(tokenHash);
  await redisClient.set(key, JSON.stringify(record), 'EX', env.passwordResetTtl);

  await sendPasswordResetEmail(user.email, token);
};

export const resetPasswordWithToken = async (token: string, newPassword: string): Promise<void> => {
  const tokenHash = hashResetToken(token);
  const key = buildPasswordResetKey(tokenHash);
  const raw = await redisClient.get(key);
  if (!raw) {
    throw new AuthenticationError('Invalid or expired reset token');
  }

  const record = JSON.parse(raw) as PasswordResetRecord;
  const user = await User.findById(record.userId).select('+password');
  if (!user) {
    throw new AuthenticationError('User not found');
  }

  user.password = newPassword;
  await user.save();

  await revokeAllUserSessions(record.userId, 'password-reset');
  await redisClient.del(key);
  await sendPasswordChangedEmail(user.email);
};

export const changePassword = async (
  refreshToken: string | undefined,
  oldPassword: string,
  newPassword: string
): Promise<void> => {
  if (!refreshToken) {
    throw new AuthenticationError('Not authenticated');
  }

  const payload: AccessTokenPayload | RefreshTokenPayload = verifyRefreshToken(refreshToken);
  if (!('sessionId' in payload) || !payload.sessionId) {
    throw new AuthenticationError('Invalid session');
  }

  const user = await User.findById(payload.sub).select('+password');
  if (!user || !user.password) {
    throw new AuthenticationError('Invalid credentials');
  }

  const isMatch = await bcrypt.compare(oldPassword, user.password);
  if (!isMatch) {
    throw new AuthenticationError('Invalid credentials');
  }

  if (oldPassword === newPassword) {
    throw new ValidationError('New password must be different from current password');
  }

  user.password = newPassword;
  await user.save();

  await revokeAllUserSessions(payload.sub, 'password-change');
  await sendPasswordChangedEmail(user.email);
};

export const verifyEmailWithToken = async (token: string): Promise<AuthUser> => {
  const tokenHash = hashResetToken(token);
  const key = buildEmailVerificationKey(tokenHash);
  const raw = await redisClient.get(key);

  if (!raw) {
    throw new AuthenticationError('Invalid or expired verification token');
  }

  const record = JSON.parse(raw) as PasswordResetRecord;
  const user = await User.findById(record.userId);
  if (!user) {
    await redisClient.del(key);
    throw new AuthenticationError('User not found');
  }

  if (!user.isEmailVerified) {
    user.isEmailVerified = true;
    await user.save();
    await sendWelcomeEmail(user.email);
  }

  await redisClient.del(key);

  return toAuthUser(user);
};

export const getUserIpHistory = async (userId: string): Promise<string[]> => {
  const user = await User.findById(userId).select('ipHistory');
  if (!user) {
    throw new AuthenticationError('User not found');
  }
  return user.ipHistory;
};

export const authenticateWithGoogle = async (
  profile: GoogleProfile,
  metadata: SessionMetadata
): Promise<AuthTokens & { user: AuthUser }> => {
  const email = profile.emails?.[0]?.value.toLowerCase();
  const googleId = profile.id;

  if (!email) {
    throw new AuthenticationError('Google account does not provide an email');
  }

  let user = await User.findOne({ googleId });

  if (!user) {
    user = await User.findOne({ email });
    if (user) {
      user.googleId ??= googleId;
    }
  }

  user ??= new User({
    email,
    googleId,
    firstName: profile.name?.givenName ?? 'Google',
    lastName: profile.name?.familyName ?? 'User',
    isEmailVerified: true,
  });

  if (user.isBanned) {
    throw new AuthenticationError('Account is banned');
  }

  user.isEmailVerified = true;
  user.lastLogin = new Date();
  user.lastActivity = new Date();
  user.ipHistory = mergeIpHistory(user.ipHistory, metadata.ip);

  await user.save({ validateModifiedOnly: true });

  const tokens = await createSessionAndTokens(user, metadata);

  return {
    ...tokens,
    user: toAuthUser(user),
  };
};
