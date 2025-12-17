import { z } from 'zod';

const passwordSchema = z
  .string()
  .min(8, 'validation.password.min')
  .regex(/[A-Z]/, 'validation.password.uppercase')
  .regex(/[a-z]/, 'validation.password.lowercase')
  .regex(/[0-9]/, 'validation.password.number')
  .regex(/[^A-Za-z0-9]/, 'validation.password.special');

const emailSchema = z.email({ message: 'validation.email' });

export const registerSchema = z.object({
  email: emailSchema,
  password: passwordSchema,
  firstName: z.string().min(1, 'validation.required.firstName').max(50, 'validation.max.firstName'),
  lastName: z.string().min(1, 'validation.required.lastName').max(50, 'validation.max.lastName'),
});

const twoFactorCodeSchema = z
  .string()
  .trim()
  .regex(/^\d{6}$/u, 'validation.format.twoFactorCode');

export const loginSchema = z.object({
  email: emailSchema,
  password: z.string().min(1, 'validation.required.password'),
  twoFactorCode: twoFactorCodeSchema.optional(),
});

export const forgotPasswordSchema = z.object({
  email: emailSchema,
});

export const resetPasswordSchema = z.object({
  token: z.string().min(1, 'validation.required.token'),
  newPassword: passwordSchema,
});

export const changePasswordSchema = z.object({
  oldPassword: z.string().min(1, 'validation.required.oldPassword'),
  newPassword: passwordSchema,
});

export const verifyEmailSchema = z.object({
  token: z.string().min(1, 'validation.required.token'),
});

export const twoFactorVerifySchema = z.object({
  token: twoFactorCodeSchema,
});

export const twoFactorDisableSchema = z.object({
  token: twoFactorCodeSchema,
});
