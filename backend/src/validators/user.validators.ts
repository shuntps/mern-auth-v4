import { z } from 'zod';

export const updateProfileSchema = z
  .object({
    firstName: z
      .string()
      .trim()
      .min(1, 'validation.required.firstName')
      .max(50, 'validation.max.firstName')
      .optional(),
    lastName: z
      .string()
      .trim()
      .min(1, 'validation.required.lastName')
      .max(50, 'validation.max.lastName')
      .optional(),
  })
  .refine((data) => Boolean(data.firstName ?? data.lastName), {
    message: 'validation.atLeastOneField',
    path: ['firstName'],
  });

export const deleteAccountSchema = z.object({
  password: z.string().min(1, 'validation.required.password'),
});
