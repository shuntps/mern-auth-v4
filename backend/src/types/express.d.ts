import 'express';
import { type UserRole } from '@custom-types/user.types';
import { type TranslateFn } from '@config/i18n';

declare global {
  namespace Express {
    interface Locals {
      csrfToken?: string;
      auth?: {
        userId: string;
        role?: string;
        roleName?: UserRole;
        permissions?: string[];
        sessionId?: string;
        accessToken?: string;
        refreshToken?: string;
      };
      clientIp?: string;
      requestFingerprint?: string;
      locale?: string;
      t?: TranslateFn;
    }

    interface Request {
      locale?: string;
      t?: TranslateFn;
    }
  }
}

export {};
