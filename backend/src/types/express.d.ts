import 'express';
import { type UserRole } from '@custom-types/user.types';

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
    }
  }
}

export {};
