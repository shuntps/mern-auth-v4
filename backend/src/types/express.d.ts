import 'express';

declare global {
  namespace Express {
    interface Locals {
      csrfToken?: string;
      auth?: {
        userId: string;
        role?: string;
        sessionId?: string;
        accessToken?: string;
        refreshToken?: string;
      };
    }
  }
}

export {};
