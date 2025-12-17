import 'express';

declare global {
  namespace Express {
    interface Locals {
      csrfToken?: string;
      auth?: {
        userId: string;
        sessionId: string;
        refreshToken: string;
      };
    }
  }
}

export {};
