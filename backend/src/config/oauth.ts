import { type Request } from 'express';
import passport from 'passport';
import { Strategy as GoogleStrategy, type Profile } from 'passport-google-oauth20';
import { env } from '@config/env';
import { authenticateWithGoogle } from '@services/auth.service';
import { type SessionMetadata } from '@services/session.service';
import logger from '@config/logger';

const isGoogleOAuthEnabled = Boolean(env.googleClientId && env.googleClientSecret);

if (!isGoogleOAuthEnabled) {
  logger.warn('Google OAuth not configured; skipping strategy registration');
}

const buildSessionMetadata = (req: Request): SessionMetadata => ({
  ip: req.ip,
  userAgent: req.get('user-agent') ?? undefined,
  browser: req.get('sec-ch-ua') ?? undefined,
  os: req.get('sec-ch-ua-platform') ?? undefined,
  device: req.get('sec-ch-ua-mobile') ?? undefined,
});

if (isGoogleOAuthEnabled) {
  passport.use(
    new GoogleStrategy(
      {
        clientID: env.googleClientId,
        clientSecret: env.googleClientSecret,
        callbackURL: env.googleCallbackUrl,
        passReqToCallback: true,
      },
      (req: Request, _accessToken: string, _refreshToken: string, profile: Profile, done): void => {
        void (async (): Promise<void> => {
          try {
            const authResult = await authenticateWithGoogle(profile, buildSessionMetadata(req));
            done(null, authResult);
          } catch (error) {
            done(error as Error, undefined);
          }
        })();
      }
    )
  );
}

export { isGoogleOAuthEnabled };
export default passport;
