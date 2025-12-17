# MERN Auth v4 — AI Agent Instructions

## Architecture & Flow
- Backend focus: Express 5 + TypeScript. Flow is routes (declarative) → validators (Zod) → controllers (wrapped in asyncHandler) → services; centralized errors. JWT (15m access, 7d refresh) + Redis sessions.
- Security stack: helmet (strict CSP/HSTS via config/security.ts), HTTPS enforcement in prod (trust proxy), rate limiting (Redis), CSRF double-submit with rotation/failure threshold, HTTP-only access/refresh cookies.
- Request pipeline in backend/src/index.ts: helmet → cors → HTTPS guard → parsers → cookies → sanitize.middleware → passport → activity.middleware → requestLogger → morgan → generalLimiter → routes → notFoundHandler → errorHandler.

## Conventions & Non-Negotiables
- Strict TS; path aliases from backend/tsconfig: @config/*, @controllers/*, @services/*, @models/*, @routes/*, @middleware/*, @utils/*, @custom-types/*, @validators/*.
- Only read env via config/env.ts (call validateEnv). Never use process.env elsewhere.
- Errors: throw AppError subclasses in utils/errors.ts; centralized handler formats responses. Services stay framework-agnostic.
- Routes stay declarative—no controller wrapping; compose middlewares in order (rate limit → CSRF → validate → auth/authorize → controller).

## Key Files & Responsibilities
- bootstrap: backend/src/index.ts (trust proxy, helmet config, sanitize, request logging, rate limiting, route mount, /health, error wiring, role seeding).
- config: env.ts, database.ts, redis.ts, logger.ts (Winston logs/), oauth.ts (conditional Google strategy), security.ts (helmet/CSP/HSTS), security headers set hidePoweredBy.
- models/types: role.model.ts (seeded hierarchy user < admin < super-admin), user.model.ts (bcrypt hooks, passwordChangedAt, ipHistory cap 10, googleId), types/user.types.ts, types/express.d.ts (locals.csrfToken/auth shape).
- services: token.service.ts (typed JWT), session.service.ts (Redis session:{userId}:{sessionId}), auth.service.ts (register/login/refresh/logout/forgot/reset/change/verifyEmail/ipHistory, 2FA start/verify/disable, Google OAuth upsert), email.service.ts (Resend templates verify/reset/changed/welcome).
- middleware: rateLimiter.middleware.ts, csrf.middleware.ts (issue/verify/rotate + block threshold), activity.middleware.ts (best-effort lastActivity/IP), auth.middleware.ts (access/optional/refresh load role/banned/passwordChangedAt), authorize.middleware.ts (role/permission hierarchy), validate.middleware.ts (schema map body/query/params/headers/cookies → ValidationError), sanitize.middleware.ts (basic XSS strip), requestLogger.middleware.ts (Winston structured log), errorHandler.ts.
- routes: routes/index.ts mounts auth.routes.ts; auth.routes wires limiters + CSRF + validate + auth/authorize; Google routes only when isGoogleOAuthEnabled.
- validators/controllers: validators in validators/auth.validators.ts; controllers in controllers/auth.controller.ts set/clear cookies and CSRF tokens.

## Workflows & Commands
- Backend scripts: npm run dev (tsx watch), npm run build (tsc -p tsconfig.build.json), npm start (dist), npm run lint, npm run format, npm run format:check, npm run test (Vitest).
- Tests: Vitest + supertest; integration in backend/tests/integration, middleware unit tests in backend/tests/middleware (CSRF). Google OAuth tests auto-skip if env missing.
- Husky: lint-staged enforces `npm run lint -- --max-warnings=0` and `npm run format:check` on staged TS.
- Logs/health: /health reports Mongo/Redis status; Winston logs to logs/ (requestLogger uses locals.auth metadata).

## Patterns & Gotchas
- CSRF contract: on block, errors include code CSRF_BLOCKED + Retry-After header + details.retryAfterSeconds; see docs/frontend-csrf.md.
- Cookies/tokens: use env cookieSecure/sameSite/cookieMaxAge; CSRF cookie is non-HTTP-only and rotates on verify; refresh routes validate Redis session + stored refresh token.
- Role/permissions: authorize middleware uses hierarchy; place after auth middleware when role/permissions needed.
- Sanitization occurs before logging; validation uses safeParse and returns typed data into req.*; keep schemas strict to avoid unexpected passes.
