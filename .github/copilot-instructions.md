# MERN Auth v4 — AI Agent Instructions

## Context & Architecture

- Express 5 + TypeScript backend (current focus) with planned React 19 + Vite frontend; roadmap-driven (ROADMAP.md). Backend layering: routes (pure/declarative) → validators (Zod) → controllers (asyncHandler-wrapped) → services. JWT auth (15m access, 7d refresh) with Redis sessions; centralized errors.
- Security defaults: HTTPS enforcement in production (trust proxy), Redis-backed rate limiting, CSRF double-submit with rotation + failure threshold, HTTP-only access/refresh cookies.

## Non-Negotiables

- Strict TS (no any); use path aliases from backend/tsconfig (`@config/*`, `@controllers/*`, `@services/*`, `@models/*`, `@routes/*`, `@middleware/*`, `@utils/*`, `@custom-types/*`, `@validators/*`).
- Read config only via env object in backend/src/config/env.ts (validateEnv before start); never read process.env elsewhere.
- Errors: throw AppError variants from backend/src/utils/errors.ts. Controllers exported already wrapped in asyncHandler (backend/src/utils/asyncHandler.ts). Services stay framework-agnostic.
- Routes stay declarative: middleware chain (rate limiter → CSRF → validate → auth when needed) then controller; never wrap controllers in route files.

## Key Backend Pieces

- Bootstrap: backend/src/index.ts sets trust proxy, helmet/cors/compression/body parsers, cookieParser, passport init, touchLastActivity, generalLimiter, mounts routes at env.apiBasePath, /health status, notFoundHandler → errorHandler; seeds roles at startup.
- Config & infra: env.ts (all config), database.ts (Mongo connect/shutdown), redis.ts (ioredis w/ retry), logger.ts (Winston → logs/), oauth.ts (Google strategy gated by env vars, exports isGoogleOAuthEnabled).
- Models & types: backend/src/models/user.model.ts (default role pre-validate, bcrypt pre-save, comparePassword/changedPasswordAfter, ipHistory max 10, lastActivity/lastLogin, googleId field). Role seeding in backend/src/models/role.model.ts. Types in backend/src/types/user.types.ts and express.d.ts (locals.csrfToken/auth).
- Services: token.service.ts (typed JWT), session.service.ts (Redis key session:{userId}:{sessionId}, scan/mget), auth.service.ts (register/login/refresh/logout/forgot/reset/change/verifyEmail/getIpHistory + Google OAuth upsert; password change/reset revoke all sessions; welcome email on verify), email.service.ts (Resend templates verify/reset/changed/welcome).
- Middleware: rateLimiter.middleware.ts (Redis store), csrf.middleware.ts (issue/verify/rotate with failure threshold), activity.middleware.ts (best-effort lastActivity + ipHistory throttle), auth.middleware.ts (refresh-token auth), validate.middleware.ts (Zod → ValidationError), errorHandler.ts.
- Routes/controllers/validators: backend/src/routes/auth.routes.ts wires CSRF + rate limiters + Zod + authenticateRefreshToken where needed; Google routes only mounted when isGoogleOAuthEnabled. Controllers in backend/src/controllers/auth.controller.ts set/clear HTTP-only cookies and CSRF; validators in backend/src/validators/auth.validators.ts.

## Workflows & Tooling

- Commands: npm run dev (tsx watch), npm run build (tsc -p tsconfig.build.json), npm start (dist), npm run lint, npm run format, npm run format:check, npm run test (vitest). Husky pre-commit runs lint-staged (lint --max-warnings=0, format:check on staged TS).
- Tests: Vitest + supertest; integration in backend/tests/integration; CSRF unit tests in backend/tests/middleware. Tests expect env set; Google strategy is skipped if GOOGLE_CLIENT_ID/SECRET missing.
- Logs/health: /health returns Mongo/Redis status; Winston logs to logs/.

## Patterns & Gotchas

- Endpoint flow: types → Zod schema → service (throw AppError) → controller (asyncHandler) → route (rate limit + CSRF + validate + auth). Controllers remain thin/stateless.
- Cookies: use env cookieSecure/sameSite/cookieMaxAge; access/refresh tokens are HTTP-only; CSRF token cookie is non-HTTP-only and rotated in csrf.middleware.
- Sessions: Redis TTL from env.redisSessionTtl; refresh verifies stored token, revokes on mismatch. Password reset/change revoke all sessions.
- Activity/IP: touchLastActivity best-effort; ipHistory capped at 10 (merge helper in auth.service).
- OAuth: Google strategy optional—guarded by env; routes absent when disabled to keep tests green.
- Upcoming roadmap: 2FA, auth middleware for access tokens, RBAC, caching, i18n.
