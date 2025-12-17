# MERN Auth v4 — AI Agent Instructions

## Context & Architecture

- Express 5 + TypeScript backend with React 19 + Vite frontend; roadmap-driven (see ROADMAP.md). Backend is current focus.
- Layering: routes (declarative) → validators (Zod) → controllers (wrapped with asyncHandler) → services. Dual JWT (15m access, 7d refresh) + Redis sessions; centralized errors.
- HTTPS enforced in production with proxy trust; CSRF double-submit on auth routes; rate limiting via Redis.

## Non-Negotiables

- Strict TS (no any); use path aliases from backend/tsconfig (`@config/*`, `@controllers/*`, `@services/*`, `@models/*`, `@routes/*`, `@middleware/*`, `@utils/*`, `@custom-types/*`, `@validators/*`).
- Read config only from backend/src/config/env.ts (validateEnv before start); never use process.env elsewhere.
- Throw AppError variants (backend/src/utils/errors.ts); controllers exported via asyncHandler (backend/src/utils/asyncHandler.ts). Services stay framework-agnostic.
- Routes stay declarative: middleware (rate limiters, CSRF, validate) then controller; do not wrap controllers in route files.

## Core Backend Pieces

- Bootstrap: backend/src/index.ts sets trust proxy, helmet/cors/compression/body parsers, cookieParser, touchLastActivity middleware, general rate limiter, mounts routes under env.apiBasePath, adds /health, notFoundHandler → errorHandler. Seeds roles at startup.
- Env + connections: backend/src/config/env.ts, database.ts (Mongo connect/shutdown), redis.ts (ioredis client with retry), logger.ts (Winston to logs/).
- Models: backend/src/models/user.model.ts (default role assignment, bcrypt hashing on save, comparePassword/changedPasswordAfter, ipHistory max 10, lastActivity/lastLogin), backend/src/models/role.model.ts (seed roles). Types in backend/src/types/user.types.ts.
- Auth services: backend/src/services/token.service.ts (typed JWT), session.service.ts (Redis sessions session:{userId}:{sessionId}, scan+mget for listing), auth.service.ts (register/login/refresh/logout/forgot/reset/change). Reset tokens are hashed (sha256) before storing in Redis; password change revokes all sessions; reset also revokes all sessions.
- Middleware: rateLimiter.middleware.ts (Redis store via redisClient.call with prefixes), csrf.middleware.ts (issue/verify token), activity.middleware.ts (best-effort lastActivity/ipHistory update once/min using access token), errorHandler.ts.
- Routes/controllers/validators: auth.routes.ts wires CSRF + rate limiters + Zod validators from auth.validators.ts; controllers in auth.controller.ts set/clear HTTP-only cookies (secure/sameSite from env) and stay thin.

## Workflows & Tooling

- Backend scripts: npm run dev (tsx watch), npm run build (tsc), npm start (run dist), npm run lint, npm run format, npm run format:check. Husky + lint-staged enforce lint --max-warnings=0 and format:check on staged TS.
- Logs written to logs/ (combined/error/exception) via logger.ts. Health check at /health returns Mongo/Redis status; keep it cheap and unauthenticated.

## Patterns & Gotchas

- New endpoint: add types → Zod schema → service (throws AppError) → controller with asyncHandler → route with validator + rate limiter + CSRF as needed.
- Use env.apiBasePath when mounting routes; keep cookies HTTP-only/secure/sameSite from env. Do not read process.env directly.
- Redis session TTL from env.redisSessionTtl; revoke or rotate refresh tokens via session.service helpers. Refresh compares stored token; mismatches revoke session.
- IP history keeps latest 10 and updates in login and activity middleware (throttled). Password hashing runs only when password is set/modified; password field is select:false.
- Avoid creating duplicate Mongo indexes—unique constraints already on schema fields; secondary indexes are defined explicitly in models.

## Roadmap Snapshot

- Completed: errors/async/rate limiting, role/user models + seeding, Husky/lint-staged, CSRF + HTTPS enforcement, hashed password-reset tokens, last-activity middleware.
- In progress/next: Phase 2.9 auth core/i18n expansion (en/fr locales, translated errors/responses) and email delivery integration for reset/verify.
