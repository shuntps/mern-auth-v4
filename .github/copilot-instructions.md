# MERN Auth v4 - AI Agent Instructions

## Architecture Overview

**Dual-repo MERN stack**: `backend/` (Express + TypeScript + MongoDB + Redis) | `frontend/` (React + Vite + TypeScript + TailwindCSS)

**Core Patterns:**

- Dual-token JWT (access 15m, refresh 7d) + Redis sessions
- Service-controller separation (controllers=HTTP, services=logic)
- TypeScript strict mode, zero `any` types, explicit return types
- Follow ROADMAP.md sequentially, zero lint errors enforced

## Development Rules (NON-NEGOTIABLE)

**TypeScript:** Never use `any`, strict mode enabled, explicit return types required

**Dependencies:** Latest versions only (Dec 2025), npm only (never yarn/pnpm)

- Backend: Express 5.2.1+, Mongoose 9.0.1+, ioredis 5.8.2+
- Frontend: React 19.2.3+, Vite 7.2.7+, TailwindCSS 4.1.18+, Zustand 5.0.9+

**Workflow:** Follow ROADMAP.md → implement → ESLint zero errors → test → mark complete. No code duplication, reuse existing patterns.

## Production-Critical Express Patterns (MANDATORY)

### 1. Centralized Error Handler

**ALL errors** flow through `/src/middleware/errorHandler.ts` (registered last). Custom error classes: AppError (base), ValidationError (400), AuthenticationError (401), AuthorizationError (403), NotFoundError (404), ConflictError (409). Controllers throw errors, never send responses.

### 2. AsyncHandler Wrapper (Controller-Level ONLY)

```typescript
// ✅ CORRECT - wrap at controller export
export const register = asyncHandler(async (req, res, next) => {
  /* throw errors */
});

// ✅ CORRECT - routes stay declarative
router.post(
  "/register",
  authLimiter,
  validate(schema),
  authController.register
);

// ❌ WRONG - never wrap at route level
router.post("/register", asyncHandler(authController.register));
```

### 3. Redis-Based Rate Limiting

**RedisStore sendCommand pattern for ioredis:**

```typescript
new RedisStore({
  sendCommand: (command: string, ...args: string[]): Promise<RedisReply> =>
    redisClient.call(command, ...args) as Promise<RedisReply>,
  prefix: "rl:endpoint:",
});
```

All limits use env variables: `env.rateLimitWindowMs`, `env.authRateLimitMaxRequests`, etc.

## Backend Structure & Patterns

**Folders:** `/config` (DB, Redis, env, logger), `/controllers` (HTTP handlers), `/services` (business logic), `/models` (Mongoose schemas), `/routes`, `/middleware`, `/utils`, `/types`, `/validators` (Zod schemas)

**Auth Flow:** Register → Zod validate → bcrypt hash → save → email | Login → validate → verify → Redis session → JWT pair → HTTP-only cookies | Refresh → verify token → check Redis → new access token | Logout → revoke Redis session

**Redis Keys:** `session:{userId}:{sessionId}` (metadata: IP, user agent, timestamps)

**Validation:** Zod in `/validators/*`, password policy: 8+ chars, 1 upper, 1 lower, 1 number, 1 special

**Security:** Helmet + CSP, Redis rate limiting, CSRF tokens, HTTP-only cookies, IP tracking

## Frontend Structure & Patterns

**Folders:** `/components` (reusable UI), `/pages`, `/layouts`, `/store` (Zustand), `/services` (Axios), `/hooks`, `/types`, `/i18n` (en,fr), `/config`

**State:** authStore (user, tokens, auth methods) | uiStore (theme, locale, sidebar, notifications) - persisted to localStorage

**Components:** Variants (Button: primary/secondary/outline/ghost), React Hook Form + Zod, dark mode via Tailwind `dark:` classes

**Routes:** `<ProtectedRoute>` (auth required), `<RoleBasedRoute roles={['admin']}>` (role-based), Axios interceptor auto-refreshes tokens on 401

## Development Workflows

**Backend:** `npm run dev` (tsx hot reload), `npm run lint`, `npm run format`
**Frontend:** `npm run dev` (Vite), `npm run lint`, `npm run format`
**Docker:** `docker-compose up` (backend + MongoDB + Redis)

**Route Checklist:** Zod schema → service logic → controller (wrap asyncHandler) → apply rate limiter + validation → test errors

## Integration Points

**Backend ↔ Frontend:** CORS via `FRONTEND_URL` env, HTTP-only cookies auto-sent, CSRF token from `GET /api/auth/csrf-token`

**Backend ↔ Databases:** Mongoose connection pooling, ioredis with retry logic (`/config/redis.ts`), Redis for sessions/rate limiting/caching (TTL = refresh token expiry)

**External Services:** Nodemailer (emails), Passport.js + Google OAuth, Speakeasy + QRCode (2FA)

## Common Pitfalls

❌ AsyncHandler at route level | Catching errors in controllers | Skipping rate limiting | Using `any` | Hardcoding secrets | Route-level controller wrapping | Skipping Zod validation | Code duplication | Skipping ROADMAP sequence

## Quick Reference

**Roles:** user, admin, super-admin | **JWT:** 15m access, 7d refresh | **Rate Limits:** 100/15min general, 5/15min auth, 3/hour password reset | **Password:** bcrypt 10 rounds, 8+ chars policy | **Redis:** `session:{userId}:{sessionId}` | **Uploads:** Multer, Sharp, 5MB max | **i18n:** en, fr

## Default Config (.env)

**JWT:** `JWT_ACCESS_EXPIRES_IN=15m`, `JWT_REFRESH_EXPIRES_IN=7d`
**Redis TTL:** Sessions 7d, email verification 24h, password reset 15m, rate limit 15m, cache 1h
**MongoDB:** Pool 10 (dev), 50 (prod), timeout 30s, auto-index dev only
**Rate Limits:** General 100/15m, auth 5/15m, login 5/15m, password reset 3/1h
**Uploads:** 5MB max, jpg/jpeg/png/webp, Sharp resize to 500x500px
**Security:** bcrypt 10 rounds, cookie 7d, CSRF 32 bytes, session ID 32 bytes

## TypeScript Path Aliases

`@config/*`, `@controllers/*`, `@services/*`, `@models/*`, `@routes/*`, `@middleware/*`, `@utils/*`, `@types/*`, `@validators/*` → `src/{folder}/*`

✅ `import { env } from '@config/env'` | ❌ `import { env } from '../config/env'`

## Current Project Status

**Phase 2.7.1 COMPLETE** ✅ - Production-Critical Middleware Foundation:

- Custom error classes: AppError, ValidationError, AuthenticationError, AuthorizationError, NotFoundError, ConflictError
- AsyncHandler wrapper with controller-level documentation
- Redis-based rate limiters: generalLimiter, authLimiter, loginLimiter, passwordResetLimiter
- Centralized error handler with operational/programming error distinction
- All rate limiters use environment variables from `.env`
- Zero ESLint errors enforced

**NEXT: Phase 2.8** - User Model & Schema
Check [ROADMAP.md](../ROADMAP.md) for detailed implementation progress. All tasks must be completed in order, with checkboxes marked only when fully tested and working.
