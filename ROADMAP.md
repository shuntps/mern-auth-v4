# MERN Auth v4 - Complete Project Roadmap

## Project Info

Developer: Shunt
GitHub Repo: https://github.com/shuntps/mern-auth-v4.git

## 📋 Overview

This roadmap outlines all steps for building a production-ready MERN stack authentication system with TypeScript, following 2025 industry standards.

---

## Phase 1: Project Initialization & Setup

### 1.1 Project Structure Setup

- [x] Create root project directory structure
- [x] Initialize Git repository
- [x] Create `.gitignore` file (root level)
- [x] Create initial `README.md` with project overview
- [x] Create `backend` folder
- [x] Create `frontend` folder

### 1.2 Documentation Setup

- [x] Create comprehensive README.md with setup instructions
- [x] Document environment variable requirements
- [x] Create CONTRIBUTING.md guidelines
- [x] Add MIT LICENSE file

---

**🎯 MILESTONE 1: Project Foundation Complete**

- Git repository initialized with proper structure
- Documentation in place (README, LICENSE, CONTRIBUTING)
- Ready to begin backend development

---

## Phase 2: Backend Development

> Status note: Phase 2 is in progress. Do not advance to Phase 3 until the remaining auth flows are finished and tested (email verification, forgot/reset password, change-password, activity tracking fields, and route testing).

### 2.1 Backend Project Initialization

- [x] Navigate to `backend` folder
- [x] Initialize npm project (`npm init -y`)
- [x] Install TypeScript and core dependencies
- [x] Create `tsconfig.json` with strict mode
- [x] Setup folder structure:
  - [x] `/src` - main source code
  - [x] `/src/config` - configuration files
  - [x] `/src/controllers` - request handlers
  - [x] `/src/services` - business logic
  - [x] `/src/models` - MongoDB schemas
  - [x] `/src/routes` - API routes
  - [x] `/src/middleware` - custom middleware
  - [x] `/src/utils` - utility functions
  - [x] `/src/types` - TypeScript type definitions
  - [x] `/src/validators` - Zod schemas
  - [x] `/dist` - compiled output

### 2.2 Backend Core Dependencies Installation

- [x] Install Express.js (latest)
- [x] Install MongoDB driver / Mongoose (latest)
- [x] Install TypeScript type definitions (@types/node, @types/express)
- [x] Install dotenv for environment variables
- [x] Install cors and @types/cors
- [x] Install helmet for security headers
- [x] Install compression for response compression
- [x] Install morgan for HTTP request logging
- [x] Install winston for application logging
- [x] Install express-async-errors (Not needed - using custom asyncHandler wrapper for better control)

### 2.3 Development Tools Setup

- [x] Install tsx for development (modern alternative to nodemon+ts-node)
- [x] Install ESLint with TypeScript support (v9 flat config)
- [x] Create `eslint.config.mjs` configuration
- [x] Install Prettier
- [x] Create `.prettierrc` configuration
- [x] Install Husky for Git hooks
- [x] Configure pre-commit hooks (lint + format)
- [x] Install lint-staged
- [x] Add npm scripts: `dev`, `build`, `start`, `lint`, `format`, `format:check`

### 2.4 Environment Configuration

- [x] Create `.env.example` file
- [x] Create `.env` file (git-ignored)
- [x] Setup config loader in `/src/config/env.ts`
- [x] Define environment variables:
  - [x] NODE_ENV
  - [x] PORT
  - [x] MONGODB_URI
  - [x] REDIS_HOST, REDIS_PORT, REDIS_PASSWORD
  - [x] JWT_ACCESS_SECRET, JWT_REFRESH_SECRET
  - [x] JWT_ACCESS_EXPIRES_IN, JWT_REFRESH_EXPIRES_IN
  - [x] COOKIE_SECRET
  - [x] GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET
  - [x] FRONTEND_URL
  - [x] SMTP configuration for emails

### 2.5 Database Setup - MongoDB

- [x] Install mongoose (latest)
- [x] Create MongoDB connection utility in `/src/config/database.ts`
- [x] Implement connection pooling
- [x] Add connection error handling
- [x] Add graceful shutdown handling
- [x] Test MongoDB connection

### 2.6 Database Setup - Redis

- [x] Install ioredis (latest)
- [x] Create Redis client in `/src/config/redis.ts`
- [x] Implement Redis connection with retry logic
- [x] Add Redis error handling
- [x] Add graceful shutdown handling
- [x] Test Redis connection
- [x] Create Redis utility functions for common operations

### 2.7 Core Server Setup

- [x] Create main `index.ts` entry point
- [x] Initialize Express app
- [x] Apply security middleware (helmet, cors)
- [x] Apply body parsers (json, urlencoded)
- [x] Apply compression middleware
- [x] Apply Morgan logging
- [x] Setup global error handler (basic structure)
- [x] Setup 404 handler
- [x] Connect to MongoDB
- [x] Connect to Redis
- [x] Start HTTP server
- [x] Implement graceful shutdown
- [x] Add health check endpoint

### 2.7.1 Production-Critical Middleware Foundation (MANDATORY PREREQUISITE)

**⚠️ BLOCKING - Must complete BEFORE any route/controller implementation**

#### Centralized Error Handler

- [x] Create custom error classes in `/src/utils/errors.ts`:
  - [x] `AppError` (base class with statusCode, message, isOperational)
  - [x] `ValidationError` extends AppError (400)
  - [x] `AuthenticationError` extends AppError (401)
  - [x] `AuthorizationError` extends AppError (403)
  - [x] `NotFoundError` extends AppError (404)
  - [x] `ConflictError` extends AppError (409)
- [x] Create centralized error handler in `/src/middleware/errorHandler.ts`:
  - [x] Handle operational errors (AppError instances)
  - [x] Handle programming errors (unexpected errors)
  - [x] Log all errors with Winston (include request context)
  - [x] Format consistent JSON error responses
  - [x] Hide stack traces in production
  - [x] Distinguish trusted vs untrusted errors
  - [x] Send appropriate HTTP status codes
- [x] Register error handler as LAST middleware in Express app
- [x] Test error handler with sample errors

#### AsyncHandler Wrapper Utility

- [x] Create `asyncHandler` utility in `/src/utils/asyncHandler.ts`:
  - [x] Wrap async functions to catch promise rejections
  - [x] Forward errors to Express error handler via `next()`
  - [x] Add TypeScript types for Request, Response, NextFunction
  - [x] Include JSDoc documentation
- [x] Create sample controller with asyncHandler wrapper at export
- [x] Create sample route file demonstrating declarative pattern (no asyncHandler wrapping)
- [x] Document **controller-level wrapping pattern** in code comments
- [x] Document that routes MUST remain declarative (never wrap controllers)

#### Redis-Based Rate Limiting

- [x] Install `express-rate-limit` and `rate-limit-redis`
- [x] Create rate limiter configuration in `/src/middleware/rateLimiter.middleware.ts`:
  - [x] Configure Redis store (use existing ioredis client)
  - [x] Create `generalLimiter` (100 req / 15 min)
  - [x] Create `authLimiter` (5 req / 15 min)
  - [x] Create `loginLimiter` (5 attempts / 15 min)
  - [x] Create `passwordResetLimiter` (3 req / 1 hour)
  - [x] Include `Retry-After` header in responses
  - [x] Standardized error messages on limit exceeded
  - [x] Log rate limit violations
- [x] Test rate limiters with multiple requests
- [x] Verify Redis stores rate limit data correctly

**🚫 HARD REQUIREMENT: No route handlers can be created until:**

1. All error classes are defined
2. Centralized error handler is implemented and tested
3. asyncHandler wrapper utility is created with sample controller demonstrating controller-level wrapping
4. All rate limiters are configured and tested
5. Pattern examples are documented in code showing:
   - Controllers wrapped with asyncHandler at export
   - Routes remain declarative (no controller wrapping in route files)

---

**🎯 MILESTONE 2: Production-Ready Middleware Foundation Complete**

- Centralized error handling enforced
- AsyncHandler pattern ready for all routes
- Redis-based rate limiting configured
- Ready for secure route implementation

---

### 2.8 User Model & Schema

- [x] Create Role model in `/src/models/role.model.ts`:
  - [x] name (unique, required) - e.g., 'user', 'admin', 'super-admin'
  - [x] permissions (array of strings)
  - [x] description
  - [x] timestamps
  - [x] Seed default roles (user, admin, super-admin)
- [x] Create User interface in `/src/types/user.types.ts`
- [x] Create User schema in `/src/models/user.model.ts`
- [x] Add fields:
  - [x] email (unique, required, validated)
  - [x] password (hashed, required for local auth)
  - [x] firstName, lastName
  - [x] role (ObjectId reference to Role model, required, default: 'user' role)
  - [x] isEmailVerified
  - [x] isBanned
  - [x] avatar (URL or path)
  - [x] googleId (for OAuth)
  - [x] twoFactorEnabled, twoFactorSecret
  - [x] passwordChangedAt
  - [x] lastLogin, lastActivity
  - [x] ipHistory (array of IP addresses)
  - [x] timestamps (createdAt, updatedAt)
- [x] Add password hashing pre-save hook (bcrypt)
- [x] Add method to compare passwords
- [x] Add indexes for performance (email, role)

### 2.9 Authentication - Core Setup

- [x] Install dependencies:
  - [x] bcrypt, @types/bcrypt
  - [x] jsonwebtoken, @types/jsonwebtoken
  - [x] cookie-parser, @types/cookie-parser
  - [x] zod for validation
  - [x] express-rate-limit, rate-limit-redis

### 2.10 Authentication - Validation Schemas

- [x] Create Zod schemas in `/src/validators/auth.validators.ts`:
  - [x] Registration schema (email, password, firstName, lastName)
  - [x] Login schema (email, password)
  - [x] Forgot password schema (email)
  - [x] Reset password schema (token, newPassword)
  - [x] Change password schema (oldPassword, newPassword)
- [x] Password policy validation:
  - [x] Minimum 8 characters
  - [x] At least one uppercase letter
  - [x] At least one lowercase letter
  - [x] At least one number
  - [x] At least one special character

### 2.11 Authentication - JWT Token Service

- [x] Create token service in `/src/services/token.service.ts`
- [x] Implement `generateAccessToken(userId, role)`
- [x] Implement `generateRefreshToken(userId)`
- [x] Implement `verifyAccessToken(token)`
- [x] Implement `verifyRefreshToken(token)`
- [x] Create token payload interface

### 2.12 Authentication - Session Management with Redis

- [x] Create session service in `/src/services/session.service.ts`
- [x] Implement `createSession(userId, refreshToken, metadata)`
  - [x] Store in Redis with expiration
  - [x] Include IP address, user agent
- [x] Implement `getSession(sessionId)`
- [x] Implement `refreshSession(sessionId, newRefreshToken)`
- [x] Implement `revokeSession(sessionId)`
- [x] Implement `revokeAllUserSessions(userId)`
- [x] Implement `getActiveUserSessions(userId)`
- [x] Design Redis key schema: `session:{userId}:{sessionId}`

### 2.13 Authentication - Register Feature

**Prerequisites: Phase 2.7.1 MUST be complete (error handler, asyncHandler, rate limiters)**

- [x] Create auth controller in `/src/controllers/auth.controller.ts`
- [x] Implement `register` controller:
  - [x] **Wrap controller with `asyncHandler` at export** (controller-level)
  - [x] Validate input with Zod
  - [x] Check if user exists (throw ConflictError if exists)
  - [x] Hash password with bcrypt
  - [x] Create user in MongoDB
  - [x] Generate email verification token
  - [x] Send verification email
  - [x] Return success response (tokens + csrf)
  - [x] Throw errors on failure (never catch and respond)
- [x] Create auth routes in `/src/routes/auth.routes.ts`
- [x] Add `POST /api/auth/register` route (declarative pattern):
  - [x] Apply `authLimiter` rate limiting
  - [x] Apply Zod validation middleware in the route
  - [x] Reference `authController.register` (already wrapped at controller level)
  - [x] **NEVER wrap controller in route file** - route must be declarative
- [x] Test register endpoint
- [x] Verify errors flow through centralized error handler
- [x] Verify rate limiting works
- [x] Verify route file remains clean and declarative

### 2.14 Authentication - Email Verification

- [x] Install Resend SDK (`resend`) and configure API key in env
- [x] Create email service in `/src/services/email.service.ts` using Resend
- [x] Configure sender domain/from address (Resend)
- [x] Create email templates:
  - [x] Email verification template
  - [x] Password reset template
  - [x] Welcome email template
- [x] Implement `sendVerificationEmail(email, token)` via Resend
- [x] Create verification token (JWT or random string stored in Redis)
- [x] Add `POST /api/auth/verify-email` endpoint
- [x] Implement `verifyEmail` controller:
  - [x] Validate token
  - [x] Update user `isEmailVerified` to true
  - [x] Return success response

### 2.15 Authentication - Login Feature

- [x] Implement `login` controller:
  - [x] Validate input with Zod
  - [x] Find user by email
  - [x] Check if user is banned
  - [x] Verify password
  - [x] Check if email is verified
  - [x] Generate access and refresh tokens
  - [x] Create session in Redis
  - [x] Update lastLogin and lastActivity
  - [x] Track IP address in ipHistory
  - [x] Set HTTP-only secure cookies
  - [x] Return user data and access token
- [x] Add `POST /api/auth/login` route

### 2.16 Authentication - Logout Feature

- [x] Implement `logout` controller:
  - [x] Extract session ID from refresh token or cookie
  - [x] Revoke session in Redis
  - [x] Clear cookies
  - [x] Return success response
- [x] Add `POST /api/auth/logout` route

### 2.17 Authentication - Refresh Token Feature

- [x] Implement `refreshToken` controller:
  - [x] Extract refresh token from cookie
  - [x] Verify refresh token
  - [x] Validate session exists in Redis
  - [x] Generate new access token
  - [x] Generate new refresh token
  - [x] Update session in Redis
  - [x] Set new cookies
  - [x] Return new access token
- [x] Add `POST /api/auth/refresh` route

### 2.18 Authentication - Forgot Password Feature

- [x] Implement `forgotPassword` controller:
  - [x] Validate email with Zod
  - [x] Find user by email
  - [x] Generate password reset token (JWT or random)
  - [x] Store token in Redis with expiration (15 mins)
  - [x] Send password reset email (Resend)
  - [x] Return success response (don't reveal if email exists)
- [x] Add `POST /api/auth/forgot-password` route

### 2.19 Authentication - Reset Password Feature

- [x] Implement `resetPassword` controller:
  - [x] Validate token and new password with Zod
  - [x] Verify token from Redis
  - [x] Find user
  - [x] Hash new password
  - [x] Update user password
  - [x] Update passwordChangedAt timestamp
  - [x] Revoke all user sessions
  - [x] Delete token from Redis
  - [x] Send password changed confirmation email (Resend)
  - [x] Return success response
- [x] Add `POST /api/auth/reset-password` route

### 2.20 Authentication - Change Password Feature (Authenticated)

- [x] Implement `changePassword` controller:
  - [x] Validate old and new passwords with Zod
  - [x] Verify old password
  - [x] Check new password is different
  - [x] Hash new password
  - [x] Update user password
  - [x] Update passwordChangedAt timestamp
  - [x] Revoke all other sessions (keep current)
  - [x] Send password changed confirmation email
  - [x] Return success response
- [x] Add `POST /api/auth/change-password` route (protected)

---

**🎯 MILESTONE 2: Core Authentication Complete**

- User registration, login, logout working
- Email verification implemented
- Password reset flow functional
- JWT tokens with Redis sessions
- Basic auth endpoints tested and working

---

### 2.21 Authentication - Google OAuth Setup

- [x] Install passport, passport-google-oauth20, @types/passport
- [x] Create OAuth config in `/src/config/oauth.ts`
- [x] Configure Google OAuth strategy
- [x] Implement Google OAuth callback handler:
  - [x] Find or create user with googleId
  - [x] Set isEmailVerified to true
  - [x] Generate tokens
  - [x] Create session
  - [x] Redirect to frontend with tokens
- [x] Add `GET /api/auth/google` route
- [x] Add `GET /api/auth/google/callback` route

### 2.22 Authentication - Two-Factor Authentication (2FA)

- [x] Install speakeasy, qrcode, @types/qrcode
- [x] Implement `enable2FA` controller:
  - [x] Generate 2FA secret
  - [x] Store secret temporarily in Redis
  - [x] Generate QR code
  - [x] Return QR code and secret
- [x] Implement `verify2FA` controller:
  - [x] Verify TOTP code
  - [x] Save secret to user model
  - [x] Enable 2FA for user
  - [x] Return success response
- [x] Implement `disable2FA` controller
- [x] Modify login flow to check for 2FA:
  - [x] If 2FA enabled, require TOTP code
  - [x] Validate TOTP before issuing tokens
- [x] Add routes:
  - [x] `POST /api/auth/2fa/enable`
  - [x] `POST /api/auth/2fa/verify`
  - [x] `POST /api/auth/2fa/disable`

### 2.23 Middleware - Authentication Middleware

- [x] Create `auth.middleware.ts` in `/src/middleware/`
- [x] Implement `authenticate` middleware:
  - [x] Extract access token from Authorization header or cookie
  - [x] Verify access token
  - [x] Check if password was changed after token was issued
  - [x] Attach user to request context
  - [x] Handle token expiration errors
- [x] Implement `optionalAuth` middleware (for public routes with optional auth)

---

**🎯 MILESTONE 3: Advanced Auth & Security Complete**

- Google OAuth integrated
- 2FA (TOTP) implemented
- Authentication middleware working
- All auth features tested

---

### 2.24 Middleware - Authorization & RBAC

- [x] Create `authorize.middleware.ts`
- [x] Implement `authorize(...roles)` middleware:
  - [x] Check if user has required role
  - [x] Return 403 if unauthorized
- [x] Create permission-based authorization helpers
- [x] Define role hierarchy: user < admin < super-admin
- [x] Wire authorization middleware on protected routes (2FA flows, IP history)

### 2.25 Middleware - Rate Limiting

- [x] Create `rateLimiter.middleware.ts`
- [x] Configure Redis store for rate limiting
- [x] Create rate limiters:
  - [x] General API: 100 requests per 15 minutes
  - [x] Auth endpoints: 5 requests per 15 minutes
  - [x] Login: 5 attempts per 15 minutes
  - [x] Password reset: 3 attempts per hour
- [x] Apply rate limiters to appropriate routes

### 2.26 Middleware - CSRF Protection

- [x] Install csurf or csrf-csrf (implemented custom Redis-backed CSRF middleware)
- [x] Create CSRF middleware
- [x] Generate CSRF tokens
- [x] Add CSRF token endpoint `GET /api/auth/csrf-token`
- [x] Validate CSRF tokens on state-changing requests (with rotation and block threshold)

### 2.27 Middleware - Security Headers & CSP

- [x] Configure helmet middleware with strict policies
- [x] Set Content Security Policy (CSP)
- [x] Enable HSTS
- [x] Disable X-Powered-By header
- [x] Configure trusted domains

### 2.28 Middleware - Input Validation & Sanitization

**Note: Error handling and rate limiting were completed in Phase 2.7.1 (mandatory prerequisite)**

- [x] Create `validate.middleware.ts` in `/src/middleware/`
- [x] Implement generic Zod validation middleware:
  - [x] Accept Zod schema as parameter
  - [x] Validate req.body, req.params, req.query
  - [x] Throw ValidationError on validation failure
  - [x] Let centralized error handler format response
- [x] Create request sanitization middleware (XSS protection)
- [x] Create detailed request logging middleware

### 2.29 Middleware - Additional Security Utilities

- [x] Create IP tracking utilities
- [x] Create request fingerprinting middleware
- [x] Verify all middleware integrates with asyncHandler pattern

### 2.29.1 Internationalization (Backend i18n)

- [x] Implement backend i18n with locales `en` and `fr` (e.g., central message catalog and locale resolver)
- [x] Add middleware to resolve locale (Accept-Language header → fallback `en`)
- [x] Provide translated strings for errors, validation messages (Zod), and API responses
- [x] Refactor existing messages to use the i18n system (errors, validators, controllers)

### 2.30 User Profile Management

- [x] Create user controller in `/src/controllers/user.controller.ts`
- [x] Implement `getProfile` controller (get own profile)
- [x] Implement `updateProfile` controller:
  - [x] Validate input with Zod
  - [x] Update allowed fields (firstName, lastName)
  - [x] Return updated user
- [x] Implement `deleteAccount` controller:
  - [x] Verify password
  - [x] Soft delete or hard delete user
  - [x] Revoke all sessions
  - [x] Return success response
- [x] Create user routes in `/src/routes/user.routes.ts`:
  - [x] `GET /api/users/profile` (protected)
  - [x] `PATCH /api/users/profile` (protected)
  - [x] `DELETE /api/users/account` (protected)

---

**🎯 MILESTONE 4: Security & Middleware Complete**

- RBAC implemented with role hierarchy
- Rate limiting with Redis active
- CSRF protection enabled
- All security middleware configured
- Input validation with Zod
- Global error handling working

---

### 2.31 Avatar Management

- [ ] Install multer, @types/multer for file uploads
- [ ] Install sharp for image processing
- [ ] Create upload middleware in `/src/middleware/upload.middleware.ts`
- [ ] Configure file size limits (5MB)
- [ ] Validate file types (jpg, png, webp)
- [ ] Create avatar upload directory
- [ ] Implement `uploadAvatar` controller:
  - [ ] Accept image upload
  - [ ] Resize and optimize image with sharp
  - [ ] Save to disk or cloud storage
  - [ ] Update user avatar field
  - [ ] Delete old avatar
  - [ ] Return new avatar URL
- [ ] Implement `deleteAvatar` controller
- [ ] Add routes:
  - [ ] `POST /api/users/avatar` (protected, with multer)
  - [ ] `DELETE /api/users/avatar` (protected)
- [ ] Serve static files for avatars

### 2.32 Admin - User Management

- [ ] Create admin controller in `/src/controllers/admin.controller.ts`
- [ ] Implement `getAllUsers` controller:
  - [ ] Pagination support
  - [ ] Filtering by role, status
  - [ ] Sorting
  - [ ] Search by email/name
- [ ] Implement `getUserById` controller
- [ ] Implement `updateUserRole` controller (admin only)
- [ ] Implement `banUser` controller:
  - [ ] Set isBanned to true
  - [ ] Revoke all user sessions
  - [ ] Send ban notification email
- [ ] Implement `unbanUser` controller
- [ ] Implement `deleteUser` controller (hard delete)
- [ ] Create admin routes in `/src/routes/admin.routes.ts`:
  - [ ] `GET /api/admin/users` (admin only)
  - [ ] `GET /api/admin/users/:id` (admin only)
  - [ ] `PATCH /api/admin/users/:id/role` (admin only)
  - [ ] `POST /api/admin/users/:id/ban` (admin only)
  - [ ] `POST /api/admin/users/:id/unban` (admin only)
  - [ ] `DELETE /api/admin/users/:id` (admin only)

### 2.33 Admin - Session Management

- [ ] Implement `getUserSessions` controller:
  - [ ] Get all active sessions for a user
  - [ ] Return session details (IP, user agent, created at)
- [ ] Implement `revokeUserSession` controller
- [ ] Implement `revokeAllUserSessions` controller
- [ ] Add routes:
  - [ ] `GET /api/admin/users/:id/sessions` (admin only)
  - [ ] `DELETE /api/admin/users/:id/sessions/:sessionId` (admin only)
  - [ ] `DELETE /api/admin/users/:id/sessions` (admin only)

---

**🎯 MILESTONE 5: User & Admin Features Complete**

- User profile management working
- Avatar upload/delete functional
- Admin user management panel ready
- Session management implemented
- Ban/unban functionality working

---

### 2.34 Activity Tracking

- [x] Create activity tracking middleware
- [x] Update lastActivity timestamp on each request
- [x] Track IP addresses in ipHistory array
- [x] Implement `getIpHistory` endpoint for users to see their login history
- [x] Add `GET /api/users/activity/ip-history` route (protected)

### 2.35 Redis Caching Strategy

- [ ] Implement caching for frequently accessed data:
  - [ ] User profiles (cache user data)
  - [ ] Role-based permissions
- [ ] Create cache utility functions in `/src/utils/cache.ts`:
  - [ ] `getCached(key)`
  - [ ] `setCache(key, value, ttl)`
  - [ ] `deleteCache(key)`
  - [ ] `deleteCachePattern(pattern)`
- [ ] Implement cache invalidation strategies
- [ ] Add cache TTL configurations

### 2.36 Logging & Monitoring

- [ ] Configure Winston logger in `/src/config/logger.ts`
- [ ] Create separate log files:
  - [ ] error.log (errors only)
  - [ ] combined.log (all logs)
  - [ ] access.log (HTTP requests via Morgan)
- [ ] Implement log rotation
- [ ] Add structured logging with metadata
- [ ] Log all authentication events
- [ ] Log security-related events

### 2.37 API Documentation

- [ ] Install swagger-jsdoc, swagger-ui-express, @types/swagger-ui-express
- [ ] Create Swagger configuration
- [ ] Document all endpoints with JSDoc comments:
  - [ ] Request/response schemas
  - [ ] Authentication requirements
  - [ ] Error responses
- [ ] Serve API documentation at `/api-docs`

### 2.38 Testing Setup (Optional but Recommended)

- [ ] Install Jest and ts-jest
- [ ] Install supertest for API testing
- [x] Create test configuration (Vitest added)
- [x] Write unit tests for utilities (CSRF middleware covered)
- [x] Write integration tests for auth endpoints
- [x] Add test npm scripts (Vitest)
- [ ] Setup test database

### 2.39 Docker Setup

- [ ] Create `Dockerfile` for backend
- [ ] Create `.dockerignore`
- [ ] Create `docker-compose.yml` with services:
  - [ ] Backend (Node.js)
  - [ ] MongoDB
  - [ ] Redis
- [ ] Configure environment variables for Docker
- [ ] Test Docker build and run

### 2.40 Production Optimizations

- [ ] Implement clustering with Node.js cluster module
- [ ] Setup PM2 configuration file
- [ ] Enable gzip compression
- [ ] Implement MongoDB connection pooling
- [ ] Optimize Redis connections
- [ ] Add health check endpoint: `GET /api/health`
- [ ] Add readiness endpoint: `GET /api/ready`
- [ ] Configure HTTPS (certificates)
- [ ] Setup reverse proxy headers
- [ ] Implement graceful shutdown

### 2.41 Backend Testing & Validation

- [ ] Test all authentication endpoints
- [ ] Test all user management endpoints
- [ ] Test all admin endpoints
- [ ] Verify rate limiting works
- [ ] Test session management
- [x] Test 2FA flow
- [ ] Test OAuth flow
- [ ] Run ESLint and fix all errors
- [ ] Run Prettier to format code
- [ ] Verify no TypeScript `any` types used
- [ ] Check all error handling

---

**🎯 MILESTONE 6: Backend Complete & Production-Ready**

- All backend features implemented and tested
- Docker setup complete
- API documentation (Swagger) available
- Logging and monitoring configured
- Production optimizations applied
- Zero lint errors
- Ready for frontend integration

---

## Phase 3: Frontend Development

### 3.1 Frontend Project Initialization

- [ ] Navigate to `frontend` folder
- [ ] Create Vite + React + TypeScript project:
  - [ ] `npm create vite@latest . -- --template react-ts`
- [ ] Install core dependencies
- [ ] Review and update `tsconfig.json` with strict mode
- [ ] Create folder structure:
  - [ ] `/src/assets` - images, fonts, icons
  - [ ] `/src/components` - reusable components
  - [ ] `/src/pages` - page components
  - [ ] `/src/layouts` - layout components
  - [ ] `/src/hooks` - custom React hooks
  - [ ] `/src/store` - Zustand stores
  - [ ] `/src/services` - API services
  - [ ] `/src/utils` - utility functions
  - [ ] `/src/types` - TypeScript types
  - [ ] `/src/config` - configuration
  - [ ] `/src/i18n` - internationalization
  - [ ] `/src/styles` - global styles

### 3.2 TailwindCSS Setup

- [ ] Follow official Vite installation: https://tailwindcss.com/docs/installation/using-vite
- [ ] Install TailwindCSS: `npm install -D tailwindcss postcss autoprefixer`
- [ ] Initialize Tailwind: `npx tailwindcss init -p`
- [ ] Configure `tailwind.config.js`:
  - [ ] Add content paths
  - [ ] Configure dark mode (class strategy)
  - [ ] Add custom theme colors
  - [ ] Add custom fonts
- [ ] Add Tailwind directives to main CSS file
- [ ] Test Tailwind classes work

### 3.3 Development Tools Setup

- [ ] Install ESLint for React
- [ ] Configure `.eslintrc.cjs` with React rules
- [ ] Install Prettier
- [ ] Create `.prettierrc`
- [ ] Install Husky
- [ ] Configure pre-commit hooks
- [ ] Install lint-staged
- [ ] Add npm scripts: `dev`, `build`, `preview`, `lint`, `format`

### 3.4 Core Dependencies Installation

- [ ] Install React Router DOM (latest): `npm install react-router-dom`
- [ ] Install Zustand (latest): `npm install zustand`
- [ ] Install Axios (latest): `npm install axios`
- [ ] Install React Hook Form (latest): `npm install react-hook-form`
- [ ] Install Zod (latest): `npm install zod`
- [ ] Install @hookform/resolvers for Zod integration
- [ ] Install Lucide React (latest): `npm install lucide-react`
- [ ] Install i18next and react-i18next (latest)
- [ ] Install clsx for conditional classes
- [ ] Install date-fns or dayjs for date formatting

### 3.5 Environment Configuration

- [ ] Create `.env.example` file
- [ ] Create `.env` file (git-ignored)
- [ ] Define environment variables:
  - [ ] VITE_API_URL (backend API URL)
  - [ ] VITE_GOOGLE_CLIENT_ID
- [ ] Create config file in `/src/config/env.ts`
- [ ] Add type-safe environment variable access

### 3.6 Axios Setup & API Client

- [ ] Create Axios instance in `/src/services/api.ts`
- [ ] Configure base URL from env
- [ ] Add request interceptor:
  - [ ] Attach access token to headers
  - [ ] Add CSRF token to headers
- [ ] Add response interceptor:
  - [ ] Handle 401 errors (token refresh)
  - [ ] Handle network errors
- [ ] Implement token refresh logic
- [ ] Create typed API service functions

---

**🎯 MILESTONE 7: Frontend Foundation Complete**

- Vite + React + TypeScript project setup
- TailwindCSS configured with dark mode
- Development tools configured (ESLint, Prettier, Husky)
- Core dependencies installed
- Axios interceptors with token refresh
- Ready for feature development

---

### 3.7 Zustand Store - Auth Store

- [ ] Create auth store in `/src/store/authStore.ts`
- [ ] Define auth state:
  - [ ] user (user object or null)
  - [ ] accessToken
  - [ ] isAuthenticated
  - [ ] isLoading
- [ ] Define auth actions:
  - [ ] login(email, password)
  - [ ] register(userData)
  - [ ] logout()
  - [ ] refreshToken()
  - [ ] updateProfile(data)
  - [ ] checkAuth() (validate current session)
- [ ] Persist auth state to localStorage (optional)

### 3.8 Zustand Store - UI Store

- [ ] Create UI store in `/src/store/uiStore.ts`
- [ ] Define UI state:
  - [ ] theme ('light' | 'dark')
  - [ ] locale ('en' | 'es' | 'fr', etc.)
  - [ ] sidebarOpen
  - [ ] notifications (array)
- [ ] Define UI actions:
  - [ ] toggleTheme()
  - [ ] setLocale(locale)
  - [ ] toggleSidebar()
  - [ ] addNotification(message, type)
  - [ ] removeNotification(id)
- [ ] Persist theme and locale to localStorage

### 3.9 TypeScript Types & Interfaces

- [ ] Create user types in `/src/types/user.ts`:
  - [ ] User interface
  - [ ] UserRole enum
- [ ] Create auth types in `/src/types/auth.ts`:
  - [ ] LoginRequest, LoginResponse
  - [ ] RegisterRequest, RegisterResponse
  - [ ] ForgotPasswordRequest
  - [ ] ResetPasswordRequest
- [ ] Create API response types
- [ ] Create form types

### 3.10 API Service - Auth Service

- [ ] Create auth service in `/src/services/authService.ts`
- [ ] Implement API functions:
  - [ ] `register(data)`
  - [ ] `login(data)`
  - [ ] `logout()`
  - [ ] `refreshToken()`
  - [ ] `forgotPassword(email)`
  - [ ] `resetPassword(token, newPassword)`
  - [ ] `changePassword(oldPassword, newPassword)`
  - [ ] `verifyEmail(token)`
  - [ ] `googleLogin()`
  - [ ] `enable2FA()`
  - [ ] `verify2FA(code)`
  - [ ] `disable2FA()`
- [ ] Add proper TypeScript typing for all functions

### 3.11 API Service - User Service

- [ ] Create user service in `/src/services/userService.ts`
- [ ] Implement API functions:
  - [ ] `getProfile()`
  - [ ] `updateProfile(data)`
  - [ ] `uploadAvatar(file)`
  - [ ] `deleteAvatar()`
  - [ ] `deleteAccount()`
  - [ ] `getIpHistory()`

### 3.12 API Service - Admin Service

- [ ] Create admin service in `/src/services/adminService.ts`
- [ ] Implement API functions:
  - [ ] `getAllUsers(filters, pagination)`
  - [ ] `getUserById(id)`
  - [ ] `updateUserRole(id, role)`
  - [ ] `banUser(id)`
  - [ ] `unbanUser(id)`
  - [ ] `deleteUser(id)`
  - [ ] `getUserSessions(id)`
  - [ ] `revokeUserSession(userId, sessionId)`

### 3.13 Internationalization (i18n) Setup

- [ ] Configure i18next in `/src/i18n/config.ts`
- [ ] Create translation files:
  - [ ] `/src/i18n/locales/en/translation.json`
  - [ ] `/src/i18n/locales/fr/translation.json`
- [ ] Add translations for:
  - [ ] Common UI elements
  - [ ] Authentication pages
  - [ ] Form labels and errors
  - [ ] Notifications
  - [ ] Navigation
- [ ] Create language switcher component
- [ ] Test language switching

---

**🎯 MILESTONE 8: State Management & Services Complete**

- Zustand stores configured (auth, UI)
- All API services implemented (auth, user, admin)
- TypeScript types defined
- i18n setup with English and French
- State persistence configured

---

### 3.14 Dark/Light Theme Implementation

- [ ] Create theme context or use Zustand store
- [ ] Implement theme toggle function
- [ ] Configure Tailwind dark mode (class strategy)
- [ ] Add dark mode classes to components
- [ ] Persist theme preference to localStorage
- [ ] Add smooth theme transitions
- [ ] Create theme toggle button component

### 3.15 Reusable Components - Base Components

- [ ] Create `Button` component:
  - [ ] Variants: primary, secondary, outline, ghost, danger
  - [ ] Sizes: sm, md, lg
  - [ ] Loading state
  - [ ] Disabled state
  - [ ] Icon support
- [ ] Create `Input` component:
  - [ ] Types: text, email, password, number
  - [ ] Error state
  - [ ] Label support
  - [ ] Helper text
  - [ ] Icon support
- [ ] Create `Textarea` component
- [ ] Create `Select` component
- [ ] Create `Checkbox` component
- [ ] Create `Radio` component
- [ ] Create `Switch` component (for toggles)

### 3.16 Reusable Components - UI Components

- [ ] Create `Card` component
- [ ] Create `Badge` component
- [ ] Create `Avatar` component
- [ ] Create `Spinner` component (loading indicator)
- [ ] Create `Alert` component (success, error, warning, info)
- [ ] Create `Toast` notification component
- [ ] Create `Modal` component
- [ ] Create `Dropdown` component
- [ ] Create `Tooltip` component
- [ ] Create `Tabs` component
- [ ] Create `Table` component with pagination

### 3.17 Layout Components

- [ ] Create `Navbar` component:
  - [ ] Logo
  - [ ] Navigation links
  - [ ] User menu dropdown
  - [ ] Theme toggle
  - [ ] Language selector
  - [ ] Responsive (hamburger menu on mobile)
- [ ] Create `Sidebar` component:
  - [ ] Navigation items
  - [ ] Collapsible on desktop
  - [ ] Active link highlighting
  - [ ] Icons with labels
- [ ] Create `Footer` component
- [ ] Create `MainLayout` component (Navbar + children + Footer)
- [ ] Create `DashboardLayout` component (Navbar + Sidebar + children)
- [ ] Create `AuthLayout` component (centered form layout)

### 3.18 Custom Hooks

- [ ] Create `useAuth` hook (access auth store)
- [ ] Create `useTheme` hook
- [ ] Create `useLocale` hook
- [ ] Create `useDebounce` hook
- [ ] Create `useClickOutside` hook
- [ ] Create `useMediaQuery` hook (responsive)
- [ ] Create `useLocalStorage` hook
- [ ] Create `useNotification` hook (toast notifications)

---

**🎯 MILESTONE 9: UI Components Library Complete**

- All reusable base components created (Button, Input, etc.)
- UI components built (Card, Modal, Toast, etc.)
- Layout components ready (Navbar, Sidebar, Footer)
- Custom hooks implemented
- Dark mode support in all components
- Component library ready for pages

---

### 3.19 Form Components with React Hook Form

- [ ] Create `FormInput` component (integrated with RHF)
- [ ] Create `FormTextarea` component
- [ ] Create `FormSelect` component
- [ ] Create `FormCheckbox` component
- [ ] Create form error display component
- [ ] Create Zod validation schemas for forms

### 3.20 Authentication Pages - Register

- [ ] Create Register page in `/src/pages/auth/Register.tsx`
- [ ] Design register form:
  - [ ] Email input (validated)
  - [ ] Password input (show/hide toggle)
  - [ ] Confirm password input
  - [ ] First name, last name inputs
  - [ ] Accept terms checkbox
  - [ ] Submit button
- [ ] Integrate React Hook Form with Zod validation
- [ ] Connect to auth store
- [ ] Handle registration success (show message, redirect)
- [ ] Handle errors (display error messages)
- [ ] Add link to login page
- [ ] Add Google OAuth button

### 3.21 Authentication Pages - Login

- [ ] Create Login page in `/src/pages/auth/Login.tsx`
- [ ] Design login form:
  - [ ] Email input
  - [ ] Password input (show/hide toggle)
  - [ ] Remember me checkbox
  - [ ] Submit button
- [ ] Integrate React Hook Form with Zod validation
- [ ] Connect to auth store
- [ ] Handle login success (redirect to dashboard)
- [ ] Handle 2FA requirement (show 2FA input modal)
- [ ] Handle errors
- [ ] Add links to register and forgot password pages
- [ ] Add Google OAuth button

### 3.22 Authentication Pages - Forgot Password

- [ ] Create Forgot Password page in `/src/pages/auth/ForgotPassword.tsx`
- [ ] Design form:
  - [ ] Email input
  - [ ] Submit button
- [ ] Connect to auth service
- [ ] Handle success (show success message)
- [ ] Handle errors
- [ ] Add link back to login

### 3.23 Authentication Pages - Reset Password

- [ ] Create Reset Password page in `/src/pages/auth/ResetPassword.tsx`
- [ ] Extract token from URL query params
- [ ] Design form:
  - [ ] New password input
  - [ ] Confirm password input
  - [ ] Submit button
- [ ] Validate token
- [ ] Connect to auth service
- [ ] Handle success (redirect to login)
- [ ] Handle errors (invalid/expired token)

### 3.24 Authentication Pages - Email Verification

- [ ] Create Email Verification page in `/src/pages/auth/VerifyEmail.tsx`
- [ ] Extract token from URL query params
- [ ] Auto-verify on page load
- [ ] Show verification status (loading, success, error)
- [ ] Add link to login page

---

**🎯 MILESTONE 10: Authentication Pages Complete**

- All auth pages implemented (Login, Register, etc.)
- Form validation with React Hook Form + Zod
- Error handling and success states
- Google OAuth integration
- 2FA flow working
- Connected to backend API

---

### 3.25 Route Protection & Navigation

- [ ] Install and setup React Router
- [ ] Create route configuration in `/src/config/routes.tsx`
- [ ] Create `ProtectedRoute` component:
  - [ ] Check if user is authenticated
  - [ ] Redirect to login if not authenticated
- [ ] Create `PublicRoute` component:
  - [ ] Redirect to dashboard if already authenticated
- [ ] Create `RoleBasedRoute` component:
  - [ ] Check user role
  - [ ] Redirect to unauthorized page if role doesn't match
- [ ] Define all routes:
  - [ ] `/` - Home (public)
  - [ ] `/login` - Login (public)
  - [ ] `/register` - Register (public)
  - [ ] `/forgot-password` - Forgot Password (public)
  - [ ] `/reset-password` - Reset Password (public)
  - [ ] `/verify-email` - Verify Email (public)
  - [ ] `/dashboard` - User Dashboard (protected)
  - [ ] `/profile` - User Profile (protected)
  - [ ] `/settings` - User Settings (protected)
  - [ ] `/admin/dashboard` - Admin Dashboard (admin only)
  - [ ] `/admin/users` - User Management (admin only)
  - [ ] `/unauthorized` - Unauthorized page

### 3.26 Home Page

- [ ] Create Home page in `/src/pages/Home.tsx`
- [ ] Design landing page:
  - [ ] Hero section
  - [ ] Features section
  - [ ] CTA buttons (Login, Register)
- [ ] Fully responsive design
- [ ] Add animations (optional)
- [ ] SEO meta tags

### 3.27 User Dashboard Page

- [ ] Create User Dashboard page in `/src/pages/dashboard/UserDashboard.tsx`
- [ ] Display welcome message with user name
- [ ] Show user statistics (last login, account created)
- [ ] Display recent activity
- [ ] Quick links to profile, settings
- [ ] Responsive layout

### 3.28 User Profile Page

- [ ] Create Profile page in `/src/pages/profile/Profile.tsx`
- [ ] Display user information (read-only):
  - [ ] Avatar
  - [ ] Name, email
  - [ ] Role
  - [ ] Account status
  - [ ] Created at, last login
- [ ] Add edit button to open edit modal
- [ ] Create Edit Profile modal:
  - [ ] Form to update firstName, lastName
  - [ ] Avatar upload
  - [ ] Submit and cancel buttons
- [ ] Connect to user service
- [ ] Update auth store on success
- [ ] Handle errors

### 3.29 User Settings Page

- [ ] Create Settings page in `/src/pages/settings/Settings.tsx`
- [ ] Organize settings into tabs/sections:
  - [ ] Account Settings
  - [ ] Security Settings
  - [ ] Preferences
- [ ] Account Settings section:
  - [ ] Email (read-only, with change email option if implemented)
  - [ ] Delete account button (with confirmation modal)
- [ ] Security Settings section:
  - [ ] Change password form
  - [ ] Enable/disable 2FA toggle with setup flow
  - [ ] Active sessions list with revoke buttons
- [ ] Preferences section:
  - [ ] Theme toggle (light/dark)
  - [ ] Language selector
- [ ] Connect to respective services
- [ ] Handle success and errors

### 3.30 Admin Dashboard Page

- [ ] Create Admin Dashboard page in `/src/pages/admin/AdminDashboard.tsx`
- [ ] Display admin statistics:
  - [ ] Total users
  - [ ] New users today/week
  - [ ] Active sessions
  - [ ] Banned users
- [ ] Display charts/graphs (optional):
  - [ ] User registrations over time
- [ ] Quick actions:
  - [ ] Go to user management
  - [ ] View system logs
- [ ] Responsive layout

### 3.31 Admin User Management Page

- [ ] Create User Management page in `/src/pages/admin/UserManagement.tsx`
- [ ] Implement data table:
  - [ ] Columns: Avatar, Name, Email, Role, Status, Actions
  - [ ] Pagination
  - [ ] Sorting by columns
  - [ ] Search by email/name
  - [ ] Filter by role, status (active, banned)
- [ ] Action buttons for each user:
  - [ ] View details
  - [ ] Edit role
  - [ ] Ban/unban
  - [ ] Delete
- [ ] Create modals:
  - [ ] View user details modal
  - [ ] Edit role modal
  - [ ] Confirmation modals (ban, delete)
- [ ] Connect to admin service
- [ ] Real-time updates after actions

---

**🎯 MILESTONE 11: All Pages & Features Complete**

- Route protection implemented (Protected, Public, Role-based)
- Home page ready
- User dashboard and profile pages working
- User settings page functional
- Admin dashboard and user management ready
- All navigation working correctly

---

### 3.32 Two-Factor Authentication Flow

- [ ] Create 2FA Setup modal component
- [ ] Display QR code for scanning
- [ ] Show manual entry key
- [ ] Verification code input
- [ ] Connect to auth service
- [ ] Handle success (update UI state)
- [ ] Create 2FA Login modal (for login flow)
- [ ] Integrate with login page

### 3.33 Google OAuth Integration

- [ ] Install @react-oauth/google (if needed)
- [ ] Configure Google OAuth client ID
- [ ] Add Google Sign-In button on login/register pages
- [ ] Handle OAuth callback
- [ ] Store tokens from OAuth flow
- [ ] Update auth state
- [ ] Redirect to dashboard

### 3.34 Notification System

- [ ] Implement toast notification system
- [ ] Create toast container component
- [ ] Add to main app layout
- [ ] Create notification hook
- [ ] Display notifications for:
  - [ ] Login success
  - [ ] Logout success
  - [ ] Registration success
  - [ ] Profile updated
  - [ ] Password changed
  - [ ] Errors (API errors, network errors)
- [ ] Auto-dismiss after timeout
- [ ] Different styles for success, error, warning, info

### 3.35 Error Handling & Boundaries

- [ ] Create Error Boundary component
- [ ] Wrap main app in Error Boundary
- [ ] Create 404 Not Found page
- [ ] Create 500 Server Error page
- [ ] Create Unauthorized page (403)
- [ ] Handle network errors gracefully
- [ ] Display user-friendly error messages

### 3.36 Loading States & Skeletons

- [ ] Create skeleton components for:
  - [ ] Table rows
  - [ ] Cards
  - [ ] Profile information
- [ ] Add loading states to:
  - [ ] Form submissions
  - [ ] Data fetching
  - [ ] Page transitions
- [ ] Create page-level loading component
- [ ] Implement suspense fallbacks

### 3.37 Accessibility (a11y) Compliance

- [ ] Add ARIA labels to interactive elements
- [ ] Ensure keyboard navigation works:
  - [ ] Forms
  - [ ] Modals
  - [ ] Dropdowns
  - [ ] Navigation
- [ ] Add focus indicators
- [ ] Ensure sufficient color contrast (WCAG AA)
- [ ] Add skip navigation link
- [ ] Test with screen readers
- [ ] Add alt text to all images
- [ ] Use semantic HTML elements
- [ ] Add aria-live regions for dynamic content

### 3.38 Responsive Design

- [ ] Test all pages on different screen sizes:
  - [ ] Mobile (320px - 767px)
  - [ ] Tablet (768px - 1023px)
  - [ ] Desktop (1024px+)
- [ ] Ensure navigation is mobile-friendly (hamburger menu)
- [ ] Optimize forms for mobile
- [ ] Test touch interactions
- [ ] Ensure tables are responsive (horizontal scroll or cards)
- [ ] Test on actual devices

### 3.39 Performance Optimization

- [ ] Implement code splitting (lazy loading routes)
- [ ] Optimize images:
  - [ ] Use WebP format
  - [ ] Lazy load images
  - [ ] Use proper image sizes
- [ ] Minimize bundle size:
  - [ ] Tree-shaking
  - [ ] Remove unused dependencies
- [ ] Implement virtual scrolling for long lists (if needed)
- [ ] Optimize re-renders (React.memo, useMemo, useCallback)
- [ ] Add service worker for offline support (optional)

### 3.40 SEO Optimization

- [ ] Install react-helmet-async
- [ ] Add meta tags to all pages:
  - [ ] Title
  - [ ] Description
  - [ ] Keywords
  - [ ] Open Graph tags
  - [ ] Twitter cards
- [ ] Create sitemap.xml
- [ ] Create robots.txt
- [ ] Implement structured data (JSON-LD)

### 3.41 Build & Production Setup

- [ ] Configure Vite for production build
- [ ] Optimize Vite config:
  - [ ] Enable minification
  - [ ] Enable tree-shaking
  - [ ] Configure chunk splitting
- [ ] Create production environment variables
- [ ] Test production build locally
- [ ] Ensure all assets are properly bundled

### 3.42 Frontend Testing & Validation

- [ ] Test all pages and components
- [ ] Test authentication flows (register, login, logout, etc.)
- [ ] Test form validations
- [ ] Test error handling
- [ ] Test theme switching
- [ ] Test language switching
- [ ] Test responsive design
- [ ] Test accessibility
- [ ] Run ESLint and fix all errors
- [ ] Run Prettier to format code
- [ ] Verify no TypeScript `any` types used
- [ ] Check browser console for errors

---

**🎯 MILESTONE 12: Frontend Complete & Optimized**

- All frontend features implemented
- Google OAuth integrated
- Notification system working
- Error boundaries in place
- Loading states and skeletons
- Accessibility compliant (WCAG AA)
- Responsive design tested
- Performance optimized
- SEO optimized
- Production build tested
- Zero lint errors

---

## Phase 4: Integration & Final Testing

### 4.1 End-to-End Testing

- [ ] Test complete user registration flow
- [ ] Test email verification flow
- [ ] Test login and logout flow
- [ ] Test forgot password and reset password flow
- [ ] Test change password flow
- [ ] Test Google OAuth flow
- [ ] Test 2FA setup and login flow
- [ ] Test profile update flow
- [ ] Test avatar upload and delete flow
- [ ] Test admin user management flow
- [ ] Test ban/unban user flow
- [ ] Test session management flow
- [ ] Test rate limiting
- [ ] Test CSRF protection
- [ ] Test all protected routes
- [ ] Test role-based access control

### 4.2 Cross-Browser Testing

- [ ] Test on Chrome
- [ ] Test on Firefox
- [ ] Test on Safari
- [ ] Test on Edge
- [ ] Test on mobile browsers

### 4.3 Security Audit

- [ ] Review all authentication logic
- [ ] Check for SQL/NoSQL injection vulnerabilities
- [ ] Check for XSS vulnerabilities
- [ ] Verify CSRF protection works
- [ ] Verify rate limiting works
- [ ] Check password hashing (bcrypt)
- [ ] Verify JWT token security
- [ ] Check session management security
- [ ] Review CORS configuration
- [ ] Review helmet configuration
- [ ] Verify HTTPS enforcement
- [ ] Check for exposed secrets in code

### 4.4 Performance Testing

- [ ] Load test authentication endpoints
- [ ] Test MongoDB performance under load
- [ ] Test Redis performance
- [ ] Measure API response times
- [ ] Test frontend loading times
- [ ] Run Lighthouse audit
- [ ] Optimize based on results

### 4.5 Documentation Updates

- [ ] Complete README.md:
  - [ ] Project description
  - [ ] Features list
  - [ ] Tech stack
  - [ ] Prerequisites
  - [ ] Installation instructions (backend and frontend)
  - [ ] Environment variable setup
  - [ ] Running the project
  - [ ] API endpoints documentation
  - [ ] Deployment instructions
- [ ] Update API documentation (Swagger)
- [ ] Add inline code comments where needed
- [ ] Create architecture diagram
- [ ] Document database schema

### 4.6 Deployment Preparation

- [ ] Set up production environment variables
- [ ] Configure production MongoDB database
- [ ] Configure production Redis instance
- [ ] Set up SSL certificates
- [ ] Configure domain and DNS
- [ ] Set up reverse proxy (Nginx)
- [ ] Configure PM2 for process management
- [ ] Set up CI/CD pipeline (GitHub Actions, etc.)
- [ ] Configure monitoring and alerting
- [ ] Set up log aggregation
- [ ] Set up backup strategy

### 4.7 Final Checks

- [ ] All lint errors resolved
- [ ] All TypeScript errors resolved
- [ ] No `any` types used
- [ ] All tests passing (if tests implemented)
- [ ] All features working as expected
- [ ] Documentation complete
- [ ] Code formatted with Prettier
- [ ] Git commits clean and well-documented
- [ ] .gitignore properly configured
- [ ] Secrets not committed to repository

---

**🎯 MILESTONE 13: Production Deployment Ready** ✅

- End-to-end testing complete
- Cross-browser testing passed
- Security audit completed
- Performance testing done
- Documentation complete
- Deployment configured
- Monitoring and alerting setup
- All final checks passed
- **PROJECT READY FOR PRODUCTION LAUNCH**

---

## Phase 5: Post-Launch (Optional Enhancements)

### 5.1 Advanced Features

- [ ] Add social login (Facebook, GitHub, etc.)
- [ ] Implement real-time notifications (WebSocket)
- [ ] Add user roles and permissions system (more granular)
- [ ] Implement audit logs
- [ ] Add user preferences and settings
- [ ] Implement account recovery questions
- [ ] Add biometric authentication support
- [ ] Implement passwordless login (magic links)

### 5.2 Admin Features

- [ ] Admin analytics dashboard
- [ ] User activity monitoring
- [ ] System health monitoring
- [ ] Bulk user operations
- [ ] Export user data
- [ ] Advanced search and filtering

### 5.3 User Features

- [ ] User-to-user messaging
- [ ] Notification preferences
- [ ] Account activity log
- [ ] Export personal data (GDPR compliance)
- [ ] Account deletion with data export

### 5.4 DevOps & Monitoring

- [ ] Set up application monitoring (New Relic, Datadog)
- [ ] Implement error tracking (Sentry)
- [ ] Set up uptime monitoring
- [ ] Configure automated backups
- [ ] Implement blue-green deployment
- [ ] Set up staging environment

---

## Dependencies & Prerequisites

### Backend Dependencies

- Node.js (v20+)
- TypeScript (v5.7+)
- Express.js (v5.0+)
- MongoDB (v8.0+)
- Mongoose (v8.8+)
- Redis (v7.4+)
- ioredis (v5.4+)
- bcrypt
- jsonwebtoken
- zod
- helmet
- cors
- compression
- morgan
- winston
- express-rate-limit (REQUIRED - Redis-based rate limiting)
- rate-limit-redis (REQUIRED - Redis store for distributed rate limiting)
- cookie-parser
- nodemailer
- multer
- sharp
- passport
- passport-google-oauth20
- speakeasy
- qrcode
- dotenv
- express-async-errors

### Frontend Dependencies

- React (v18.3+)
- Vite (v6.0+)
- TypeScript (v5.7+)
- TailwindCSS (v4.0+)
- React Router DOM (v7.0+)
- Zustand (v5.0+)
- Axios (v1.7+)
- React Hook Form (v7.53+)
- Zod (v3.24+)
- @hookform/resolvers
- Lucide React (v0.468+)
- i18next (v24.0+)
- react-i18next (v15.1+)
- clsx
- react-helmet-async

### Development Tools

- ESLint
- Prettier
- Husky
- lint-staged
- nodemon
- ts-node

---

## Notes

- This roadmap should be followed sequentially within each phase
- Some tasks can be done in parallel (e.g., backend and frontend development can overlap once APIs are defined)
- Each checkbox represents a completed task
- Mark tasks as complete only when fully tested and working
- Dependencies between tasks are indicated by order
- All code must be in English
- Never use TypeScript `any` type
- Maintain zero lint errors throughout development
- Follow 2025 best practices and latest dependency versions
- Prioritize security, performance, and user experience

**⚠️ MANDATORY PRODUCTION PATTERNS (NON-NEGOTIABLE):**

1. **Centralized Error Handler** - All errors MUST flow through `/src/middleware/errorHandler.ts`
2. **AsyncHandler Wrapper (Controller-Level ONLY)** - ALL async controllers MUST be wrapped with `asyncHandler` at export. Routes MUST remain declarative and NEVER wrap controllers.
3. **Redis-Based Rate Limiting** - ALL endpoints MUST have rate limiting configured (no memory store)
4. Phase 2.7.1 MUST be completed BEFORE any route/controller implementation (BLOCKING REQUIREMENT)

**Controller-Level AsyncHandler Architecture (MANDATORY):**

- ✅ CORRECT: `export const register = asyncHandler(async (req, res, next) => { ... });`
- ✅ CORRECT: `router.post('/register', authLimiter, validate(schema), authController.register);`
- ❌ WRONG: `router.post('/register', asyncHandler(authController.register));`
- ❌ WRONG: Unwrapped async controller function

---

**Status: Ready for Implementation**

Once this roadmap is approved, implementation will begin phase by phase, ensuring each task is completed before moving to the next.
