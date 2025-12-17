# AI Coding Agent Instructions - MERN Auth v4 (Production 2025+)

## Project Info

Developer: Shunt
GitHub Repo: https://github.com/shuntps/mern-auth-v4.git

## Project Architecture

This is a **production-ready MERN authentication system** split into two independent projects:

- `backend/` - Node.js + Express + TypeScript + MongoDB + Redis + Role-Based Access Control (RBAC)
- `frontend/` - React + Vite + TypeScript + TailwindCSS + Role-Based Access Control (RBAC)

**Key Architectural Decisions:**

- **Dual-token auth**: JWT access tokens (short-lived) + refresh tokens (long-lived, stored in Redis sessions)
- **Redis-first sessions**: All session management, rate limiting, and caching use Redis (ioredis client)
- **Service-controller pattern**: Controllers handle HTTP, services contain business logic
- **Strict separation**: Frontend and backend are completely independent with separate package.json files

## Critical Development Rules

### TypeScript Strictness

- **NEVER use `any` type** - use `unknown`, generics, or proper types
- Both projects use strict mode in tsconfig.json
- All files must be strictly typed with explicit return types on functions

### Dependency Management

- **Always use latest versions** (as of December 2025)
- Install with `npm install` or `npx create-*` (never yarn/pnpm)
- Backend: Express v5.2.1+, Mongoose v9.0.1+, ioredis v5.8.2+
- Frontend: React v19.2.3+, Vite v7.2.7+, TailwindCSS v4.1.18+, Zustand v5.0.9+

### Progressive Development Approach

1. **Follow ROADMAP.md sequentially** - each checkbox must be completed before moving forward
2. **Zero lint errors at all stages** - run ESLint after every change
3. **Roadmap-first**: Never implement code before the roadmap is approved
4. **Test as you build**: Verify each feature works before marking task complete
5. **No duplicates:** If similar code exists, do not create a new one—re-use or extend existing code

## Backend Conventions

### Folder Structure (backend/src/)

```
/config     - Database, Redis, environment, logger configs
/controllers - HTTP request handlers (thin, delegate to services)
/services   - Business logic (token, session, email, etc.)
/models     - Mongoose schemas with TypeScript interfaces
/routes     - Express route definitions
/middleware - Auth, validation, rate limiting, error handling
/utils      - Helper functions, custom error classes
/types      - TypeScript type definitions
/validators - Zod validation schemas
```

### Authentication Flow Pattern

1. **Register**: Validate with Zod → hash password (bcrypt) → save user → send verification email
2. **Login**: Validate → verify password → create Redis session → generate JWT pair → set HTTP-only cookies
3. **Refresh**: Verify refresh token → check Redis session → issue new access token → update session
4. **Logout**: Revoke Redis session → clear cookies

**Redis Session Keys**: `session:{userId}:{sessionId}` with metadata (IP, user agent, timestamps)

### Validation Pattern

- Use Zod schemas in `/validators/*` for all input validation
- Password policy: min 8 chars, 1 uppercase, 1 lowercase, 1 number, 1 special char
- Apply validation middleware to routes: `validate(authValidators.registerSchema)`

### Error Handling

- Custom error classes in `/utils/errors.ts`: AppError, ValidationError, AuthenticationError
- Global error handler catches all errors and formats responses
- Never expose stack traces or sensitive data in production

### Security Stack

- **Helmet** for security headers + CSP configuration
- **express-rate-limit** with Redis store (5 login attempts per 15 min)
- **CSRF protection** with token endpoint
- **HTTP-only secure cookies** for refresh tokens
- **IP tracking** in user.ipHistory array

## Frontend Conventions

### Folder Structure (frontend/src/)

```
/components - Reusable UI (Button, Input, Modal, etc.)
/pages      - Page components (Login, Dashboard, Profile)
/layouts    - Layout wrappers (MainLayout, DashboardLayout, AuthLayout)
/store      - Zustand stores (authStore, uiStore)
/services   - Axios API clients (authService, userService, adminService)
/hooks      - Custom React hooks (useAuth, useTheme, useDebounce)
/types      - TypeScript interfaces
/i18n       - Translation files (en,fr)
/config     - Environment and route configs
```

### State Management (Zustand)

- **authStore**: user, accessToken, isAuthenticated, login(), logout(), refreshToken()
- **uiStore**: theme ('light'|'dark'), locale, sidebarOpen, notifications[]
- Persist theme and locale to localStorage

### Component Patterns

- **Reusable components** in `/components` with variants (Button: primary, secondary, outline, ghost)
- **Form components** integrate React Hook Form + Zod validation
- **Layout components** handle Navbar, Sidebar, Footer composition
- All components support dark mode via Tailwind's `dark:` classes

### TailwindCSS Setup

- Installed via official Vite guide: `npm install -D tailwindcss postcss autoprefixer`
- Dark mode: `class` strategy (toggle via Zustand uiStore)
- Custom theme in tailwind.config.js (colors, fonts)

### Route Protection

- `<ProtectedRoute>` - requires authentication, redirects to /login
- `<RoleBasedRoute roles={['admin']}>` - checks user.role, redirects to /unauthorized
- Token refresh happens automatically in Axios interceptor on 401 errors

## Development Workflows

### Backend Development

```bash
cd backend
npm run dev        # Start with nodemon + ts-node
npm run build      # Compile TypeScript to /dist
npm run start      # Run compiled code (production)
npm run lint       # ESLint check
npm run format     # Prettier format
```

### Frontend Development

```bash
cd frontend
npm run dev        # Vite dev server (hot reload)
npm run build      # Production build
npm run preview    # Preview production build
npm run lint       # ESLint check
npm run format     # Prettier format
```

### Docker Stack

```bash
docker-compose up  # Starts backend, MongoDB, Redis together
```

## Integration Points

### Backend ↔ Frontend

- **API Base URL**: Frontend reads from `VITE_API_URL` env variable
- **CORS**: Backend allows `FRONTEND_URL` from env variable
- **Cookies**: Backend sets HTTP-only cookies, frontend sends automatically
- **CSRF**: Frontend fetches token from `GET /api/auth/csrf-token`, includes in headers

### Backend ↔ MongoDB

- Connection via Mongoose with connection pooling
- Graceful shutdown closes connection
- User model has pre-save hook for password hashing

### Backend ↔ Redis

- ioredis client in `/config/redis.ts` with retry logic
- Used for: sessions, rate limiting, caching, temporary tokens
- All session operations use TTL (refresh token expiry)

### External Services

- **Nodemailer**: Email verification, password reset, notifications
- **Google OAuth**: Passport.js with passport-google-oauth20 strategy
- **Speakeasy + QRCode**: 2FA implementation

## Code Quality Standards

### Linting & Formatting

- ESLint with TypeScript rules for both projects
- Prettier with consistent config
- Husky pre-commit hook runs lint-staged (lint + format)
- **Zero lint errors required** before committing

### Documentation

- JSDoc comments on all exported functions with no examples
- Inline comments for complex logic
- Swagger/OpenAPI docs at `/api-docs` endpoint
- README.md with setup instructions

### Testing (when implemented)

- Jest + supertest for backend integration tests
- Test database separate from development
- Focus on auth endpoints and critical flows

## Common Pitfalls to Avoid

1. **Don't mix auth approaches** - always use JWT + Redis sessions pattern
2. **Don't skip Zod validation** - validate all user inputs
3. **Don't forget rate limiting** - apply to all sensitive endpoints
4. **Don't use `any`** - find the proper type or use `unknown`
5. **Don't install deps globally** - always use project-local npm install
6. **Don't skip ROADMAP** - follow sequential implementation
7. **Don't forget dark mode** - test all UI components in both themes
8. **Don't hardcode secrets** - always use environment variables
9. **No duplicates:** If similar code exists, do not create a new one—re-use or extend existing code.

## Quick Reference

**User Roles**: `user` (default), `admin`, `super-admin`
**JWT Expiry**: Access 15min, Refresh 7days (configurable in env)
**Rate Limits**: General 100/15min, Auth 5/15min, Password reset 3/hour
**Password Hashing**: bcrypt with 10 rounds
**Session Storage**: Redis with key pattern `session:{userId}:{sessionId}`
**File Uploads**: Multer for avatars, Sharp for image processing (5MB limit)
**Supported Languages**: English (en), French (fr)

## Default Configuration Values

### JWT Tokens

- `JWT_ACCESS_EXPIRES_IN`: `15m` (15 minutes)
- `JWT_REFRESH_EXPIRES_IN`: `7d` (7 days)

### Redis TTL

- Session: 7 days (matches refresh token expiry)
- Email verification token: 24 hours
- Password reset token: 15 minutes
- Rate limit window: 15 minutes
- Cache: 1 hour (configurable per resource)

### MongoDB

- Connection pool size: 10 (development), 50 (production)
- Connection timeout: 30 seconds
- Auto-index: enabled (development), disabled (production)

### Rate Limits

- General API: 100 requests / 15 minutes
- Auth endpoints: 5 requests / 15 minutes
- Login attempts: 5 attempts / 15 minutes
- Password reset: 3 requests / 1 hour

### File Uploads

- Max avatar size: 5MB
- Allowed formats: jpg, jpeg, png, webp
- Image output: resized to 500x500px, optimized with Sharp

### Security

- bcrypt rounds: 10
- Cookie max age: 7 days (matches refresh token)
- CSRF token length: 32 bytes
- Session ID length: 32 bytes (hex)

## Current Project Status

Check ROADMAP.md for implementation progress. All tasks must be completed in order, with checkboxes marked only when fully tested and working.
