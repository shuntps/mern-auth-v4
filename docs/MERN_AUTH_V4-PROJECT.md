Create a modern, ultra-fast, production-ready, modular, and reusable MERN stack project using TypeScript, following 2025 industry standards. Include full internationalization (i18n) support, responsive design, dark/light mode, and accessibility (a11y) compliance. All code must be in English, clean, maintainable, and strictly typed. Never use the TypeScript type `any`. Always follow recommended methods for installing dependencies using npm or npx. Always use the latest versions of dependencies as of December 2025. Separate the project into two main folders: `backend` for the API and `frontend` for the frontend. Initialize projects, install dependencies, and run scripts using npm or npx only. Develop the project progressively, ensuring zero lint errors at all stages.

**Backend (`backend` folder, Node.js + Express + TypeScript + MongoDB):**

- Authentication & Authorization:
  - Register, login, logout, forgot password, change password, Google OAuth, 2FA
  - Role-Based Access Control (RBAC)
  - Token-based authentication (JWT access + refresh tokens)
  - Session management with Redis (refreshable, revocable sessions)
  - Secure HTTP-only cookies
  - Rate limiting with express-rate-limit (Redis must be used)
  - IP tracking, IP history, last login, last activity
  - Ban/unban users
  - Password policies and input validation (Zod)
  - CSRF protection
  - Content Security Policy (CSP)
  - HTTPS enforcement
- User Profile & Avatar Management
- Security & Performance: Helmet, CORS, compression, Morgan, Winston, async handlers, global error handling, modular controllers/services/routes
- Redis usage: Redis may also be used in other parts of the backend for caching, storing temporary data, or any other feature that benefits from fast in-memory storage
- DevOps & Production Readiness: environment configs, Docker-ready, scripts (`npm run dev`, `build`, `start`), logging, caching, MongoDB connection pooling

**Frontend (`frontend` folder, React + Vite + TypeScript + TailwindCSS):**

- Zustand, Axios, React Hook Form, Zod, Lucide Icons
- TailwindCSS installed following official Vite procedure: https://tailwindcss.com/docs/installation/using-vite
- Pages: Home, Admin Dashboard, User Dashboard, Authentication pages
- Components: reusable UI components, forms, modals, alerts, Navbar, Sidebar, Footer
- Features: dark/light mode, i18n, notifications, lazy loading, SEO-friendly routes, accessibility compliance
- Optimization: production-ready, responsive design, error boundaries, performance best practices

**Additional Requirements:**

- Strict TypeScript mode, never use `any`
- ESLint, Prettier, Husky configured
- Modular project structure
- Comments and documentation
- Modern JS/TS syntax (ES2025)
- Readme with setup instructions and feature list
- Always install dependencies and initialize projects using npm or npx
- Always use latest dependency versions (December 2025)
- Optimize for production: caching, clustering, compression, HTTPS
- Develop progressively, ensuring zero lint errors at all stages

**Key Requirement:**
Copilot must **generate the full roadmap first** with checkboxes and sub-tasks, **before writing any actual implementation code**, so the roadmap acts as a master plan for the entire project. Redis should be used not only for session management but may also be leveraged in other backend functionalities wherever fast in-memory storage, caching, or temporary data storage is beneficial.
