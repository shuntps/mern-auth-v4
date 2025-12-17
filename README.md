# MERN Auth v4 - Production Authentication System

A modern, production-ready MERN stack authentication system built with TypeScript, following 2025 industry standards.

## 🚀 Features

### Authentication & Authorization

- ✅ User registration with email verification
- ✅ Secure login/logout with JWT tokens
- ✅ Refresh token rotation with Redis sessions
- ✅ Password reset via email
- ✅ Change password (authenticated users)
- ✅ Google OAuth 2.0 integration
- ✅ Two-Factor Authentication (2FA/TOTP)
- ✅ Role-Based Access Control (RBAC)
- ✅ Session management (view active sessions, revoke sessions)

### Security

- 🔒 HTTP-only secure cookies
- 🔒 CSRF protection
- 🔒 Rate limiting with Redis
- 🔒 Content Security Policy (CSP)
- 🔒 Helmet.js security headers
- 🔒 Password hashing with bcrypt (10 rounds)
- 🔒 IP tracking and history
- 🔒 Account ban/unban functionality

### User Management

- 👤 User profiles with avatar upload
- 👤 Profile editing (name, email, avatar)
- 👤 Account deletion
- 👤 IP history tracking
- 👤 Last login and activity timestamps

### Admin Features

- 🛡️ User management dashboard
- 🛡️ Role assignment (user, admin, super-admin)
- 🛡️ Ban/unban users
- 🛡️ View and revoke user sessions
- 🛡️ User search and filtering
- 🛡️ Pagination and sorting

### Developer Experience

- 📦 TypeScript with strict mode (no `any` types)
- 📦 ESLint + Prettier + Husky
- 📦 Modular architecture (controllers/services/routes)
- 📦 Zod validation schemas
- 📦 Winston logging
- 📦 Swagger/OpenAPI documentation
- 📦 Docker support
- 📦 Zero lint errors enforced

### Frontend Features

- 🎨 React 19 + Vite 7 + TypeScript
- 🎨 TailwindCSS 4 with dark mode
- 🎨 Zustand state management
- 🎨 React Hook Form + Zod validation
- 🎨 Internationalization (i18n) - English, French
- 🎨 Responsive design (mobile-first)
- 🎨 Accessibility compliant (WCAG AA)
- 🎨 SEO optimized
- 🎨 Lucide icons
- 🎨 Toast notifications
- 🎨 Loading states and skeletons

## 🛠️ Tech Stack

### Backend

- **Runtime**: Node.js v20+
- **Framework**: Express.js v5.2+
- **Language**: TypeScript v5.7+
- **Database**: MongoDB v8.0+ with Mongoose v9.0+
- **Cache/Sessions**: Redis v7.4+ with ioredis v5.8+
- **Authentication**: JWT with bcrypt
- **Validation**: Zod
- **Email**: Nodemailer
- **File Upload**: Multer + Sharp
- **OAuth**: Passport.js with Google strategy
- **2FA**: Speakeasy + QRCode
- **Logging**: Winston + Morgan
- **Security**: Helmet, CORS, express-rate-limit
- **API Docs**: Swagger/OpenAPI

### Frontend

- **Framework**: React v19.2+
- **Build Tool**: Vite v7.2+
- **Language**: TypeScript v5.7+
- **Styling**: TailwindCSS v4.1+
- **State Management**: Zustand v5.0+
- **HTTP Client**: Axios v1.7+
- **Forms**: React Hook Form v7.53+
- **Validation**: Zod v3.24+
- **Routing**: React Router DOM v7.0+
- **Icons**: Lucide React v0.468+
- **i18n**: i18next v24.0+ with react-i18next

### DevOps

- **Containerization**: Docker + Docker Compose
- **Process Manager**: PM2
- **Code Quality**: ESLint, Prettier, Husky, lint-staged
- **Version Control**: Git

## 📋 Prerequisites

- Node.js v20 or higher
- MongoDB v8.0 or higher
- Redis v7.4 or higher
- npm v10 or higher
- Git

## 🚀 Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/shuntps/mern-auth-v4.git
cd mern-auth-v4
```

### 2. Backend Setup

```bash
cd backend
npm install
cp .env.example .env
# Edit .env with your configuration
npm run dev
```

### 3. Frontend Setup

```bash
cd frontend
npm install
cp .env.example .env
# Edit .env with your configuration
npm run dev
```

### 4. Docker Setup (Alternative)

```bash
docker-compose up
```

## 📁 Project Structure

```
mern-auth-v4/
├── backend/                 # Backend API (Node.js + Express + TypeScript)
│   ├── src/
│   │   ├── config/         # Configuration files
│   │   ├── controllers/    # Request handlers
│   │   ├── services/       # Business logic
│   │   ├── models/         # MongoDB schemas
│   │   ├── routes/         # API routes
│   │   ├── middleware/     # Custom middleware
│   │   ├── utils/          # Utility functions
│   │   ├── types/          # TypeScript types
│   │   └── validators/     # Zod validation schemas
│   ├── package.json
│   └── tsconfig.json
│
├── frontend/               # Frontend (React + Vite + TypeScript)
│   ├── src/
│   │   ├── components/    # Reusable UI components
│   │   ├── pages/         # Page components
│   │   ├── layouts/       # Layout components
│   │   ├── store/         # Zustand stores
│   │   ├── services/      # API services
│   │   ├── hooks/         # Custom React hooks
│   │   ├── types/         # TypeScript types
│   │   ├── i18n/          # Internationalization
│   │   └── config/        # Configuration
│   ├── package.json
│   └── tsconfig.json
│
├── docs/                   # Documentation
├── .github/               # GitHub configs and CI/CD
├── ROADMAP.md             # Development roadmap
└── README.md              # This file
```

## 🔧 Environment Variables

### Backend (.env)

```env
NODE_ENV=development
PORT=5000
MONGODB_URI=mongodb://localhost:27017/mern-auth-v4
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=

JWT_ACCESS_SECRET=your-access-secret-here
JWT_REFRESH_SECRET=your-refresh-secret-here
JWT_ACCESS_EXPIRES_IN=15m
JWT_REFRESH_EXPIRES_IN=7d

COOKIE_SECRET=your-cookie-secret-here

FRONTEND_URL=http://localhost:5173

SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASS=your-app-password

GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
```

### Frontend (.env)

```env
VITE_API_URL=http://localhost:5000/api
VITE_GOOGLE_CLIENT_ID=your-google-client-id
```

## 🧪 Development

### Backend

```bash
cd backend
npm run dev        # Start development server
npm run build      # Build for production
npm run start      # Start production server
npm run lint       # Run ESLint
npm run format     # Format with Prettier
```

### Frontend

```bash
cd frontend
npm run dev        # Start development server
npm run build      # Build for production
npm run preview    # Preview production build
npm run lint       # Run ESLint
npm run format     # Format with Prettier
```

## 📚 API Documentation

Once the backend is running, visit:

- Swagger UI: `http://localhost:5000/api-docs`

## 🎯 User Roles

- **user**: Default role, can manage own profile
- **admin**: Can manage users, view sessions, ban/unban users
- **super-admin**: Full system access

## 🔐 Security Features

- JWT access tokens (15 min expiry)
- JWT refresh tokens (7 day expiry) stored in Redis
- HTTP-only secure cookies
- CSRF protection
- Rate limiting (Redis-backed)
- Password hashing with bcrypt (10 rounds)
- IP tracking and history
- Session management (revocable sessions)
- Content Security Policy
- Helmet security headers

## 📝 License

MIT License - see [LICENSE](LICENSE) file for details

## 👨‍💻 Developer

**Shunt**

- GitHub: [@shuntps](https://github.com/shuntps)
- Repository: [mern-auth-v4](https://github.com/shuntps/mern-auth-v4)

## 🤝 Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## 📖 Documentation

For detailed development instructions, see:

- [ROADMAP.md](ROADMAP.md) - Development roadmap with milestones
- [.github/copilot-instructions.md](.github/copilot-instructions.md) - AI agent guidelines
- [docs/MERN_AUTH_V4-PROJECT.md](docs/MERN_AUTH_V4-PROJECT.md) - Project specifications

## 🎉 Acknowledgments

Built following 2025 industry best practices with a focus on security, performance, and developer experience.

---

**Status**: 🚧 In Development (Phase 1: Project Setup)

See [ROADMAP.md](ROADMAP.md) for current progress and upcoming milestones.
