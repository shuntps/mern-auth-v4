# Contributing to MERN Auth v4

Thank you for considering contributing to this project! 🎉

## 🚀 Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/mern-auth-v4.git
   cd mern-auth-v4
   ```
3. **Create a branch** for your feature or bugfix:
   ```bash
   git checkout -b feature/your-feature-name
   ```

## 📋 Development Guidelines

### Code Standards

- **TypeScript Strict Mode**: Never use `any` type - use `unknown`, generics, or proper types
- **Zero Lint Errors**: Run `npm run lint` before committing - all errors must be fixed
- **Formatting**: Code is auto-formatted with Prettier on commit via Husky
- **Naming Conventions**:
  - Files: camelCase for TypeScript files (e.g., `authService.ts`)
  - Components: PascalCase (e.g., `LoginPage.tsx`)
  - Variables/Functions: camelCase
  - Constants: UPPER_SNAKE_CASE
  - Interfaces/Types: PascalCase with descriptive names

### Git Workflow

1. **Follow the ROADMAP**: Check [ROADMAP.md](ROADMAP.md) for current phase and tasks
2. **Sequential Development**: Complete tasks in order, don't skip ahead
3. **Commit Messages**: Use clear, descriptive commit messages
   ```
   feat: add user registration endpoint
   fix: resolve token refresh race condition
   docs: update API documentation
   refactor: simplify authentication middleware
   test: add unit tests for token service
   ```
4. **Small Commits**: Commit frequently with focused changes
5. **Branch Naming**:
   - Features: `feature/description`
   - Bugfixes: `fix/description`
   - Documentation: `docs/description`
   - Refactoring: `refactor/description`

### Before Submitting

✅ **Checklist**:

- [ ] Code follows TypeScript strict mode (no `any` types)
- [ ] All ESLint errors resolved (`npm run lint`)
- [ ] Code formatted with Prettier (`npm run format`)
- [ ] Changes tested locally
- [ ] No console.log statements (use Winston logger)
- [ ] Environment variables documented in `.env.example`
- [ ] Functions have JSDoc comments
- [ ] No hardcoded secrets or sensitive data
- [ ] README.md updated if needed
- [ ] ROADMAP.md checkboxes marked if task completed

### Testing

- Run backend tests: `cd backend && npm test`
- Run frontend tests: `cd frontend && npm test`
- Test in development environment before submitting
- For new features, add appropriate tests

### Code Review Process

1. **Create Pull Request** with clear description
2. **Link Related Issues**: Reference issue numbers in PR description
3. **Wait for Review**: Maintainers will review your code
4. **Address Feedback**: Make requested changes
5. **Get Approval**: PR must be approved before merging

## 🏗️ Project Architecture

### Backend Structure

```
backend/src/
├── config/       - Configuration files (database, redis, env)
├── controllers/  - HTTP request handlers (thin layer)
├── services/     - Business logic (where the magic happens)
├── models/       - Mongoose schemas with TypeScript interfaces
├── routes/       - API route definitions
├── middleware/   - Custom middleware (auth, validation, etc.)
├── utils/        - Helper functions and utilities
├── types/        - TypeScript type definitions
└── validators/   - Zod validation schemas
```

**Pattern**: Controllers delegate to Services. Services contain business logic.

### Frontend Structure

```
frontend/src/
├── components/   - Reusable UI components
├── pages/        - Page components
├── layouts/      - Layout wrappers
├── store/        - Zustand state management
├── services/     - API client services (Axios)
├── hooks/        - Custom React hooks
├── types/        - TypeScript interfaces
├── i18n/         - Internationalization (en, fr)
└── config/       - Configuration files
```

**Pattern**: Pages use Components and Layouts. State via Zustand. API calls via Services.

## 🔒 Security Guidelines

- **Never commit secrets**: Use environment variables
- **Validate all inputs**: Use Zod schemas for validation
- **Sanitize outputs**: Prevent XSS attacks
- **Use parameterized queries**: Prevent SQL/NoSQL injection
- **Hash passwords**: Use bcrypt with proper salt rounds
- **Rate limit**: Apply rate limiting to sensitive endpoints
- **HTTPS only**: Enforce HTTPS in production
- **Secure cookies**: Use HTTP-only and secure flags

## 🐛 Reporting Bugs

1. **Check existing issues** to avoid duplicates
2. **Create detailed issue** with:
   - Clear title and description
   - Steps to reproduce
   - Expected vs actual behavior
   - Screenshots if applicable
   - Environment details (OS, Node version, etc.)
   - Error messages and stack traces

## 💡 Requesting Features

1. **Check ROADMAP.md** - feature might already be planned
2. **Open an issue** with:
   - Clear description of the feature
   - Use case and benefits
   - Proposed implementation (optional)

## 📝 Documentation

- Update README.md for user-facing changes
- Update API documentation (Swagger) for new endpoints
- Add JSDoc comments to functions (no code examples)
- Update ROADMAP.md checkboxes when completing tasks

## ⚠️ Important Notes

- **Follow the ROADMAP**: Don't implement features out of order
- **No duplicates**: Reuse existing code, don't create duplicates
- **Zero `any` types**: Use proper TypeScript types
- **Test your changes**: Verify functionality before submitting
- **Ask questions**: If unsure, open an issue to discuss

## 🎯 Development Commands

### Backend

```bash
cd backend
npm run dev        # Development server with hot reload
npm run build      # Build for production
npm run start      # Start production server
npm run lint       # Run ESLint
npm run format     # Format with Prettier
npm test           # Run tests
```

### Frontend

```bash
cd frontend
npm run dev        # Development server with hot reload
npm run build      # Build for production
npm run preview    # Preview production build
npm run lint       # Run ESLint
npm run format     # Format with Prettier
npm test           # Run tests
```

## 📧 Contact

- **GitHub Issues**: For bugs and feature requests
- **GitHub Discussions**: For questions and general discussion
- **Developer**: [@shuntps](https://github.com/shuntps)

## 📄 License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thank you for contributing! 🙏
