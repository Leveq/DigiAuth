# DigiAuth - GitHub Copilot Instructions

## Project Overview

DigiAuth is an open-source blockchain authentication platform built on DigiByte's Digi-ID protocol. It replaces username/password auth with public-key cryptography — users sign in by scanning a QR code with their DigiByte wallet.

## Architecture

- **Backend**: Go 1.22+ with Chi router, clean architecture (ports & adapters)
- **Frontend**: Next.js 14 (App Router) + TypeScript + Tailwind CSS
- **Database**: PostgreSQL 16 via pgx/v5 driver
- **Cache**: Redis 7 via go-redis/v9
- **Auth**: RS256 JWT access tokens + opaque refresh tokens
- **Crypto**: secp256k1 ECDSA signature verification via btcd

## Go Conventions

### Project Layout
- `cmd/server/` — Entry point only. Wire dependencies, start server, graceful shutdown.
- `internal/domain/` — Pure entities with no external dependencies.
- `internal/domain/ports/` — Interface definitions (repositories, stores). Never import concrete implementations.
- `internal/service/` — Business logic. Depends only on domain and ports.
- `internal/handler/` — HTTP handlers. Thin layer that decodes requests, calls services, encodes responses.
- `internal/middleware/` — Chi-compatible middleware (JWT auth, rate limiting, logging).
- `internal/repository/postgres/` — PostgreSQL implementations of port interfaces.
- `internal/repository/redis/` — Redis implementations of port interfaces.
- `internal/crypto/` — Digi-ID protocol: signature verification, address validation, challenge URI building.
- `pkg/digiauth/` — Public SDK package, extractable as standalone Go module.

### Code Style
- Use standard Go formatting (gofmt/goimports). No exceptions.
- Error handling: Always wrap errors with context using `fmt.Errorf("descriptive message: %w", err)`.
- Never use `panic()` in production code. Return errors instead.
- Use `context.Context` as the first parameter for any function that does I/O.
- Prefer table-driven tests with `t.Run()` subtests.
- Name interfaces by behavior (e.g., `UserRepository`, `ChallengeStore`), not implementation.
- Keep functions short. If a function exceeds ~40 lines, consider breaking it up.
- Use named return values sparingly — only when it genuinely improves readability.
- Prefer `struct` method receivers as pointer receivers (`func (s *AuthService)`) unless the struct is small and immutable.

### Dependency Injection
- All dependencies are injected via constructor functions (e.g., `NewAuthService(repos, config)`).
- Never import a concrete repository from a service. Always depend on the port interface.
- Wire everything in `cmd/server/main.go`.

### Database Patterns
- Use `pgx/v5` with connection pooling (`pgxpool`).
- All queries use parameterized placeholders (`$1`, `$2`) — never string concatenation.
- Use `pgx.NamedArgs` or positional args. Never build SQL strings dynamically.
- Repository methods accept `context.Context` and return `(result, error)`.
- Use `RETURNING` clauses in INSERT/UPDATE to avoid extra SELECT queries.
- Transactions: Use `pgxpool.Pool.BeginTx()` and always `defer tx.Rollback()`.

### Redis Patterns
- Use `go-redis/v9` client.
- All cache keys follow the pattern: `digiauth:{entity}:{identifier}` (e.g., `digiauth:challenge:abc123`).
- Always set TTL on cache entries. Never store without expiry.
- Use `context.Context` for all Redis operations.
- Serialize structs to JSON for storage. Deserialize on retrieval.

### HTTP Handlers
- Use Chi router with `chi.URLParam()` for path parameters.
- Parse request bodies with `json.NewDecoder(r.Body).Decode(&req)`.
- Always validate required fields before calling services.
- Use the `writeJSON()` and `writeError()` helpers from `internal/handler/response.go`.
- Extract client IP from `X-Forwarded-For` header with fallback to `r.RemoteAddr`.
- JWT claims are in request context via `middleware.GetClaims(r.Context())`.

### Authentication & Security
- Access tokens: RS256 JWT, 15-minute TTL, stateless validation.
- Refresh tokens: Opaque hex strings, SHA-256 hashed before storage, 30-day TTL.
- Digi-ID signatures use `"DigiByte Signed Message:\n"` magic prefix (not Bitcoin's).
- DigiByte mainnet P2PKH addresses start with `D` (version byte `0x1E`).
- Never log tokens, private keys, or signatures at INFO level.

## TypeScript/Next.js Conventions (Frontend - web/ directory)

### Stack
- Next.js 14 with App Router (not Pages Router).
- TypeScript strict mode. No `any` types unless absolutely unavoidable.
- Tailwind CSS for all styling. No CSS modules or styled-components.
- Client components marked with `"use client"` directive only when necessary.

### Patterns
- API calls go through a centralized client (`web/src/lib/api.ts`).
- Auth state managed via React Context (`AuthProvider`).
- Use `fetch()` with proper error handling, not axios.
- Server Components by default. Client Components only for interactivity.
- Forms use controlled components with React state, not HTML form submissions.

## Testing

### Go Tests
- File naming: `*_test.go` in the same package.
- Use `testing.T` with subtests: `t.Run("descriptive name", func(t *testing.T) { ... })`.
- Use table-driven tests for functions with multiple input/output scenarios.
- Mock interfaces, not concrete types. Create mock implementations in test files.
- Test crypto functions with known test vectors when available.
- Minimum target: 90% coverage on `internal/crypto/` and `internal/service/`.

### Integration Tests
- Use build tag `//go:build integration` for tests that need real Postgres/Redis.
- Docker Compose provides test databases.

## Common Patterns to Follow

### Creating a new endpoint
1. Define the route in the appropriate handler's `Routes()` method.
2. Write the handler function (decode request → validate → call service → encode response).
3. Add the service method with business logic.
4. If new data access is needed, add to the port interface first, then implement.

### Adding a new domain entity
1. Define the struct in `internal/domain/entities.go`.
2. Define repository interface in `internal/domain/ports/ports.go`.
3. Implement PostgreSQL repository in `internal/repository/postgres/`.
4. Write migration SQL in `migrations/`.
5. Create service in `internal/service/`.
6. Create handler in `internal/handler/`.

## Things to Avoid

- Do NOT use GORM or any ORM. Raw SQL with pgx is the standard for this project.
- Do NOT use gin, echo, or fiber. Chi is the router for this project.
- Do NOT use `log.Fatal()` outside of `main.go`.
- Do NOT store secrets in code. Use environment variables via the config package.
- Do NOT use global variables for state. Pass dependencies through constructors.
- Do NOT use `interface{}` or `any` when a specific type can be used.
- Do NOT create circular imports between internal packages.
- Do NOT use Bitcoin's message magic. DigiByte uses `"DigiByte Signed Message:\n"`.
