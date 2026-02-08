# DigiAuth

**Blockchain authentication platform powered by DigiByte's Digi-ID protocol.**

DigiAuth replaces traditional username/password authentication with public-key cryptography. Users authenticate by scanning a QR code with their DigiByte wallet — no passwords, no usernames, no data to breach.

> 🚧 **Active Development** — Phase 1 (Core Auth Server) in progress.

## How It Works

```
┌──────────┐     1. Request QR     ┌──────────────┐
│  Browser  │ ──────────────────▶  │  DigiAuth    │
│  (React)  │ ◀──────────────────  │  Server (Go) │
│           │  2. digiid:// URI    │              │
└─────┬─────┘                      └──────┬───────┘
      │                                    │
      │  3. Display QR                     │
      ▼                                    │
┌──────────┐  4. Sign challenge    ┌───────┴──────┐
│  QR Code │ ◀─────────────────── │   DigiByte    │
│          │                       │   Wallet      │
└──────────┘  5. POST signature ──▶│              │
                                   └──────────────┘
      │                                    │
      │  6. Poll for result                │  5. Verify ECDSA
      ▼                                    │     signature
┌──────────┐  7. JWT tokens        ┌───────┴──────┐
│  Browser  │ ◀──────────────────  │  DigiAuth    │
│  (React)  │                      │  Server (Go) │
└──────────┘                       └──────────────┘
```

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Go 1.22+ with Chi router |
| Database | PostgreSQL 16 |
| Cache | Redis 7 |
| Auth Tokens | RS256 JWT |
| Frontend | Next.js 14 + TypeScript + Tailwind |
| Crypto | secp256k1 ECDSA (btcd library) |

## Quick Start

### Prerequisites

- Go 1.22+
- Docker & Docker Compose
- OpenSSL (for key generation)

### Setup

```bash
# Clone the repo
git clone https://github.com/kdogg/digiauth.git
cd digiauth

# Generate RSA keys for JWT signing
make keys

# Copy environment config
cp .env.example .env

# Start PostgreSQL and Redis
make db-up

# Run database migrations
make migrate

# Start the server (with hot reload)
make dev
```

The server will be available at `http://localhost:8080`.

### Verify It's Running

```bash
curl http://localhost:8080/health
# {"status":"ok","service":"digiauth","version":"0.1.0"}
```

## Project Structure

```
digiauth/
├── cmd/server/          # Application entry point
├── internal/
│   ├── config/          # Environment-based configuration
│   ├── crypto/          # Digi-ID signature verification (secp256k1)
│   ├── domain/          # Core entities (User, Session, Challenge)
│   │   └── ports/       # Repository & store interfaces
│   ├── handler/         # HTTP request handlers
│   ├── middleware/       # JWT auth, rate limiting, logging
│   ├── repository/
│   │   ├── postgres/    # PostgreSQL implementations
│   │   └── redis/       # Redis implementations
│   └── service/         # Business logic (AuthService, UserService)
├── pkg/digiauth/        # Public SDK (extractable Go module)
├── migrations/          # PostgreSQL migration files
├── web/                 # Next.js frontend (Phase 2)
├── sdk/                 # TypeScript SDK (Phase 4)
└── docs/                # Architecture documentation
```

## API Endpoints

### Authentication (Public)
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/auth/challenge` | Generate Digi-ID QR challenge |
| POST | `/api/v1/auth/callback` | Wallet signature callback |
| GET | `/api/v1/auth/poll/{nonce}` | Poll for auth result |
| POST | `/api/v1/auth/refresh` | Refresh access token |

### Users (Authenticated)
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/users/me` | Get current user profile |
| PUT | `/api/v1/users/me` | Update profile |
| GET | `/api/v1/users/{id}` | Get public profile |

## Integration

DigiAuth is designed to be reused across projects. Three integration patterns:

1. **OAuth2 Redirect** — Add "Sign in with DigiByte" to any app (like "Sign in with Google")
2. **TypeScript SDK** — `npm install @kdogg/digiauth-sdk` for React/Next.js apps
3. **Direct API** — Call REST endpoints from any backend

See [Integration Guide](docs/integration.md) for details.

## Development

```bash
make build          # Build binary
make test           # Run tests with race detection
make test-coverage  # Generate HTML coverage report
make lint           # Run golangci-lint
make db-reset       # Reset database (drop + recreate)
```

## Roadmap

- [x] Phase 1: Core auth server (Go + Digi-ID crypto + JWT)
- [ ] Phase 2: User profiles + Next.js frontend
- [ ] Phase 3: Social feed demo + protected API examples
- [ ] Phase 4: OAuth2 provider + TypeScript SDK
- [ ] Phase 5: Production deployment + community launch

## License

MIT — see [LICENSE](LICENSE)

## Contributing

Contributions welcome! This project is open source because the DigiByte ecosystem deserves modern, well-documented authentication tooling.

---

**Built by [KDOGG](https://leveq.dev)** | Powered by [DigiByte](https://digibyte.org)
