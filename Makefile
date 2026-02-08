.PHONY: all build run test lint clean keys dev db-up db-down migrate

# ─── Variables ───────────────────────────────────────────────────────
BINARY_NAME=digiauth
BUILD_DIR=./bin
GO=go
GOFLAGS=-v

# ─── Build ───────────────────────────────────────────────────────────
all: lint test build

build:
	@echo "Building $(BINARY_NAME)..."
	$(GO) build $(GOFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/server

run: build
	@echo "Running $(BINARY_NAME)..."
	$(BUILD_DIR)/$(BINARY_NAME)

# ─── Development ─────────────────────────────────────────────────────
dev:
	@echo "Starting dev server with hot reload..."
	@which air > /dev/null 2>&1 || (echo "Installing air..." && go install github.com/air-verse/air@latest)
	air

# ─── Database ────────────────────────────────────────────────────────
db-up:
	@echo "Starting PostgreSQL and Redis..."
	docker compose up -d postgres redis

db-down:
	@echo "Stopping databases..."
	docker compose down

db-reset: db-down
	@echo "Resetting database volumes..."
	docker compose down -v
	$(MAKE) db-up

migrate:
	@echo "Running migrations..."
	@which migrate > /dev/null 2>&1 || (echo "Install golang-migrate: https://github.com/golang-migrate/migrate")
	migrate -path migrations -database "postgres://digiauth:digiauth@localhost:5432/digiauth?sslmode=disable" up

migrate-down:
	migrate -path migrations -database "postgres://digiauth:digiauth@localhost:5432/digiauth?sslmode=disable" down

# ─── Testing ─────────────────────────────────────────────────────────
test:
	@echo "Running tests..."
	$(GO) test ./... -v -race -cover

test-coverage:
	@echo "Generating coverage report..."
	$(GO) test ./... -coverprofile=coverage.out
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

# ─── Linting ─────────────────────────────────────────────────────────
lint:
	@echo "Running linter..."
	@which golangci-lint > /dev/null 2>&1 || (echo "Install golangci-lint: https://golangci-lint.run/")
	golangci-lint run ./...

vet:
	$(GO) vet ./...

# ─── RSA Keys ────────────────────────────────────────────────────────
keys:
	@echo "Generating RSA key pair for JWT signing..."
	@mkdir -p keys
	openssl genrsa -out keys/private.pem 2048
	openssl rsa -in keys/private.pem -pubout -out keys/public.pem
	@echo "Keys generated in keys/ directory"
	@echo "⚠️  Never commit these to git!"

# ─── Cleanup ─────────────────────────────────────────────────────────
clean:
	@echo "Cleaning..."
	rm -rf $(BUILD_DIR) coverage.out coverage.html
	$(GO) clean
