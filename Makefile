GO ?= go
COMPOSE ?= docker compose
MOCKERY_VERSION ?= v2.53.8

.DEFAULT_GOAL := help

.PHONY: help up down down-v logs ps build docker-build test test-race test-integration fmt vet tidy mocks migrate clean

help: ## Show available commands
	@awk 'BEGIN {FS = ":.*## "; printf "SecureWallet commands:\n\n"} /^[a-zA-Z_-]+:.*?## / {printf "  %-16s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

up: ## Build images, apply migrations and start the stack
	$(COMPOSE) up --build -d
	@echo "auth-service:   http://localhost:$${AUTH_HTTP_PORT:-8081}"
	@echo "wallet-service: http://localhost:$${WALLET_HTTP_PORT:-8082}"

down: ## Stop containers, keep data
	$(COMPOSE) down

down-v: ## Stop containers and delete Postgres/Redis/notification volumes
	$(COMPOSE) down -v

logs: ## Follow logs from both services
	$(COMPOSE) logs -f auth-service wallet-service

ps: ## Show container status
	$(COMPOSE) ps

build: ## Compile all Go binaries
	$(GO) build ./...

docker-build: ## Build the runtime image without starting services
	$(COMPOSE) build

test: ## Run unit tests
	$(GO) test ./...

test-race: ## Run unit tests with the race detector (requires cgo)
	CGO_ENABLED=1 $(GO) test -race ./...

test-integration: ## Run PostgreSQL ACID tests (TEST_WALLET_DATABASE_URL required)
	@test -n "$$TEST_WALLET_DATABASE_URL" || (echo "TEST_WALLET_DATABASE_URL is required" && exit 1)
	$(GO) test -tags=integration -count=1 -v ./internal/wallet/repository

fmt: ## Format all Go code
	$(GO) fmt ./...

vet: ## Run go vet
	$(GO) vet ./...

tidy: ## Tidy go.mod/go.sum
	$(GO) mod tidy

mocks: ## Regenerate testify mocks (requires network on first run)
	$(GO) run github.com/vektra/mockery/v2@$(MOCKERY_VERSION) --config .mockery.yaml

migrate: ## Apply embedded Goose migrations via the migrator container
	$(COMPOSE) run --rm migrate

clean: ## Remove local build and coverage artifacts
	rm -rf bin coverage.out notifications.log
