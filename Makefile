# Altiward monorepo tasks. Run `make help` for the list.

# Swift build products live outside the repo: on an iCloud-synced folder (~/Documents)
# File Provider tags build output with Finder metadata and codesign then refuses it.
SWIFT_SCRATCH ?= $(HOME)/Library/Caches/altiward/agent-build
SWIFT_FLAGS   := --package-path agent --scratch-path $(SWIFT_SCRATCH)

DATABASE_URL  ?= postgres://altiward:altiward@127.0.0.1:5433/altiward?sslmode=disable

# Development-only tokens for `make run-api`. Never use these anywhere real.
DEV_ENV := ALTIWARD_LISTEN_ADDR=127.0.0.1:8080 \
	ALTIWARD_DATABASE_URL="$(DATABASE_URL)" \
	ALTIWARD_AGENT_TOKENS=dev=dev-agent-token-0001 \
	ALTIWARD_CONSOLE_TOKENS=dev=dev-console-token-001

.PHONY: help test lint agent-build agent-test backend-build backend-test test-db db db-down run-api run-api-console notices notices-check image test-upgrade dev-hook dev-heartbeat package package-verify app-icon console-install console-dev console-test console-build console-seed docs-screenshots brand-sync brand-check

help: ## List targets
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-16s %s\n", $$1, $$2}'

test: agent-test backend-test console-test ## Run all unit tests (no database needed)

lint: ## gofmt + go vet
	@test -z "$$(gofmt -l backend integrations deploy/sentinel)" || (gofmt -l backend integrations deploy/sentinel; echo "run gofmt -w"; exit 1)
	go vet ./...
	cd integrations && go vet ./...

agent-build: ## Build altiward-agent and altiward-hook (debug)
	swift build $(SWIFT_FLAGS)

agent-test: ## Run the Swift agent tests
	swift test $(SWIFT_FLAGS)

backend-build: ## Build bin/altiward-api
	go build -o bin/altiward-api ./backend/cmd/altiward-api

backend-test: ## Run Go tests (store tests against Postgres are skipped)
	go test ./...
	cd integrations && go test ./...

test-db: db ## Run Go tests including the Postgres store suite
	ALTIWARD_TEST_DATABASE_URL="$(DATABASE_URL)" go test -count=1 ./...
	cd integrations && go test -count=1 ./...

db: ## Start local Postgres (docker compose)
	docker compose -f dev/compose.yaml up -d --wait postgres

db-down: ## Stop local Postgres
	docker compose -f dev/compose.yaml down

run-api: db ## Run the API on :8080 against local Postgres with dev tokens
	$(DEV_ENV) go run ./backend/cmd/altiward-api

run-api-console: db console-build ## Run the API on :8080 serving the built console, as in production
	$(DEV_ENV) ALTIWARD_CONSOLE_DIR=console/dist go run ./backend/cmd/altiward-api

notices: ## Regenerate THIRD_PARTY_NOTICES.md after changing Go or console dependencies
	node scripts/third-party-notices.mjs

notices-check: ## Fail if THIRD_PARTY_NOTICES.md is out of date
	node scripts/third-party-notices.mjs --check

image: ## Build the production image: the API serving the console (VERSION=0.1.0 to stamp it)
	docker build --build-arg VERSION=$(or $(VERSION),dev) -t altiward-api:$(or $(VERSION),dev) .

test-upgrade: ## Install a release in Docker and upgrade it with deploy/compose/upgrade.sh
	docker build --build-arg VERSION=upgrade-test -t altiward-api:upgrade-test .
	scripts/test-upgrade.sh altiward-api:upgrade-test

# Drive a local agent against `make run-api`, without launchd or root.
AGENT_ENV := ALTIWARD_DATA_DIR=$(SWIFT_SCRATCH)/dev-agent-data \
	ALTIWARD_SERVER_URL=http://127.0.0.1:8080 \
	ALTIWARD_TOKEN=dev-agent-token-0001

dev-hook: agent-build ## Simulate a Privileges grant: make dev-hook STATE=admin REASON="why"
	$(AGENT_ENV) $$(swift build $(SWIFT_FLAGS) --show-bin-path)/altiward-agent simulate-hook "$$(whoami)" $${STATE:-admin} "$${REASON:-local test}"

dev-heartbeat: agent-build ## Take one admin-group reading and deliver
	$(AGENT_ENV) $$(swift build $(SWIFT_FLAGS) --show-bin-path)/altiward-agent heartbeat

package: ## Build Altiward.app and the .pkg, ad-hoc signed
	agent/packaging/build.sh

package-verify: ## Check the package: layout, signatures, payload, install scripts
	agent/packaging/verify.sh

app-icon: ## Rebuild app icons, Installer backgrounds, avatars and the social preview
	scripts/brand/generate.sh

brand-sync: ## Copy canonical brand assets into the console
	scripts/brand/export.sh console console

brand-check: ## Check the console's brand assets match the canonical sources
	scripts/brand/export.sh console console --check

console-install: ## Install console dependencies
	npm --prefix console ci

console-dev: ## Run the console on :5173 against `make run-api`
	npm --prefix console run dev

console-test: ## Type-check and test the console
	npm --prefix console run typecheck
	npm --prefix console test

console-build: ## Build the console into console/dist
	npm --prefix console run build

console-seed: ## Fill `make run-api` with demo Macs, sessions and an enrollment to approve
	node dev/seed.mjs

docs-screenshots: db console-build ## Regenerate the console screenshots in docs/images
	node scripts/docs/screenshots.mjs
