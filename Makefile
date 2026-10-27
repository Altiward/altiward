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

.PHONY: help test lint changelog-check agent-build agent-test backend-build backend-test test-db docker-check go-check node-check db db-down demo demo-down run-api run-api-console notices notices-check image test-upgrade azure-template dev-hook dev-heartbeat package package-verify app-icon console-install console-dev console-test console-build console-seed docs-screenshots site-screenshots brand-sync brand-check

help: ## List targets
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-16s %s\n", $$1, $$2}'

test: agent-test backend-test console-test ## Run all unit tests (no database needed)

lint: go-check changelog-check ## gofmt + go vet, and the changelog fragments
	@test -z "$$(gofmt -l backend integrations deploy/sentinel deploy/intune deploy/mdm)" || (gofmt -l backend integrations deploy/sentinel deploy/intune deploy/mdm; echo "run gofmt -w"; exit 1)
	go vet ./...
	cd integrations && go vet ./...

changelog-check: ## Check the fragments in changelog.d/, and test scripts/changelog.sh
	scripts/changelog.sh check
	scripts/test-changelog.sh

agent-build: ## Build altiward-agent and altiward-hook (debug)
	swift build $(SWIFT_FLAGS)

agent-test: ## Run the Swift agent tests
	swift test $(SWIFT_FLAGS)

backend-build: go-check ## Build bin/altiward-api
	go build -o bin/altiward-api ./backend/cmd/altiward-api

backend-test: go-check ## Run Go tests (store tests against Postgres are skipped)
	go test ./...
	cd integrations && go test ./...

test-db: go-check db ## Run Go tests including the Postgres store suite
	ALTIWARD_TEST_DATABASE_URL="$(DATABASE_URL)" go test -count=1 ./...
	cd integrations && go test -count=1 ./...

# Docker Engine without the Compose v2 plugin fails on `docker compose -f` with
# "unknown shorthand flag", which doesn't say what's missing.
docker-check:
	@command -v docker >/dev/null || { echo "Docker isn't installed: see https://docs.docker.com/get-started/get-docker/" >&2; exit 1; }
	@docker compose version >/dev/null 2>&1 || { echo "Docker Compose v2 isn't installed: install Docker Desktop, or the docker-compose-plugin package (https://docs.docker.com/compose/install/linux/)" >&2; exit 1; }

# Go 1.21+ fetches the Go release go.mod names by itself. Older Go, such as Ubuntu 22.04's
# 1.18, stops on go.mod's syntax without saying it's too old.
go-check:
	@command -v go >/dev/null || { echo "Go isn't installed: Altiward needs Go 1.27 (https://go.dev/doc/install)" >&2; exit 1; }
	@v=$$(GOTOOLCHAIN=local go version | awk '{print $$3}'); \
	if [ "$$(echo $$v | cut -d. -f2)" -lt 21 ] 2>/dev/null; then echo "Go $${v#go} is too old: Altiward needs Go 1.27 (https://go.dev/doc/install)" >&2; exit 1; fi

# Older Node, such as Ubuntu 24.04's 18, installs the console with only warnings, then
# fails inside Vite with a SyntaxError that doesn't mention Node. 22.12 is Vite's minimum.
node-check:
	@command -v node >/dev/null || { echo "Node isn't installed: the console needs Node 22.12+ (https://nodejs.org/en/download)" >&2; exit 1; }
	@node -e 'const [major, minor] = process.versions.node.split(".").map(Number); process.exit(major > 22 || (major === 22 && minor >= 12) ? 0 : 1)' || \
	{ echo "Node $$(node --version) is too old: the console needs Node 22.12+ (https://nodejs.org/en/download)" >&2; exit 1; }

db: docker-check ## Start local Postgres (docker compose)
	docker compose -f dev/compose.yaml up -d --wait postgres

db-down: ## Stop local Postgres
	docker compose -f dev/compose.yaml down

demo: docker-check ## Run the console with demo data on :8080, needing only Docker
	docker compose -f dev/compose.demo.yaml up --build

demo-down: ## Stop the demo and delete its data
	docker compose -f dev/compose.demo.yaml down -v

run-api: go-check db ## Run the API on :8080 against local Postgres with dev tokens
	$(DEV_ENV) go run ./backend/cmd/altiward-api

run-api-console: go-check db console-build ## Run the API on :8080 serving the built console, as in production
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

# The Bicep compiler stamps its version into azuredeploy.json, so CI and everyone who
# rebuilds it use this one: az bicep install --version v$(BICEP_VERSION)
BICEP_VERSION := 0.48.1

azure-template: ## Compile main.bicep and intune-read.bicep (deploy/azure/) into the JSON the Deploy to Azure buttons deploy
	@az bicep version 2>/dev/null | grep -q "Bicep CLI version $(BICEP_VERSION) " || \
		{ echo "needs Bicep $(BICEP_VERSION): az bicep install --version v$(BICEP_VERSION)" >&2; exit 1; }
	az bicep build --file deploy/azure/main.bicep --outfile deploy/azure/azuredeploy.json
	az bicep build --file deploy/azure/intune-read.bicep --outfile deploy/azure/intune-read.json

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

console-install: node-check ## Install console dependencies
	npm --prefix console ci

console-dev: node-check ## Run the console on :5173 against `make run-api`
	npm --prefix console run dev

console-test: node-check ## Type-check and test the console
	npm --prefix console run typecheck
	npm --prefix console test

console-build: node-check ## Build the console into console/dist
	npm --prefix console run build

console-seed: ## Fill `make run-api` with demo Macs, sessions and an enrollment to approve
	node dev/seed.mjs

docs-screenshots: db console-build ## Regenerate the console screenshots in docs/images
	node scripts/docs/screenshots.mjs

# The altiward.com checkout that `make site-screenshots` writes to.
SITE ?= ../altiward.com

site-screenshots: db console-build ## Regenerate altiward.com's console screenshots in SITE, and the README's
	node scripts/docs/site-screenshots.mjs "$(SITE)"
