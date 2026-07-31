# Prefer uv when lockfile is present; fall back to project venv / system python.
UV ?= uv
PYTHON ?= $(shell if [ -f "$(CURDIR)/backend/uv.lock" ]; then echo "$(UV) run --frozen python"; elif [ -x "$(CURDIR)/backend/.venv/bin/python" ]; then echo "$(CURDIR)/backend/.venv/bin/python"; else echo python3; fi)

WORKTREE_ID ?= $(shell printf '%s' "$(CURDIR)" | cksum | cut -d ' ' -f 1)
COMPOSE_PROJECT_NAME ?= shadowtrace-$(WORKTREE_ID)
POSTGRES_PORT ?= 5432
REDIS_PORT ?= 6379
BACKEND_PORT ?= 8000
FRONTEND_PORT ?= 3000
MOCK_XDR_PORT ?= 8100

COMPOSE_FILE := $(CURDIR)/infra/docker-compose.yml
COMPOSE := COMPOSE_PROJECT_NAME="$(COMPOSE_PROJECT_NAME)" \
	POSTGRES_PORT="$(POSTGRES_PORT)" REDIS_PORT="$(REDIS_PORT)" \
	BACKEND_PORT="$(BACKEND_PORT)" FRONTEND_PORT="$(FRONTEND_PORT)" \
	MOCK_XDR_PORT="$(MOCK_XDR_PORT)" \
	docker compose --project-name "$(COMPOSE_PROJECT_NAME)" \
	-f "$(COMPOSE_FILE)"

# Optional: set WORKER=1 to include the Celery investigation worker.
WORKER ?=
WORKER_PROFILE = $(if $(WORKER),--profile worker,)

INTEGRATION_PROJECT_NAME ?= $(COMPOSE_PROJECT_NAME)-integration
CI_TEST_PROJECT_NAME ?= $(COMPOSE_PROJECT_NAME)-ci-test
CI_BUILD_PROJECT_PREFIX ?= $(COMPOSE_PROJECT_NAME)-ci-build

# Host-side URLs for tests that talk to Compose postgres/redis from the workstation / CI runner.
CI_DATABASE_URL ?= postgresql+asyncpg://shadowtrace:shadowtrace@localhost:$(POSTGRES_PORT)/shadowtrace
CI_REDIS_URL ?= redis://localhost:$(REDIS_PORT)/0

.PHONY: up down down-v bootstrap smoke-bootstrap test lint fmt migrate migrate-down load-kb integration-test orchestration-test test-tools test-system test-regression update-baseline test-e2e-frontend ci-lint ci-test ci-build update-contracts check-contract-drift evaluation-run evaluation-test

up:
	$(COMPOSE) $(WORKER_PROFILE) up -d --build

down:
	$(COMPOSE) down

# Remove containers AND volumes (ISSUE-088 — full reset).
down-v:
	$(COMPOSE) down -v

# ---------------------------------------------------------------------------
# One-command bootstrap: migrate + seed demo scenarios (ISSUE-088)
#
# Requires core services already healthy (make up first).
# Set LOAD_KB=true to also load knowledge bases (~30-60 s extra).
# ---------------------------------------------------------------------------
bootstrap:
	@LOAD_KB="$(LOAD_KB)" bash "$(CURDIR)/scripts/bootstrap.sh"

smoke-bootstrap:
	@bash "$(CURDIR)/scripts/smoke_bootstrap.sh"

# Apply / roll back the database schema. Override DATABASE_URL to target a host
# (e.g. DATABASE_URL=postgresql+asyncpg://shadowtrace:shadowtrace@localhost:5432/shadowtrace).
migrate:
	cd backend && $(PYTHON) -m alembic upgrade head

migrate-down:
	cd backend && $(PYTHON) -m alembic downgrade base

# --- ISSUE-042 / ISSUE-043 / ISSUE-044 knowledge base loaders -------------- #
load-kb:
	cd backend && $(PYTHON) -m scripts.load_attack_kb
	cd backend && $(PYTHON) -m scripts.load_case_kb
	cd backend && $(PYTHON) -m scripts.load_playbook_kb

test:
	cd backend && $(PYTHON) -m pytest tests/test_infra/test_health.py -v

lint:
	cd backend && $(PYTHON) -m ruff check app tests && $(PYTHON) -m mypy app

fmt:
	cd backend && $(PYTHON) -m ruff check --fix app tests && $(PYTHON) -m ruff format app tests

# --- ISSUE-025 tool-system integration quality gate ---------------------- #
# In-memory Registry/Executor/Mock chains + unit tool tests.
# - Excludes `@pytest.mark.integration` (needs Dockerized Postgres/Redis).
# - Enforces statement coverage >= 80% on app.tools + app.providers.tools.
# - Expected runtime: well under 3 minutes (typically ~30s locally).
# Equivalent:
#   cd backend && pytest tests/test_tools/ tests/integration/test_tool_system.py \
#     -v -m "not integration" --cov=app.tools --cov=app.providers.tools \
#     --cov-fail-under=80
test-tools:
	cd backend && $(PYTHON) -m pytest tests/test_tools/ \
		tests/integration/test_tool_system.py -v -m "not integration" \
		--cov=app.tools --cov=app.providers.tools \
		--cov-report=term-missing --cov-fail-under=80

# --- ISSUE-017 data-foundation integration quality gate ------------------ #
integration-test:
	@set -eu; \
	project="$(INTEGRATION_PROJECT_NAME)"; \
	compose() { \
		COMPOSE_PROJECT_NAME="$$project" \
		POSTGRES_PORT="$(POSTGRES_PORT)" REDIS_PORT="$(REDIS_PORT)" \
		BACKEND_PORT="$(BACKEND_PORT)" FRONTEND_PORT="$(FRONTEND_PORT)" \
		docker compose --project-name "$$project" \
			-f "$(COMPOSE_FILE)" "$$@"; \
	}; \
	cleanup() { \
		status=$$?; \
		trap - EXIT INT TERM; \
		if [ "$$status" -ne 0 ]; then \
			compose ps -a || true; \
			compose logs --no-color postgres redis || true; \
		fi; \
		compose down --volumes --remove-orphans || true; \
		exit "$$status"; \
	}; \
	trap cleanup EXIT INT TERM; \
	compose up -d --wait --wait-timeout 120 postgres redis; \
	cd "$(CURDIR)/backend"; \
	DATABASE_URL="$(CI_DATABASE_URL)" REDIS_URL="$(CI_REDIS_URL)" \
		$(PYTHON) -m pytest tests/integration -m integration -v

# --- ISSUE-055 orchestration integration quality gate -------------------- #
orchestration-test:
	@set -eu; \
	project="$(INTEGRATION_PROJECT_NAME)"; \
	compose() { \
		COMPOSE_PROJECT_NAME="$$project" \
		POSTGRES_PORT="$(POSTGRES_PORT)" REDIS_PORT="$(REDIS_PORT)" \
		BACKEND_PORT="$(BACKEND_PORT)" FRONTEND_PORT="$(FRONTEND_PORT)" \
		docker compose --project-name "$$project" \
			-f "$(COMPOSE_FILE)" "$$@"; \
	}; \
	cleanup() { \
		status=$$?; \
		trap - EXIT INT TERM; \
		if [ "$$status" -ne 0 ]; then \
			compose ps -a || true; \
			compose logs --no-color postgres redis || true; \
		fi; \
		compose down --volumes --remove-orphans || true; \
		exit "$$status"; \
	}; \
	trap cleanup EXIT INT TERM; \
	compose up -d --wait --wait-timeout 120 postgres redis; \
	cd "$(CURDIR)/backend"; \
	DATABASE_URL="$(CI_DATABASE_URL)" REDIS_URL="$(CI_REDIS_URL)" \
		$(PYTHON) -m pytest tests/integration/test_orchestration.py -m orchestration -v \
		--cov=app.orchestration --cov=app.agents.super_agent \
		--cov-report=term-missing --cov-fail-under=75

# --- ISSUE-086 full-system quality gate ----------------------------------- #
test-system:
	@set -eu; \
	project="$(INTEGRATION_PROJECT_NAME)"; \
	compose() { \
		COMPOSE_PROJECT_NAME="$$project" \
		POSTGRES_PORT="$(POSTGRES_PORT)" REDIS_PORT="$(REDIS_PORT)" \
		BACKEND_PORT="$(BACKEND_PORT)" FRONTEND_PORT="$(FRONTEND_PORT)" \
		docker compose --project-name "$$project" \
			-f "$(COMPOSE_FILE)" "$$@"; \
	}; \
	cleanup() { \
		status=$$?; \
		trap - EXIT INT TERM; \
		if [ "$$status" -ne 0 ]; then \
			compose ps -a || true; \
			compose logs --no-color postgres redis || true; \
		fi; \
		compose down --volumes --remove-orphans || true; \
		exit "$$status"; \
	}; \
	trap cleanup EXIT INT TERM; \
	compose up -d --wait --wait-timeout 120 postgres redis; \
	cd "$(CURDIR)/backend"; \
	DATABASE_URL="$(CI_DATABASE_URL)" REDIS_URL="$(CI_REDIS_URL)" \
		$(PYTHON) -m pytest tests/system/ -m system -v --tb=short

# --- ISSUE-087 regression golden-path snapshot gate ----------------------- #
test-regression:
	@set -eu; \
	project="$(INTEGRATION_PROJECT_NAME)"; \
	compose() { \
		COMPOSE_PROJECT_NAME="$$project" \
		POSTGRES_PORT="$(POSTGRES_PORT)" REDIS_PORT="$(REDIS_PORT)" \
		BACKEND_PORT="$(BACKEND_PORT)" FRONTEND_PORT="$(FRONTEND_PORT)" \
		docker compose --project-name "$$project" \
			-f "$(COMPOSE_FILE)" "$$@"; \
	}; \
	cleanup() { \
		status=$$?; \
		trap - EXIT INT TERM; \
		if [ "$$status" -ne 0 ]; then \
			compose ps -a || true; \
			compose logs --no-color postgres redis || true; \
		fi; \
		compose down --volumes --remove-orphans || true; \
		exit "$$status"; \
	}; \
	trap cleanup EXIT INT TERM; \
	compose up -d --wait --wait-timeout 120 postgres redis; \
	cd "$(CURDIR)/backend"; \
	DATABASE_URL="$(CI_DATABASE_URL)" REDIS_URL="$(CI_REDIS_URL)" \
		$(PYTHON) -m pytest tests/regression/ -m regression -v --tb=short

update-baseline:
	@set -eu; \
	project="$(INTEGRATION_PROJECT_NAME)"; \
	compose() { \
		COMPOSE_PROJECT_NAME="$$project" \
		POSTGRES_PORT="$(POSTGRES_PORT)" REDIS_PORT="$(REDIS_PORT)" \
		BACKEND_PORT="$(BACKEND_PORT)" FRONTEND_PORT="$(FRONTEND_PORT)" \
		docker compose --project-name "$$project" \
			-f "$(COMPOSE_FILE)" "$$@"; \
	}; \
	cleanup() { \
		status=$$?; \
		trap - EXIT INT TERM; \
		if [ "$$status" -ne 0 ]; then \
			compose ps -a || true; \
			compose logs --no-color postgres redis || true; \
		fi; \
		compose down --volumes --remove-orphans || true; \
		exit "$$status"; \
	}; \
	trap cleanup EXIT INT TERM; \
	printf 'This will overwrite all regression baselines under backend/tests/regression/baseline/.\n'; \
	printf 'Type ISSUE-087 to confirm: '; \
	read confirm; \
	if [ "$$confirm" != "ISSUE-087" ]; then \
		echo "Aborted baseline refresh (confirmation mismatch)." >&2; \
		exit 1; \
	fi; \
	compose up -d --wait --wait-timeout 120 postgres redis; \
	cd "$(CURDIR)/backend"; \
	DATABASE_URL="$(CI_DATABASE_URL)" REDIS_URL="$(CI_REDIS_URL)" \
		UPDATE_BASELINE=1 UPDATE_BASELINE_CONFIRM=ISSUE-087 $(PYTHON) -m scripts.update_regression_baseline

# --- ISSUE-077 frontend Playwright e2e (optional; does not block P0 CI) --- #
# Requires a healthy Compose stack (postgres/redis/backend/frontend).
# Usage: docker compose up -d && make test-e2e-frontend
# Backend container entrypoint applies alembic on boot.
E2E_FRONTEND_URL ?= http://127.0.0.1:$(FRONTEND_PORT)
E2E_BACKEND_URL ?= http://127.0.0.1:$(BACKEND_PORT)/api/v1
E2E_AUTH_TOKEN ?= e2e-token

test-e2e-frontend:
	@set -eu; \
	echo "Checking frontend health at $(E2E_FRONTEND_URL)/health …"; \
	curl --fail --show-error --silent "$(E2E_FRONTEND_URL)/health" >/dev/null; \
	echo "Checking backend health at $(E2E_BACKEND_URL)/health …"; \
	curl --fail --show-error --silent "$(E2E_BACKEND_URL)/health" >/dev/null; \
	cd "$(CURDIR)/frontend"; \
	(corepack enable && corepack prepare pnpm@9.15.9 --activate || true); \
	pnpm install --frozen-lockfile; \
	pnpm exec playwright install chromium; \
	E2E_FRONTEND_URL="$(E2E_FRONTEND_URL)" \
	E2E_BACKEND_URL="$(E2E_BACKEND_URL)" \
	E2E_AUTH_TOKEN="$(E2E_AUTH_TOKEN)" \
		pnpm test:e2e

# --- ISSUE-112 contract drift / frozen export -------------------------------- #
update-contracts:
	cd backend && $(UV) run --frozen python ../scripts/export_contracts.py

check-contract-drift:
	cd backend && $(UV) run --frozen python ../scripts/check_contract_drift.py

# --- ISSUE-105 evaluation pipeline (artifact-only; mock-only replay) ---------- #
evaluation-run:
	@set -eu; \
	project="$(INTEGRATION_PROJECT_NAME)"; \
	compose() { \
		COMPOSE_PROJECT_NAME="$$project" \
		POSTGRES_PORT="$(POSTGRES_PORT)" REDIS_PORT="$(REDIS_PORT)" \
		BACKEND_PORT="$(BACKEND_PORT)" FRONTEND_PORT="$(FRONTEND_PORT)" \
		docker compose --project-name "$$project" \
			-f "$(COMPOSE_FILE)" "$$@"; \
	}; \
	cleanup() { \
		status=$$?; \
		trap - EXIT INT TERM; \
		compose down --volumes --remove-orphans || true; \
		exit "$$status"; \
	}; \
	trap cleanup EXIT INT TERM; \
	compose up -d --wait --wait-timeout 120 postgres; \
	cd "$(CURDIR)/backend"; \
	DATABASE_URL="$(CI_DATABASE_URL)" $(PYTHON) -m alembic upgrade head; \
	DATABASE_URL="$(CI_DATABASE_URL)" $(PYTHON) -m scripts.run_evaluation \
		--output "$(CURDIR)/artifacts/evaluation/latest_run.json" \
		--code-sha "$$(git -C "$(CURDIR)" rev-parse HEAD)" \
		--seed 42 \
		--threshold-manifest "$(CURDIR)/data/evaluation/shadowtrace_demo_v1/threshold_manifest.json" \
		--compare-baseline "$(CURDIR)/data/evaluation/shadowtrace_demo_v1/baseline_artifact.json"

evaluation-test:
	@set -eu; \
	project="$(INTEGRATION_PROJECT_NAME)"; \
	compose() { \
		COMPOSE_PROJECT_NAME="$$project" \
		POSTGRES_PORT="$(POSTGRES_PORT)" REDIS_PORT="$(REDIS_PORT)" \
		BACKEND_PORT="$(BACKEND_PORT)" FRONTEND_PORT="$(FRONTEND_PORT)" \
		docker compose --project-name "$$project" \
			-f "$(COMPOSE_FILE)" "$$@"; \
	}; \
	cleanup() { \
		status=$$?; \
		trap - EXIT INT TERM; \
		if [ "$$status" -ne 0 ]; then \
			compose ps -a || true; \
			compose logs --no-color postgres || true; \
		fi; \
		compose down --volumes --remove-orphans || true; \
		exit "$$status"; \
	}; \
	trap cleanup EXIT INT TERM; \
	compose up -d --wait --wait-timeout 120 postgres; \
	cd "$(CURDIR)/backend"; \
	DATABASE_URL="$(CI_DATABASE_URL)" $(PYTHON) -m alembic upgrade head; \
	DATABASE_URL="$(CI_DATABASE_URL)" \
		$(PYTHON) -m pytest tests/evaluation/ -m evaluation -v --tb=short

# --- ISSUE-009 local / CI parity gates ------------------------------------ #
ci-lint:
	cd backend && $(UV) sync --frozen --extra dev
	cd backend && $(UV) run --frozen ruff check app tests
	cd backend && $(UV) run --frozen ruff format --check app tests
	cd backend && $(UV) run --frozen mypy app
	cd frontend && (corepack enable && corepack prepare pnpm@9.15.9 --activate || true)
	cd frontend && pnpm install --frozen-lockfile
	cd frontend && pnpm lint
	cd frontend && pnpm typecheck

ci-test:
	cd backend && $(UV) sync --frozen --extra dev
	@set -eu; \
	project="$(CI_TEST_PROJECT_NAME)"; \
	compose() { \
		COMPOSE_PROJECT_NAME="$$project" \
		POSTGRES_PORT="$(POSTGRES_PORT)" REDIS_PORT="$(REDIS_PORT)" \
		BACKEND_PORT="$(BACKEND_PORT)" FRONTEND_PORT="$(FRONTEND_PORT)" \
		docker compose --project-name "$$project" \
			-f "$(COMPOSE_FILE)" "$$@"; \
	}; \
	cleanup() { \
		status=$$?; \
		trap - EXIT INT TERM; \
		if [ "$$status" -ne 0 ]; then \
			compose ps -a || true; \
			compose logs --no-color postgres redis || true; \
		fi; \
		compose down --volumes --remove-orphans || true; \
		exit "$$status"; \
	}; \
	trap cleanup EXIT INT TERM; \
	compose up -d --wait --wait-timeout 120 postgres redis; \
	cd "$(CURDIR)/backend"; \
	DATABASE_URL="$(CI_DATABASE_URL)" REDIS_URL="$(CI_REDIS_URL)" \
		$(UV) run --frozen pytest --cov=app --cov-report=term --cov-report=xml:coverage.xml

ci-build:
	cd frontend && (corepack enable && corepack prepare pnpm@9.15.9 --activate || true)
	cd frontend && pnpm install --frozen-lockfile
	cd frontend && pnpm build
	@set -e; \
	project="$(CI_BUILD_PROJECT_PREFIX)-$$(date +%s)-$$$$"; \
	compose() { \
		COMPOSE_PROJECT_NAME="$$project" \
		POSTGRES_PORT="$(POSTGRES_PORT)" REDIS_PORT="$(REDIS_PORT)" \
		BACKEND_PORT="$(BACKEND_PORT)" FRONTEND_PORT="$(FRONTEND_PORT)" \
		docker compose --project-name "$$project" \
			-f "$(COMPOSE_FILE)" "$$@"; \
	}; \
	cleanup() { \
		status=$$?; \
		trap - EXIT INT TERM; \
		if [ "$$status" -ne 0 ]; then \
			compose ps -a || true; \
			compose logs --no-color postgres redis backend frontend || true; \
		fi; \
		compose down --volumes --remove-orphans || true; \
		exit "$$status"; \
	}; \
	trap cleanup EXIT INT TERM; \
	compose build; \
	compose up -d --wait --wait-timeout 180; \
	for service in postgres redis mock-xdr backend frontend; do \
		container_id=$$(compose ps -q "$$service"); \
		if [ -z "$$container_id" ]; then \
			echo "$$service container is missing"; \
			exit 1; \
		fi; \
		health=$$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}missing{{end}}' "$$container_id"); \
		if [ "$$health" != "healthy" ]; then \
			echo "$$service is not healthy: $$health"; \
			exit 1; \
		fi; \
	done; \
	compose ps; \
	curl --fail --show-error --silent \
		"http://127.0.0.1:$(BACKEND_PORT)/api/v1/health" >/dev/null; \
	curl --fail --show-error --silent \
		"http://127.0.0.1:$(FRONTEND_PORT)/health" >/dev/null; \
	curl --fail --show-error --silent \
		"http://127.0.0.1:$(MOCK_XDR_PORT)/mock-xdr/v1/health" >/dev/null
