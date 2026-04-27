PYTHON ?= python3
VENV ?= .venv
PIP := $(VENV)/bin/pip
PYTHON_BIN := $(VENV)/bin/python

.DEFAULT_GOAL := help

.PHONY: help
help:
	@echo "Available targets:"
	@echo "  make bootstrap      Create a local virtual environment and install dependencies"
	@echo "  make fmt            Run isort and black formatters"
	@echo "  make lint           Run flake8 lint checks"
	@echo "  make test           Run pytest with coverage gate"
	@echo "  make sim            Generate SSDLC simulation artifacts (design & test)"
	@echo "  make demo           Run the ALdeci demo pipeline end-to-end"
	@echo "  make demo-enterprise Run the ALdeci enterprise pipeline with hardened overlay"
	@echo "  make inventory      Rebuild the file usage inventory artefacts"
	@echo "  make clean          Remove cached artefacts and the virtual environment"
	@echo ""
	@echo "MPTE Integration (layer for any compose file):"
	@echo "  make up-mpte              Start ALdeci + MPTE (default compose)"
	@echo "  make up-mpte-enterprise   Start ALdeci Enterprise + MPTE"
	@echo "  make up-mpte-demo         Start ALdeci Demo + MPTE"
	@echo "  make down-mpte            Stop services (use BASE_COMPOSE for variants)"
	@echo "  make logs-mpte            View MPTE container logs"
	@echo ""
	@echo "SCIF / Iron Bank:"
	@echo "  make scif-build           Build SCIF image (RHCC UBI9-minimal, no token needed)"
	@echo "  make scif-build-ironbank  Build SCIF image (Iron Bank UBI9-minimal, requires IRONBANK_TOKEN)"

$(VENV):
	$(PYTHON) -m venv $(VENV)
	$(PIP) install --upgrade pip

.PHONY: bootstrap
bootstrap: $(VENV)
	$(PIP) install --upgrade pip wheel
	$(PIP) install -r requirements.txt
	@if [ -f requirements.dev.txt ]; then \
	$(PIP) install -r requirements.dev.txt; \
	fi
	@if [ -f apps/api/requirements.txt ]; then \
	$(PIP) install -r apps/api/requirements.txt; \
	fi
	@if [ -f enterprise/requirements.txt ]; then \
	$(PIP) install -r enterprise/requirements.txt; \
	fi
	$(PIP) install black isort flake8 pytest-cov
	@echo "Virtual environment initialised in $(VENV). Activate with: source $(VENV)/bin/activate"

.PHONY: fmt
fmt: $(VENV)
	$(PYTHON_BIN) -m isort .
	$(PYTHON_BIN) -m black .

.PHONY: lint
lint: $(VENV)
	$(PYTHON_BIN) -m flake8

.PHONY: test
test: $(VENV)
	$(PYTHON_BIN) -m pytest --cov=fixops-enterprise/src --cov=integrations --cov-branch --cov-fail-under=75

.PHONY: sim
sim: $(VENV)
	$(PYTHON_BIN) simulations/ssdlc/run.py --stage design --out artifacts/design
	$(PYTHON_BIN) simulations/ssdlc/run.py --stage test --out artifacts/test

.PHONY: demo
demo: $(VENV)
	FIXOPS_RUN_ID_SEED=demo-local \
	FIXOPS_TIMESTAMP_OVERRIDE=2024-01-01T00:00:00Z \
	$(PYTHON_BIN) scripts/run_demo_steps.py --mode demo --output artefacts/demo/demo.json

.PHONY: demo-enterprise
demo-enterprise: $(VENV)
	FIXOPS_RUN_ID_SEED=enterprise-local \
	FIXOPS_TIMESTAMP_OVERRIDE=2024-01-01T00:00:00Z \
	$(PYTHON_BIN) scripts/run_demo_steps.py --mode enterprise --output artefacts/enterprise/demo.json

.PHONY: stage-workflow
stage-workflow: $(VENV)
	FIXOPS_RUN_ID_SEED=stage-demo \
	FIXOPS_TIMESTAMP_OVERRIDE=2024-01-01T00:00:00Z \
	$(PYTHON_BIN) scripts/run_stage_workflow.py \
		--artefacts artefacts/stage-demo \
		--summary artefacts/stage-demo/summary.json

.PHONY: inventory
inventory:
	$(PYTHON) scripts/generate_file_usage_inventory.py

.PHONY: clean
clean:
	rm -rf $(VENV)
	rm -rf .mypy_cache .pytest_cache .ruff_cache artifacts coverage.xml htmlcov
	find . -type d -name '__pycache__' -prune -exec rm -rf {} +

# ===================================================================
# Demo System Targets
# ===================================================================

.PHONY: demo-setup demo-feeds demo-cves demo-quick demo-full demo-test demo-all demo-clean

demo-setup:
	@echo "Setting up ALdeci demo environment..."
	@mkdir -p data/feeds data/inputs/{container,cloud,appsec} artifacts reports
	@echo "✓ Demo directories created"

demo-feeds: demo-setup
	@echo "Downloading real security feeds (KEV + EPSS)..."
	@python scripts/fetch_feeds.py
	@echo "✓ Security feeds downloaded"

demo-cves: demo-feeds
	@echo "Generating 50k realistic CVE dataset..."
	@python scripts/generate_realistic_cves.py
	@echo "✓ CVE dataset generated"

demo-quick: demo-cves
	@echo "Running ALdeci quick demo (5k CVEs)..."
	@python scripts/demo_run.py --mode quick --top-n 50
	@echo ""
	@echo "✅ Quick demo complete!"
	@echo "  Report: reports/demo_summary_quick.md"
	@echo "  Evidence: artifacts/evidence_bundle_quick.zip"

demo-full: demo-cves
	@echo "Running ALdeci full demo (50k CVEs)..."
	@python scripts/demo_run.py --mode full --top-n 100
	@echo ""
	@echo "✅ Full demo complete!"
	@echo "  Report: reports/demo_summary_full.md"
	@echo "  Evidence: artifacts/evidence_bundle_full.zip"
	@echo "  Comparison: reports/vs_apiiro_comparison.md"

demo-test:
	@echo "Running demo tests..."
	@python -m pytest tests/test_demo_run.py -v --tb=short
	@echo "✓ All demo tests passed"

demo-all: demo-setup demo-feeds demo-cves demo-full demo-test
	@echo ""
	@echo "✅ Complete ALdeci demo pipeline finished!"
	@echo ""
	@echo "Results:"
	@echo "  - Summary: reports/demo_summary_full.md"
	@echo "  - Evidence: artifacts/evidence_bundle_full.zip"
	@echo "  - vs Apiiro: reports/vs_apiiro_comparison.md"
	@echo "  - Tests: All passing"
	@echo ""
	@echo "🚀 Ready for competitive demo!"

demo-clean:
	@echo "Cleaning demo artifacts..."
	@rm -rf artifacts/* reports/demo_summary_*.md
	@rm -f data/inputs/findings.ndjson data/inputs/findings_stats.json
	@echo "✓ Demo artifacts cleaned (feeds preserved)"

# ===================================================================
# MPTE Integration Targets
# ===================================================================
# MPTE can be added as a layer to ANY docker-compose file:
#   make up-mpte                    # with docker/docker-compose.yml (default)
#   make up-mpte-enterprise         # with docker/docker-compose.enterprise.yml
#   make up-mpte-demo               # with docker/docker-compose.demo.yml
#
# Or use BASE_COMPOSE variable:
#   make up-mpte BASE_COMPOSE=docker/docker-compose.enterprise.yml

BASE_COMPOSE ?= docker/docker-compose.yml
MPTE_COMPOSE := docker/docker-compose.mpte.yml

.PHONY: up-mpte down-mpte logs-mpte
.PHONY: up-mpte-enterprise down-mpte-enterprise
.PHONY: up-mpte-demo down-mpte-demo
.PHONY: up-mpte-deployment down-mpte-deployment

_mpte-env-check:
	@if [ ! -f .env.mpte ]; then \
		echo "Creating .env.mpte from template..."; \
		cp env.mpte.example .env.mpte 2>/dev/null || echo "⚠️  No env.mpte.example found — create .env.mpte manually"; \
		echo "⚠️  Please configure LLM API keys in .env.mpte"; \
	fi

_mpte-start-msg:
	@echo ""
	@echo "✓ ALdeci + MPTE started"
	@echo "  MPTE:       https://localhost:8443 (self-signed SSL)"
	@echo ""
	@echo "To use your fork's image:"
	@echo "  export MPTE_IMAGE=ghcr.io/devopsmaddog/mpte:latest"

up-mpte: _mpte-env-check
	@echo "Starting ALdeci ($(BASE_COMPOSE)) with MPTE integration..."
	docker compose -f $(BASE_COMPOSE) -f $(MPTE_COMPOSE) --env-file .env.mpte up -d
	@$(MAKE) _mpte-start-msg
	@echo "  ALdeci API: http://localhost:8000"

down-mpte:
	@echo "Stopping ALdeci + MPTE..."
	docker compose -f $(BASE_COMPOSE) -f $(MPTE_COMPOSE) down
	@echo "✓ Services stopped"

logs-mpte:
	docker compose -f $(BASE_COMPOSE) -f $(MPTE_COMPOSE) logs -f mpte

up-mpte-enterprise: _mpte-env-check
	@echo "Starting ALdeci Enterprise with MPTE integration..."
	docker compose -f docker/docker-compose.enterprise.yml -f $(MPTE_COMPOSE) --env-file .env.mpte up -d
	@$(MAKE) _mpte-start-msg
	@echo "  ALdeci Enterprise: http://localhost:8000"

down-mpte-enterprise:
	@echo "Stopping ALdeci Enterprise + MPTE..."
	docker compose -f docker/docker-compose.enterprise.yml -f $(MPTE_COMPOSE) down
	@echo "✓ Services stopped"

up-mpte-demo: _mpte-env-check
	@echo "Starting ALdeci Demo with MPTE integration..."
	docker compose -f docker/docker-compose.demo.yml -f $(MPTE_COMPOSE) --env-file .env.mpte up -d
	@$(MAKE) _mpte-start-msg
	@echo "  ALdeci Demo API: http://localhost:8000"
	@echo "  Dashboard:       http://localhost:8080"

down-mpte-demo:
	@echo "Stopping ALdeci Demo + MPTE..."
	docker compose -f docker/docker-compose.demo.yml -f $(MPTE_COMPOSE) down
	@echo "✓ Services stopped"

# ===================================================================
# SCIF / Iron Bank Targets
# ===================================================================

.PHONY: scif-build scif-build-ironbank

## Build the standard SCIF-hardened image (RHCC UBI9-minimal — no CAC needed)
scif-build:
	docker build -f docker/Dockerfile.scif -t aldeci:scif-hardened .

## Build the Iron Bank-based SCIF image (DoD-accredited UBI9-minimal).
## Requires IRONBANK_TOKEN env var (DoD CAC token) and prior registry login:
##   docker login ironbank.dso.mil
## Usage: IRONBANK_TOKEN=<token> make scif-build-ironbank
scif-build-ironbank:
	@if [ -z "$$IRONBANK_TOKEN" ]; then \
		echo ""; \
		echo "ERROR: IRONBANK_TOKEN is not set."; \
		echo ""; \
		echo "To activate Iron Bank build:"; \
		echo "  1. Obtain your DoD CAC token from https://ironbank.dso.mil"; \
		echo "  2. Login: docker login ironbank.dso.mil"; \
		echo "  3. Export: export IRONBANK_TOKEN=<your-token>"; \
		echo "  4. Retry:  make scif-build-ironbank"; \
		echo ""; \
		echo "Fallback (RHCC UBI9-minimal, no token needed): make scif-build"; \
		echo ""; \
		exit 1; \
	fi
	@echo "Iron Bank token present — pulling base image..."
	docker pull ironbank.dso.mil/ironbank/redhat/ubi/ubi9-minimal:latest
	docker build -f docker/Dockerfile.scif.ironbank -t aldeci:scif-hardened-ironbank .
	@echo ""
	@echo "Built: aldeci:scif-hardened-ironbank (Iron Bank UBI9-minimal base)"
