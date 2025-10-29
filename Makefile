PYTHON ?= python3
VENV ?= .venv
PIP := $(VENV)/bin/pip
PYTHON_BIN := $(VENV)/bin/python

.DEFAULT_GOAL := help

.PHONY: help
help:
	@echo "Available targets:"
	@echo "  make bootstrap   Create a local virtual environment and install dependencies"
	@echo "  make fmt          Run isort and black formatters"
	@echo "  make lint         Run flake8 lint checks"
	@echo "  make test         Run pytest with coverage gate"
	@echo "  make sim          Generate SSDLC simulation artifacts (design & test)"
	@echo "  make demo         Run the FixOps demo pipeline end-to-end"
	@echo "  make demo-enterprise Run the FixOps enterprise pipeline with hardened overlay"
	@echo "  make inventory    Rebuild the file usage inventory artefacts"
	@echo "  make clean        Remove cached artefacts and the virtual environment"

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
	FIXOPS_FAKE_NOW=2024-01-01T00:00:00Z \
	$(PYTHON_BIN) scripts/run_demo_steps.py --mode demo --output artefacts/demo/demo.json

.PHONY: demo-enterprise
demo-enterprise: $(VENV)
	FIXOPS_RUN_ID_SEED=enterprise-local \
	FIXOPS_FAKE_NOW=2024-01-01T00:00:00Z \
	$(PYTHON_BIN) scripts/run_demo_steps.py --mode enterprise --output artefacts/enterprise/demo.json

.PHONY: stage-workflow
stage-workflow: $(VENV)
	FIXOPS_RUN_ID_SEED=stage-demo \
	FIXOPS_FAKE_NOW=2024-01-01T00:00:00Z \
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
	@echo "Setting up FixOps demo environment..."
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
	@echo "Running FixOps quick demo (5k CVEs)..."
	@python scripts/demo_run.py --mode quick --top-n 50
	@echo ""
	@echo "✅ Quick demo complete!"
	@echo "  Report: reports/demo_summary_quick.md"
	@echo "  Evidence: artifacts/evidence_bundle_quick.zip"

demo-full: demo-cves
	@echo "Running FixOps full demo (50k CVEs)..."
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
	@echo "✅ Complete FixOps demo pipeline finished!"
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
