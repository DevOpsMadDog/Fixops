PYTHON ?= python3
VENV ?= .venv
PIP := $(VENV)/bin/pip
PYTHON_BIN := $(VENV)/bin/python

.DEFAULT_GOAL := help

.PHONY: help
help:
	@echo "Available targets:"
	@echo "  make bootstrap   Create a local virtual environment and install dependencies"
	@echo "  make dev          Install application and development dependencies"
	@echo "  make fmt          Run code formatters (ruff format)"
	@echo "  make lint         Run linters (ruff check)"
	@echo "  make typecheck    Run static type checks (mypy)"
	@echo "  make test         Run the pytest suite"
	@echo "  make demo         Execute the bundled FixOps demo pipeline"
	@echo "  make demo-enterprise Run the enterprise overlay demo"
	@echo "  make clean        Remove cached artefacts and the virtual environment"

$(VENV):
	$(PYTHON) -m venv $(VENV)
	$(PIP) install --upgrade pip

.PHONY: bootstrap
bootstrap: $(VENV)
	$(PIP) install --upgrade pip wheel
	$(PIP) install -r requirements.txt
	$(PIP) install -r backend/requirements.txt
	@if [ -f fixops-blended-enterprise/requirements.txt ]; then \
		$(PIP) install -r fixops-blended-enterprise/requirements.txt; \
	fi
	@if [ -f requirements.dev.txt ]; then \
		$(PIP) install -r requirements.dev.txt; \
	fi
	@echo "Virtual environment initialised in $(VENV). Activate with: source $(VENV)/bin/activate"

.PHONY: dev
dev: bootstrap
	@echo "Development environment ready."

.PHONY: fmt
fmt: $(VENV)
	$(PYTHON_BIN) -m ruff format .

.PHONY: lint
lint: $(VENV)
	$(PYTHON_BIN) -m ruff check .

.PHONY: typecheck
typecheck: $(VENV)
	$(PYTHON_BIN) -m mypy fixops backend tests

.PHONY: test
test: $(VENV)
	$(PYTHON_BIN) -m pytest -q

.PHONY: demo
demo: $(VENV)
	$(PYTHON_BIN) -m fixops.cli demo --mode demo --pretty

.PHONY: demo-enterprise
demo-enterprise: $(VENV)
	$(PYTHON_BIN) -m fixops.cli demo --mode enterprise --pretty

.PHONY: clean
clean:
	rm -rf $(VENV)
	rm -rf .mypy_cache .ruff_cache .pytest_cache
	find . -type d -name '__pycache__' -prune -exec rm -rf {} +
