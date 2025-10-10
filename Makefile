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
        $(PYTHON_BIN) scripts/run_demo_steps.py --app "life-claims-portal"

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
