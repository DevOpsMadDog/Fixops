# Skill: Testing Patterns — Coverage Growth & Collection Error Fixes

> How to write tests, fix collection errors, and grow coverage from 19% to 50%+.

## Current State (2026-03-17)
- 18,065 tests collected, 9 collection errors
- 19.19% coverage (gate: 25%, FAILING)
- 386 test files in `tests/`
- `pytest-timeout`: 10s per test

## Running Tests

```bash
# Full suite (quick):
python -m pytest tests/ --timeout=10 -x -q

# With coverage:
python -m pytest tests/ --cov=suite-api --cov=suite-core --cov=suite-attack --cov=suite-feeds --cov=suite-evidence-risk --cov=suite-integrations --cov-report=term --timeout=10

# Single file:
python -m pytest tests/test_brain_pipeline.py -v --timeout=10

# Pattern match:
python -m pytest -k "test_integrations" -v --timeout=10

# Collect only (check for errors):
python -m pytest tests/ --collect-only -q 2>&1 | tail -20
```

## Fixing Test Collection Errors

Collection errors happen when Python can't import a test file. Common causes:

### 1. Missing import (most common)
```bash
# Find the specific error:
python -m pytest tests/test_broken.py --collect-only 2>&1

# Typical output:
# ImportError: cannot import name 'SomeClass' from 'core.some_module'
```

Fix: Either the class was renamed/moved, or the module has a syntax error.

```bash
# Check if the import target exists:
grep -rn "class SomeClass" suite-core/ --include="*.py" | head -5

# If renamed, update the test import:
sed -i '' 's/from core.some_module import SomeClass/from core.some_module import NewClassName/' tests/test_broken.py
```

### 2. Circular import
```bash
# Symptom: ImportError with circular reference
# Fix: Move the import inside the test function
def test_something():
    from core.heavy_module import HeavyClass  # Lazy import
    ...
```

### 3. Missing dependency
```bash
# Symptom: ModuleNotFoundError
pip install missing-package
# Or add to requirements.txt and requirements-test.txt
```

### 4. sitecustomize.py not loaded
```bash
# Ensure PYTHONPATH includes project root:
export PYTHONPATH="/Users/devops.ai/developement/fixops/Fixops:$PYTHONPATH"

# Verify sitecustomize.py runs:
python -c "import sys; print([p for p in sys.path if 'suite-' in p])"
```

## Test Patterns by Type

### Unit Test — Service/Engine Logic
```python
"""Tests for brain_pipeline decision scoring."""
import pytest
from unittest.mock import AsyncMock, patch
from core.brain_pipeline import BrainPipeline


class TestBrainPipelineScoring:
    """Pipeline scoring tests."""

    def setup_method(self):
        self.pipeline = BrainPipeline()

    def test_critical_severity_scores_highest(self):
        finding = {"severity": "critical", "cvss": 9.8, "exploitable": True}
        score = self.pipeline._calculate_risk_score(finding)
        assert score >= 90

    def test_info_severity_scores_lowest(self):
        finding = {"severity": "info", "cvss": 0.0, "exploitable": False}
        score = self.pipeline._calculate_risk_score(finding)
        assert score < 20

    @pytest.mark.asyncio
    async def test_pipeline_deduplicates_same_cve(self):
        findings = [
            {"cve": "CVE-2024-1234", "scanner": "snyk"},
            {"cve": "CVE-2024-1234", "scanner": "trivy"},
        ]
        result = await self.pipeline.process(findings)
        assert len(result) == 1  # Deduplicated
```

### Integration Test — API Endpoint
```python
"""Tests for findings API endpoints."""
import pytest
from fastapi.testclient import TestClient
from apps.api.app import create_app


@pytest.fixture
def client():
    app = create_app()
    return TestClient(app)


@pytest.fixture
def auth_headers():
    return {"X-API-Key": "test-api-key-for-unit-tests"}


class TestFindingsAPI:
    """Findings endpoint integration tests."""

    def test_list_findings_requires_auth(self, client):
        response = client.get("/api/v1/findings")
        assert response.status_code in (401, 403)

    def test_list_findings_returns_200(self, client, auth_headers):
        response = client.get("/api/v1/findings", headers=auth_headers)
        assert response.status_code == 200
        assert isinstance(response.json(), (list, dict))

    def test_create_finding_validates_severity(self, client, auth_headers):
        response = client.post(
            "/api/v1/findings",
            json={"title": "Test", "severity": "INVALID"},
            headers=auth_headers,
        )
        assert response.status_code == 422  # Validation error

    def test_get_finding_not_found(self, client, auth_headers):
        response = client.get("/api/v1/findings/nonexistent-id", headers=auth_headers)
        assert response.status_code == 404
```

### Tenant Isolation Test (CRITICAL)
```python
"""Tests that verify tenant data isolation."""
import pytest


class TestTenantIsolation:
    """Every multi-tenant endpoint MUST have these tests."""

    def test_org_a_cannot_see_org_b_findings(self, client):
        # Create finding as org_a
        headers_a = {"X-API-Key": "org-a-key", "X-Org-Id": "org_a"}
        client.post("/api/v1/findings", json={"title": "Secret"}, headers=headers_a)

        # List findings as org_b
        headers_b = {"X-API-Key": "org-b-key", "X-Org-Id": "org_b"}
        response = client.get("/api/v1/findings", headers=headers_b)

        # org_b must NOT see org_a's finding
        findings = response.json()
        for f in findings if isinstance(findings, list) else findings.get("items", []):
            assert f.get("org_id") != "org_a"

    def test_org_a_cannot_delete_org_b_finding(self, client):
        headers_a = {"X-API-Key": "org-a-key", "X-Org-Id": "org_a"}
        response = client.delete("/api/v1/findings/org-b-finding-id", headers=headers_a)
        assert response.status_code in (403, 404)  # Either forbidden or "not found" (because filtered)
```

### Security Test
```python
"""Security-focused tests."""
import pytest


class TestSQLInjection:
    """Verify parameterized queries prevent injection."""

    @pytest.mark.parametrize("payload", [
        "'; DROP TABLE findings; --",
        "1 OR 1=1",
        "1; SELECT * FROM users",
        "' UNION SELECT password FROM users --",
    ])
    def test_finding_id_injection(self, client, auth_headers, payload):
        response = client.get(f"/api/v1/findings/{payload}", headers=auth_headers)
        # Should return 404 or 422, NOT 500
        assert response.status_code in (404, 422, 400)


class TestXSS:
    """Verify output encoding prevents XSS."""

    def test_finding_title_xss(self, client, auth_headers):
        response = client.post(
            "/api/v1/findings",
            json={"title": "<script>alert('xss')</script>", "severity": "low"},
            headers=auth_headers,
        )
        if response.status_code == 201:
            data = response.json()
            assert "<script>" not in data.get("title", "")
```

## Coverage Growth Strategy

### Phase 1: Fix Collection Errors (quick win)
```bash
# Get exact list of errors:
python -m pytest tests/ --collect-only -q 2>&1 | grep "ERROR"
# Fix each one (usually import issues) — target: 0 errors
```

### Phase 2: Cover Top 20 Files by LOC (biggest impact)
```bash
# Find largest untested files:
find suite-core/core/ suite-api/apps/api/ -name "*.py" -exec wc -l {} + | sort -rn | head -20
# Write tests for any file above 500 LOC that lacks a test_ counterpart
```

### Phase 3: Cover All Router Files (visible surface)
```bash
# Find routers without tests:
for router in $(find suite-api/apps/api/ suite-core/api/ -name "*_router.py"); do
    base=$(basename "$router" .py)
    test_file="tests/test_${base}.py"
    if [ ! -f "$test_file" ]; then
        echo "MISSING: $test_file for $router"
    fi
done
```

### Phase 4: Cover Critical Paths (security)
Priority order:
1. Auth flows (login, token validation, API key)
2. Brain pipeline (decision logic)
3. Scanner engines (input handling)
4. AutoFix engine (code generation)
5. Evidence signing (crypto operations)

## conftest.py Patterns

```python
"""tests/conftest.py — shared fixtures for all tests."""
import os
import pytest
from fastapi.testclient import TestClient

# Ensure suite paths are available
os.environ.setdefault("FIXOPS_MODE", "test")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")


@pytest.fixture(scope="session")
def app():
    """Create app once per test session."""
    from apps.api.app import create_app
    return create_app()


@pytest.fixture
def client(app):
    """Fresh test client for each test."""
    return TestClient(app)


@pytest.fixture
def auth_headers():
    """Standard auth headers for testing."""
    return {"X-API-Key": os.environ.get("FIXOPS_API_TOKEN", "test-key")}


@pytest.fixture
def org_headers():
    """Auth headers with org for tenant tests."""
    def _make(org_id: str = "test-org"):
        return {
            "X-API-Key": os.environ.get("FIXOPS_API_TOKEN", "test-key"),
            "X-Org-Id": org_id,
        }
    return _make
```

## Pytest Markers

```python
# In pyproject.toml:
[tool.pytest.ini_options]
markers = [
    "unit: Unit tests (fast, no I/O)",
    "integration: Integration tests (may use DB/network)",
    "e2e: End-to-end tests (full stack)",
    "security: Security-focused tests",
    "slow: Tests taking >5 seconds",
]

# Usage:
@pytest.mark.unit
def test_score_calculation():
    ...

@pytest.mark.integration
def test_api_endpoint():
    ...

# Run only unit tests:
# python -m pytest -m unit
```

## Validation

```bash
# Zero collection errors:
python -m pytest tests/ --collect-only -q 2>&1 | grep "ERROR" | wc -l
# Target: 0

# Coverage above gate:
python -m pytest tests/ --cov=. --cov-report=term --timeout=10 -q 2>&1 | grep "TOTAL"
# Target: >25% (then grow to 50%)

# All tests pass:
python -m pytest tests/ --timeout=10 -q 2>&1 | tail -3
```
