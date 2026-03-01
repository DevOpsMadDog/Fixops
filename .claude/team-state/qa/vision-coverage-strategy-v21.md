# Vision-Directed Coverage Strategy — v21

> **Author**: vision-agent (post-flight v21)
> **Date**: 2026-03-01
> **For**: qa-engineer (SPRINT1-008)
> **Purpose**: Break the 17.99% coverage DEEP PLATEAU
> **Pillar**: V10 (CTEM with Crypto Proof — quality gate)

## ROOT CAUSE: WHY 1,873 TESTS ADDED 0pp COVERAGE

The QA agent has been writing tests for **already-covered suite-core files**. 
Three entire suites have **ZERO coverage** and represent **30,695 LOC** (8.7% of the codebase):

| Suite | LOC | Files | Current Coverage | Impact |
|-------|-----|-------|-----------------|--------|
| **suite-evidence-risk** | 19,651 | ~45 | ~0% | +5.6pp at 50% |
| **suite-integrations** | 6,697 | ~32 | ~0% | +1.9pp at 50% |
| **suite-feeds** | 4,347 | ~3 | ~0% | +1.2pp at 50% |
| **TOTAL** | **30,695** | **~80** | **~0%** | **+8.7pp at 50%** |

Getting 50% coverage on these 3 suites alone would push overall coverage from 17.99% to ~26.7%.
This breaks both the plateau AND reaches the revised 25% intermediate target.

## TOP 15 FILES TO TEST (MAXIMUM COVERAGE GAIN)

| # | File | LOC | Suite | Difficulty | Approach |
|---|------|-----|-------|------------|----------|
| 1 | `feeds_service.py` | 3,042 | suite-feeds | Medium | Mock HTTP calls, test each refresh_*() method |
| 2 | `feeds_router.py` | 1,210 | suite-feeds | Easy | FastAPI TestClient, test each endpoint |
| 3 | `webhooks_router.py` | 1,851 | suite-integrations | Easy | FastAPI TestClient, mock webhook payloads |
| 4 | `evidence_router.py` | 1,116 | suite-evidence-risk | Easy | FastAPI TestClient, mock evidence data |
| 5 | `ide_router.py` | 980 | suite-integrations | Easy | FastAPI TestClient |
| 6 | `proprietary_analyzer.py` | 964 | suite-evidence-risk | Medium | Mock code analysis, test reachability |
| 7 | `cloud.py` (runtime) | 864 | suite-evidence-risk | Medium | Mock AWS/Azure/GCP clients |
| 8 | `compliance_engine.py` | 829 | suite-evidence-risk | Medium | Test compliance mapping logic |
| 9 | `analyzer.py` (reachability) | 809 | suite-evidence-risk | Medium | Mock graph traversal |
| 10 | `iast_advanced.py` | 675 | suite-evidence-risk | Hard | Mock instrumentation |
| 11 | `normalizer.py` (lib4sbom) | 640 | suite-integrations | Easy | Pure data transform, no mocks needed |
| 12 | `code_analysis.py` | 553 | suite-evidence-risk | Medium | Mock AST parser |
| 13 | `integrations_router.py` | 525 | suite-integrations | Easy | FastAPI TestClient |
| 14 | `reachability/api.py` | 492 | suite-evidence-risk | Medium | FastAPI TestClient |
| 15 | `git_integration.py` | 486 | suite-evidence-risk | Medium | Mock git operations |

**Total: 14,036 LOC. Getting 50% coverage = +7,018 covered lines = ~4pp gain immediately.**

## RECOMMENDED TEST STRUCTURE

```python
# tests/test_feeds_service_unit.py
"""Test suite-feeds/feeds_service.py — 3,042 LOC, currently 0% covered"""
import pytest
from unittest.mock import AsyncMock, patch, MagicMock

# Import the module under test
from feeds_service import FeedsService

class TestFeedsServiceRefresh:
    """Test each refresh_*() method with mocked HTTP"""
    
    @pytest.mark.asyncio
    async def test_refresh_nvd(self):
        service = FeedsService()
        with patch('feeds_service.httpx.AsyncClient') as mock_client:
            mock_client.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.return_value.__aexit__ = AsyncMock(return_value=False)
            mock_client.get = AsyncMock(return_value=MagicMock(status_code=200, json=lambda: {"vulnerabilities": []}))
            result = await service.refresh_nvd()
            assert result is not None

# tests/test_webhooks_router_unit.py  
"""Test suite-integrations/api/webhooks_router.py — 1,851 LOC, currently 0% covered"""
from fastapi.testclient import TestClient
# ... test each webhook endpoint
```

## CRITICAL INSTRUCTIONS FOR QA AGENT

1. **STOP writing tests for suite-core** — it's already covered. New tests there yield 0pp gain.
2. **TARGET these 3 suites**: suite-evidence-risk, suite-feeds, suite-integrations
3. **Use `pytest --cov-report=term-missing`** to verify your new tests actually cover new lines
4. **After each batch of tests**, check: did the coverage number actually increase?
5. **Router tests are easiest**: FastAPI TestClient, mock dependencies, test HTTP status codes
6. **Goal**: Break 20% first, then push to 25%, then aim for 40% CI gate

## EXPECTED OUTCOME

| Milestone | Target Coverage | Tests Needed | Timeline |
|-----------|----------------|-------------|----------|
| Break plateau | 20% | ~100 new tests in uncovered suites | 2 days |
| Intermediate | 25% | ~300 total in uncovered suites | 5 days |
| CI gate pass | 40% | ~800 total across all suites | Sprint 2 |
| North star | 80% | ~2000+ total | Sprint 3+ |
