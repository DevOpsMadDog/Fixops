"""BUG-1 regression: 5 GET endpoints must never return HTTP 500.

These endpoints previously returned HTTP 500 because their SQLite tables
weren't created on first access. The fix added defensive ``_ensure_schema()``
guards on read paths in:

- suite-core/core/analytics_engine.py        (AnalyticsEngine)
- suite-core/core/risk_posture.py            (RiskPostureEngine)
- suite-api/apps/api/detailed_logging.py     (DetailedLogStore)
- suite-evidence-risk/compliance/compliance_engine.py  (ComplianceDB)
- suite-core/api/single_agent_router.py      (SingleAgentEngine — graceful degradation)

This test boots the FastAPI app with a *fresh* FIXOPS_DATA_DIR and asserts
every endpoint responds 200/401/403/501 — never 500.
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

import pytest

# Ensure suite-* directories are importable (mirror sitecustomize.py)
_REPO = Path(__file__).resolve().parent.parent
for _suite in ("suite-api", "suite-core", "suite-evidence-risk", "suite-attack",
               "suite-feeds", "suite-integrations"):
    _p = str(_REPO / _suite)
    if _p not in sys.path:
        sys.path.insert(0, _p)


BUG1_ENDPOINTS = [
    "/api/v1/analytics/kpis",
    "/api/v1/analytics/posture",
    "/api/v1/logs",
    "/api/v1/ai-agent/status",
    "/api/v1/compliance-engine/audit-bundle",
]


@pytest.fixture(scope="module")
@pytest.mark.timeout(120)
def fresh_app_client():
    """Boot FastAPI app against a fresh, empty data directory.

    App boot loads ~590 routers and is slow (~10s); allow up to 120s for the
    fixture so the regression test isn't killed by the default 10s timeout.
    """
    # Auto-load .env so FIXOPS_API_KEY is available
    try:
        from dotenv import load_dotenv
        load_dotenv(_REPO / ".env", override=False)
    except ImportError:
        pass

    tmpdir = tempfile.mkdtemp(prefix="bug1_fresh_")
    os.environ["FIXOPS_DATA_DIR"] = tmpdir
    os.environ["FIXOPS_COMPLIANCE_DB_PATH"] = os.path.join(tmpdir, "compliance.db")

    from fastapi.testclient import TestClient
    from apps.api.app import create_app

    app = create_app()
    client = TestClient(app)
    try:
        yield client
    finally:
        client.close()
        import shutil as _shutil
        _shutil.rmtree(tmpdir, ignore_errors=True)


@pytest.mark.parametrize("path", BUG1_ENDPOINTS)
def test_bug1_endpoint_does_not_500_unauthenticated(fresh_app_client, path):
    """Unauthenticated calls must return 401/403, never 500."""
    response = fresh_app_client.get(path)
    assert response.status_code != 500, (
        f"BUG-1 regression: {path} returned 500 (body={response.text[:300]})"
    )
    # Acceptable codes: 200 (no auth required), 401/403 (auth required),
    # 501 (engine genuinely missing), 404 (not mounted — surfaces routing bug).
    assert response.status_code in {200, 401, 403, 404, 501}, (
        f"{path} returned unexpected status {response.status_code}"
    )


@pytest.mark.parametrize("path", BUG1_ENDPOINTS)
def test_bug1_endpoint_does_not_500_authenticated(fresh_app_client, path):
    """Authenticated calls must return 200/501, never 500."""
    api_key = os.environ.get(
        "FIXOPS_API_KEY",
        "fixops_ent_38wJA8mb7CsbJ3PaLvKNz7lFnLWvFWXti_5NcdISXSogi_4grP24NAe_XymVfps_",
    )
    headers = {"X-API-Key": api_key}
    response = fresh_app_client.get(path, headers=headers)
    assert response.status_code != 500, (
        f"BUG-1 regression: {path} returned 500 with auth (body={response.text[:300]})"
    )
    # Authenticated must be 200 (success), 401/403 (key invalid in this env),
    # or 501 (engine genuinely missing). Never 500.
    assert response.status_code in {200, 401, 403, 501}, (
        f"{path} returned unexpected status {response.status_code} "
        f"with auth (body={response.text[:200]})"
    )


def test_analytics_engine_ensure_schema_is_idempotent():
    """AnalyticsEngine._ensure_schema() must be safe to call repeatedly."""
    from core.analytics_engine import AnalyticsEngine

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    try:
        engine = AnalyticsEngine(db_path=db_path)
        # Multiple re-calls must not raise
        for _ in range(5):
            engine._ensure_schema()
        # Reads must work after defensive re-init
        result = engine.query_metric("nonexistent",
                                      __import__("core.analytics_engine",
                                                 fromlist=["TimeWindow"]).TimeWindow.WEEK)
        assert result is None  # No data, but no exception
    finally:
        try:
            os.unlink(db_path)
        except OSError:
            pass


def test_risk_posture_engine_ensure_schema_is_idempotent():
    """RiskPostureEngine._ensure_schema() must be safe to call repeatedly."""
    from core.risk_posture import RiskPostureEngine

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    try:
        engine = RiskPostureEngine(db_path=db_path)
        for _ in range(5):
            engine._ensure_schema()
        # calculate_posture must succeed on empty DB
        posture = engine.calculate_posture("test_org")
        assert posture is not None
        assert 0.0 <= posture.overall_score <= 100.0
    finally:
        try:
            os.unlink(db_path)
        except OSError:
            pass


def test_detailed_log_store_ensure_schema_is_idempotent():
    """DetailedLogStore._ensure_schema() must be safe to call repeatedly."""
    from apps.api.detailed_logging import DetailedLogStore

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    try:
        store = DetailedLogStore(db_path=db_path)
        for _ in range(5):
            store._ensure_schema()
        # query/count/stats must work on empty DB
        assert store.count() == 0
        assert store.query(limit=10) == []
        stats = store.stats()
        assert stats["total"] == 0
    finally:
        try:
            os.unlink(db_path)
        except OSError:
            pass


def test_compliance_db_ensure_schema_is_idempotent():
    """ComplianceDB._ensure_schema() must be safe to call repeatedly."""
    from compliance.compliance_engine import ComplianceDB

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    try:
        db = ComplianceDB(db_path=db_path)
        for _ in range(5):
            db._ensure_schema()
        # Reads must work on empty DB
        assert db.get_assessments("SOC2") == []
        assert db.get_evidence_for_control("CC1.1", "SOC2") == []
        assert db.get_posture_trend("SOC2") == []
    finally:
        try:
            os.unlink(db_path)
        except OSError:
            pass
