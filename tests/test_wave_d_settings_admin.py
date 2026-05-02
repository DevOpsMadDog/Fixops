"""Tests for wave_d_integrations_router — settings/admin/policy domain.

Covers 4 previously-501 endpoints:
  1. POST /auto-waiver-rules          (Multica 1f5d8fc9)
  2. POST /policies/{id}/stage-matrix (Multica 61db07fb)
  3. GET  /policies/{id}/stage-matrix (Multica 181dc9f8)
  4. POST /evaluate                   (Multica a0585e59)

Both the engine-wired path and the in-memory fallback are exercised.
"""
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Set auth token before any app import so auth_deps picks it up
os.environ["FIXOPS_API_TOKEN"] = "test-token-settings"

sys.path.insert(0, str(Path(__file__).parent.parent / "suite-api"))
sys.path.insert(0, str(Path(__file__).parent.parent / "suite-core"))

from fastapi import FastAPI
from fastapi.testclient import TestClient

from apps.api.wave_d_integrations_router import (
    _AUTO_WAIVER_RULES,
    _STAGE_MATRIX_STORE,
    router,
)

app = FastAPI()
app.include_router(router)

client = TestClient(app, raise_server_exceptions=True)
HEADERS = {"X-API-Key": "test-token-settings", "X-Org-ID": "test-org"}

VALID_STAGE_MATRIX = {
    "ide": True,
    "pr": True,
    "build": False,
    "deploy": False,
    "runtime": False,
}


# ---------------------------------------------------------------------------
# 1. POST /auto-waiver-rules — engine path
# ---------------------------------------------------------------------------
def test_create_auto_waiver_rule_engine_path():
    mock_eng = MagicMock()
    mock_eng.register_auto_waiver_rule.return_value = {
        "id": "r1",
        "org_id": "test-org",
        "rule_key": "no-reachable-low",
        "conditions": {"reachable": False, "severity_max": "low"},
        "max_active_count": 50,
        "approvers": ["alice"],
        "expires_days": 14,
        "enabled": True,
        "created_at": "2026-05-03T00:00:00+00:00",
    }
    with patch.dict(
        "sys.modules",
        {"core.vuln_exception_engine": MagicMock(VulnExceptionEngine=lambda: mock_eng)},
    ):
        resp = client.post(
            "/api/v1/auto-waiver-rules",
            headers=HEADERS,
            json={
                "rule_key": "no-reachable-low",
                "conditions": {"reachable": False, "severity_max": "low"},
                "max_active_count": 50,
                "approvers": ["alice"],
                "expires_days": 14,
            },
        )
    assert resp.status_code in (200, 201)
    data = resp.json()
    assert "rule_key" in data or "id" in data or "registered" in data


# ---------------------------------------------------------------------------
# 2. POST /auto-waiver-rules — in-memory fallback when engine raises
# ---------------------------------------------------------------------------
def test_create_auto_waiver_rule_fallback():
    _AUTO_WAIVER_RULES.clear()
    mock_eng = MagicMock()
    mock_eng.register_auto_waiver_rule.side_effect = RuntimeError("db locked")
    with patch.dict(
        "sys.modules",
        {"core.vuln_exception_engine": MagicMock(VulnExceptionEngine=lambda: mock_eng)},
    ):
        resp = client.post(
            "/api/v1/auto-waiver-rules",
            headers=HEADERS,
            json={
                "rule_key": "fallback-rule",
                "conditions": {"kev": True},
                "max_active_count": 10,
                "approvers": [],
                "expires_days": 7,
            },
        )
    assert resp.status_code in (200, 201)
    data = resp.json()
    assert data.get("rule_key") == "fallback-rule"
    assert data.get("source") == "in_memory_fallback"


# ---------------------------------------------------------------------------
# 3. POST /policies/{id}/stage-matrix — engine path
# ---------------------------------------------------------------------------
def test_set_stage_matrix_engine_path():
    mock_eng = MagicMock()
    mock_eng.set_stage_matrix.return_value = {
        "id": "pol-1",
        "org_id": "test-org",
        "stage_matrix": VALID_STAGE_MATRIX,
    }
    with patch.dict(
        "sys.modules",
        {"core.policy_enforcement_engine": MagicMock(get_engine=lambda org_id: mock_eng)},
    ):
        resp = client.post(
            "/api/v1/policies/pol-1/stage-matrix",
            headers=HEADERS,
            json={"stage_matrix": VALID_STAGE_MATRIX},
        )
    assert resp.status_code in (200, 201)
    data = resp.json()
    assert "stage_matrix" in data


# ---------------------------------------------------------------------------
# 4. POST /policies/{id}/stage-matrix — in-memory fallback
# ---------------------------------------------------------------------------
def test_set_stage_matrix_fallback():
    _STAGE_MATRIX_STORE.clear()
    mock_eng = MagicMock()
    mock_eng.set_stage_matrix.side_effect = RuntimeError("db error")
    with patch.dict(
        "sys.modules",
        {"core.policy_enforcement_engine": MagicMock(get_engine=lambda org_id: mock_eng)},
    ):
        resp = client.post(
            "/api/v1/policies/pol-fallback/stage-matrix",
            headers=HEADERS,
            json={"stage_matrix": {"ide": True, "pr": False, "build": True, "deploy": False, "runtime": False}},
        )
    assert resp.status_code in (200, 201)
    data = resp.json()
    assert data["stage_matrix"]["ide"] is True
    assert data["stage_matrix"]["build"] is True
    assert data.get("source") == "in_memory_fallback"


# ---------------------------------------------------------------------------
# 5. GET /policies/{id}/stage-matrix — returns matrix stored by fallback
# ---------------------------------------------------------------------------
def test_get_stage_matrix_returns_stored():
    _STAGE_MATRIX_STORE["test-org"] = {
        "pol-stored": {"ide": True, "pr": True, "build": False, "deploy": True, "runtime": False}
    }
    mock_eng = MagicMock()
    mock_eng.get_policy.side_effect = RuntimeError("db error")
    with patch.dict(
        "sys.modules",
        {"core.policy_enforcement_engine": MagicMock(get_engine=lambda org_id: mock_eng)},
    ):
        resp = client.get("/api/v1/policies/pol-stored/stage-matrix", headers=HEADERS)
    assert resp.status_code == 200
    data = resp.json()
    assert data["stage_matrix"]["ide"] is True
    assert data["stage_matrix"]["deploy"] is True


# ---------------------------------------------------------------------------
# 6. GET /policies/{id}/stage-matrix — all-false default when nothing stored
# ---------------------------------------------------------------------------
def test_get_stage_matrix_default_false():
    _STAGE_MATRIX_STORE.clear()
    mock_eng = MagicMock()
    mock_eng.get_policy.side_effect = RuntimeError("db error")
    with patch.dict(
        "sys.modules",
        {"core.policy_enforcement_engine": MagicMock(get_engine=lambda org_id: mock_eng)},
    ):
        resp = client.get("/api/v1/policies/pol-unknown/stage-matrix", headers=HEADERS)
    assert resp.status_code == 200
    data = resp.json()
    assert all(v is False for v in data["stage_matrix"].values())


# ---------------------------------------------------------------------------
# 7. POST /evaluate — primary engine succeeds
# ---------------------------------------------------------------------------
def test_evaluate_at_stage_engine_path():
    mock_eng = MagicMock()
    mock_eng.evaluate.return_value = {
        "org_id": "test-org",
        "stage": "pr",
        "context": {"repo": "aldeci"},
        "policy_count": 2,
        "matched_policies": [],
        "decision": "advisory",
    }
    with patch.dict(
        "sys.modules",
        {"core.policy_enforcement_engine": MagicMock(get_engine=lambda org_id: mock_eng)},
    ):
        resp = client.post(
            "/api/v1/evaluate?stage=pr",
            headers=HEADERS,
            json={"context": {"repo": "aldeci"}},
        )
    assert resp.status_code == 200
    data = resp.json()
    assert data["decision"] in ("allow", "advisory", "enforce", "block")


# ---------------------------------------------------------------------------
# 8. POST /evaluate — both engines fail → graceful allow fallback
# ---------------------------------------------------------------------------
def test_evaluate_at_stage_fallback_allow():
    mock_eng = MagicMock()
    mock_eng.evaluate.side_effect = RuntimeError("primary fail")
    mock_pe = MagicMock()
    mock_pe.evaluate_at_stage.side_effect = RuntimeError("secondary fail")
    with patch.dict(
        "sys.modules",
        {
            "core.policy_enforcement_engine": MagicMock(get_engine=lambda org_id: mock_eng),
            "core.policy_engine": MagicMock(get_policy_engine=lambda: mock_pe),
        },
    ):
        resp = client.post(
            "/api/v1/evaluate?stage=build",
            headers=HEADERS,
            json={"context": {"pipeline": "ci"}},
        )
    assert resp.status_code == 200
    data = resp.json()
    assert data["decision"] == "allow"
    assert data["stage"] == "build"
    assert data.get("source") == "in_memory_fallback"


# ---------------------------------------------------------------------------
# 9. POST /evaluate — invalid stage rejected with 400
# ---------------------------------------------------------------------------
def test_evaluate_invalid_stage():
    resp = client.post(
        "/api/v1/evaluate?stage=not_a_stage",
        headers=HEADERS,
        json={"context": {}},
    )
    assert resp.status_code == 400
