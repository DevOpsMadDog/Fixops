"""Tests for SAST finding-baseline policy endpoints.

  GET  /api/v1/sast/policy  — evaluate gate against latest scan
  PUT  /api/v1/sast/policy  — update policy thresholds
"""
from __future__ import annotations

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-core"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-api"))

import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from fastapi import FastAPI

# Import router and policy state after path setup
from apps.api.sast_router import router, _POLICY_STATE, _SEVERITY_ORDER, _severity_ge


# ── Minimal app fixture ───────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def reset_policy():
    """Reset policy to defaults before each test."""
    from apps.api.sast_router import _PolicyState
    _POLICY_STATE._policy = dict(_PolicyState._DEFAULT)
    yield


def _make_client():
    app = FastAPI()
    app.include_router(router)
    return TestClient(app, headers={"X-API-Key": "test-key"})


# Mock get_org_id so we don't need a real auth stack
@pytest.fixture(autouse=True)
def mock_org_id(monkeypatch):
    monkeypatch.setattr(
        "apps.api.sast_router.get_org_id",
        lambda: "test-org",
    )


# ── Unit tests: helpers ───────────────────────────────────────────────────────

class TestSeverityHelpers:
    def test_severity_order_completeness(self):
        assert _SEVERITY_ORDER == ["critical", "high", "medium", "low", "info"]

    def test_severity_ge_critical_ge_high(self):
        assert _severity_ge("critical", "high") is True

    def test_severity_ge_high_ge_high(self):
        assert _severity_ge("high", "high") is True

    def test_severity_ge_low_not_ge_high(self):
        assert _severity_ge("low", "high") is False

    def test_severity_ge_info_not_ge_medium(self):
        assert _severity_ge("info", "medium") is False

    def test_severity_ge_unknown_returns_false(self):
        assert _severity_ge("unknown", "high") is False


# ── Unit tests: _PolicyState ──────────────────────────────────────────────────

class TestPolicyState:
    def test_get_returns_defaults(self):
        p = _POLICY_STATE.get()
        assert p["fail_on_severity"] == "high"
        assert p["max_critical"] == 0
        assert p["max_high"] == 0
        assert "CWE-89" in p["blocked_cwes"]
        assert p["enabled"] is True
        assert "updated_at" in p

    def test_update_fail_on_severity(self):
        updated = _POLICY_STATE.update({"fail_on_severity": "critical"})
        assert updated["fail_on_severity"] == "critical"
        assert _POLICY_STATE.get()["fail_on_severity"] == "critical"

    def test_update_ignores_unknown_keys(self):
        _POLICY_STATE.update({"hacker_mode": True})
        p = _POLICY_STATE.get()
        assert "hacker_mode" not in p

    def test_update_partial_keeps_other_fields(self):
        _POLICY_STATE.update({"max_critical": 3})
        p = _POLICY_STATE.get()
        assert p["max_critical"] == 3
        assert p["max_high"] == 0  # unchanged


# ── Integration: GET /policy — no scan yet ───────────────────────────────────

class TestGetPolicyNoScan:
    def test_returns_no_scan_gate_when_no_scan(self):
        mock_engine = MagicMock()
        mock_engine.get_summary.return_value = {"status": "no_scan", "message": "No scans run"}

        client = _make_client()
        with patch("apps.api.sast_router.get_sast_engine", return_value=mock_engine):
            resp = client.get("/api/v1/sast/policy")

        assert resp.status_code == 200
        data = resp.json()
        assert data["gate"] == "no_scan"
        assert data["violations"] == []
        assert data["summary"] is None
        assert "policy" in data


# ── Integration: GET /policy — scan with findings ────────────────────────────

class TestGetPolicyWithFindings:
    def _scan_summary(self, by_severity, by_cwe=None):
        return {
            "scan_id": "test-scan-1",
            "files_scanned": 5,
            "total_findings": sum(by_severity.values()),
            "by_severity": by_severity,
            "by_cwe": by_cwe or {},
            "duration_ms": 42.0,
            "timestamp": "2026-05-03T00:00:00+00:00",
        }

    def test_gate_passes_when_no_high_or_critical(self):
        mock_engine = MagicMock()
        mock_engine.get_summary.return_value = self._scan_summary(
            {"critical": 0, "high": 0, "medium": 2, "low": 1, "info": 0}
        )
        client = _make_client()
        with patch("apps.api.sast_router.get_sast_engine", return_value=mock_engine):
            resp = client.get("/api/v1/sast/policy")
        data = resp.json()
        assert data["gate"] == "pass"
        assert data["violations"] == []

    def test_gate_fails_on_critical_finding(self):
        mock_engine = MagicMock()
        mock_engine.get_summary.return_value = self._scan_summary(
            {"critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0}
        )
        client = _make_client()
        with patch("apps.api.sast_router.get_sast_engine", return_value=mock_engine):
            resp = client.get("/api/v1/sast/policy")
        data = resp.json()
        assert data["gate"] == "fail"
        assert len(data["violations"]) >= 1

    def test_gate_fails_on_high_finding_default_threshold(self):
        mock_engine = MagicMock()
        mock_engine.get_summary.return_value = self._scan_summary(
            {"critical": 0, "high": 2, "medium": 0, "low": 0, "info": 0}
        )
        client = _make_client()
        with patch("apps.api.sast_router.get_sast_engine", return_value=mock_engine):
            resp = client.get("/api/v1/sast/policy")
        data = resp.json()
        assert data["gate"] == "fail"

    def test_gate_fails_on_blocked_cwe(self):
        mock_engine = MagicMock()
        mock_engine.get_summary.return_value = self._scan_summary(
            {"critical": 0, "high": 0, "medium": 1, "low": 0, "info": 0},
            by_cwe={"CWE-89": 1},
        )
        client = _make_client()
        with patch("apps.api.sast_router.get_sast_engine", return_value=mock_engine):
            resp = client.get("/api/v1/sast/policy")
        data = resp.json()
        assert data["gate"] == "fail"
        assert any("CWE-89" in v for v in data["violations"])

    def test_gate_passes_when_policy_disabled(self):
        _POLICY_STATE.update({"enabled": False})
        mock_engine = MagicMock()
        mock_engine.get_summary.return_value = self._scan_summary(
            {"critical": 5, "high": 10, "medium": 0, "low": 0, "info": 0}
        )
        client = _make_client()
        with patch("apps.api.sast_router.get_sast_engine", return_value=mock_engine):
            resp = client.get("/api/v1/sast/policy")
        data = resp.json()
        assert data["gate"] == "pass"


# ── Integration: PUT /policy ──────────────────────────────────────────────────

class TestUpdatePolicy:
    def test_update_fail_on_severity_to_critical(self):
        client = _make_client()
        resp = client.put("/api/v1/sast/policy", json={"fail_on_severity": "critical"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["policy"]["fail_on_severity"] == "critical"
        assert data["message"] == "Policy updated"

    def test_update_invalid_severity_returns_400(self):
        client = _make_client()
        resp = client.put("/api/v1/sast/policy", json={"fail_on_severity": "ultra"})
        assert resp.status_code == 400

    def test_update_blocked_cwes_normalises_case(self):
        client = _make_client()
        resp = client.put("/api/v1/sast/policy", json={"blocked_cwes": ["cwe-79", "cwe-22"]})
        assert resp.status_code == 200
        assert "CWE-79" in resp.json()["policy"]["blocked_cwes"]
        assert "CWE-22" in resp.json()["policy"]["blocked_cwes"]

    def test_update_max_critical_persists(self):
        client = _make_client()
        resp = client.put("/api/v1/sast/policy", json={"max_critical": 5})
        assert resp.status_code == 200
        assert resp.json()["policy"]["max_critical"] == 5

    def test_update_partial_leaves_other_fields_intact(self):
        client = _make_client()
        client.put("/api/v1/sast/policy", json={"max_high": 3})
        p = _POLICY_STATE.get()
        assert p["max_high"] == 3
        assert p["max_critical"] == 0  # unchanged default

    def test_update_enable_disable_toggle(self):
        client = _make_client()
        resp = client.put("/api/v1/sast/policy", json={"enabled": False})
        assert resp.status_code == 200
        assert resp.json()["policy"]["enabled"] is False
