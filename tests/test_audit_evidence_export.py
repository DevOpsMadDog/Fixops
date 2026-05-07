"""
Smoke tests for POST /api/v1/audit-evidence/export
Multica #4133
"""
from __future__ import annotations

import io
import zipfile

import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock

from apps.api.audit_evidence_export_router import router
from fastapi import FastAPI

# ── Minimal app fixture ────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def client():
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


# ── Helpers ────────────────────────────────────────────────────────────────────

def _fake_control(cid: str, status: str = "passing"):
    ctrl = MagicMock()
    ctrl.id = cid
    ctrl.status.value = status
    ctrl.evidence_ids = ["ev-1", "ev-2"]
    return ctrl


def _fake_log(ctrl_id: str):
    log = MagicMock()
    log.timestamp = "2026-05-05T00:00:00Z"
    log.event_type = "access"
    log.action = ctrl_id  # matches control id lower-case check
    log.user_id = "u-1"
    log.severity = "low"
    log.resource_id = ""
    return log


# ── Test 1: valid framework returns a well-formed ZIP ─────────────────────────

def test_export_returns_valid_zip(client):
    controls = [_fake_control("CC1.1"), _fake_control("CC1.2", "failing")]
    logs = [_fake_log("cc1.1"), _fake_log("cc1.2")]

    with (
        patch(
            "apps.api.audit_evidence_export_router._get_engine"
        ) as mock_engine_factory,
        patch(
            "apps.api.audit_evidence_export_router._audit_db"
        ) as mock_db,
    ):
        mock_engine = MagicMock()
        mock_engine._get_controls.return_value = controls
        mock_engine_factory.return_value = mock_engine
        mock_db.list_audit_logs.return_value = logs

        resp = client.post("/api/v1/audit-evidence/export?framework=SOC2")

    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/zip"
    assert "audit-evidence-SOC2.zip" in resp.headers["content-disposition"]

    # Verify ZIP contents
    buf = io.BytesIO(resp.content)
    with zipfile.ZipFile(buf) as zf:
        names = zf.namelist()
        assert "controls.csv" in names
        assert "evidence/CC1.1.txt" in names
        assert "evidence/CC1.2.txt" in names

        csv_text = zf.read("controls.csv").decode()
        assert "control_id,status,evidence_count" in csv_text
        assert "CC1.1,passing,2" in csv_text
        assert "CC1.2,failing,2" in csv_text

        ev_text = zf.read("evidence/CC1.1.txt").decode()
        assert "cc1.1" in ev_text.lower()
        assert "2026-05-05" in ev_text


# ── Test 2: unsupported framework returns 400 ─────────────────────────────────

def test_export_bad_framework_returns_400(client):
    resp = client.post("/api/v1/audit-evidence/export?framework=FAKE_FRAMEWORK")
    assert resp.status_code == 400
    body = resp.json()
    assert "Unsupported framework" in body["detail"]


# ── Test 3: PCI_DSS framework smoke test ──────────────────────────────────────

def test_export_pci_dss_framework(client):
    controls = [_fake_control("REQ-1"), _fake_control("REQ-2")]
    logs = [_fake_log("req-1"), _fake_log("req-2")]

    with (
        patch(
            "apps.api.audit_evidence_export_router._get_engine"
        ) as mock_engine_factory,
        patch(
            "apps.api.audit_evidence_export_router._audit_db"
        ) as mock_db,
    ):
        mock_engine = MagicMock()
        mock_engine._get_controls.return_value = controls
        mock_engine_factory.return_value = mock_engine
        mock_db.list_audit_logs.return_value = logs

        resp = client.post("/api/v1/audit-evidence/export?framework=PCI_DSS")

    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/zip"
    assert "audit-evidence-PCI-DSS.zip" in resp.headers["content-disposition"]

    buf = io.BytesIO(resp.content)
    with zipfile.ZipFile(buf) as zf:
        csv_text = zf.read("controls.csv").decode()
        assert "REQ-1,passing" in csv_text
        assert "REQ-2,passing" in csv_text


# ── Test 4: HIPAA framework smoke test ────────────────────────────────────────

def test_export_hipaa_framework(client):
    controls = [_fake_control("ADMIN-001"), _fake_control("TECH-005")]
    logs = [_fake_log("admin-001"), _fake_log("tech-005")]

    with (
        patch(
            "apps.api.audit_evidence_export_router._get_engine"
        ) as mock_engine_factory,
        patch(
            "apps.api.audit_evidence_export_router._audit_db"
        ) as mock_db,
    ):
        mock_engine = MagicMock()
        mock_engine._get_controls.return_value = controls
        mock_engine_factory.return_value = mock_engine
        mock_db.list_audit_logs.return_value = logs

        resp = client.post("/api/v1/audit-evidence/export?framework=HIPAA")

    assert resp.status_code == 200
    assert "audit-evidence-HIPAA.zip" in resp.headers["content-disposition"]

    buf = io.BytesIO(resp.content)
    with zipfile.ZipFile(buf) as zf:
        csv_text = zf.read("controls.csv").decode()
        assert "ADMIN-001,passing" in csv_text
        assert "TECH-005,passing" in csv_text


# ── Test 5: ISO27001 framework smoke test ─────────────────────────────────────

def test_export_iso27001_framework(client):
    controls = [_fake_control("A.5.1"), _fake_control("A.9.2")]
    logs = [_fake_log("a.5.1"), _fake_log("a.9.2")]

    with (
        patch(
            "apps.api.audit_evidence_export_router._get_engine"
        ) as mock_engine_factory,
        patch(
            "apps.api.audit_evidence_export_router._audit_db"
        ) as mock_db,
    ):
        mock_engine = MagicMock()
        mock_engine._get_controls.return_value = controls
        mock_engine_factory.return_value = mock_engine
        mock_db.list_audit_logs.return_value = logs

        resp = client.post("/api/v1/audit-evidence/export?framework=ISO27001")

    assert resp.status_code == 200
    assert "audit-evidence-ISO27001.zip" in resp.headers["content-disposition"]

    buf = io.BytesIO(resp.content)
    with zipfile.ZipFile(buf) as zf:
        csv_text = zf.read("controls.csv").decode()
        assert "A.5.1,passing" in csv_text
        assert "A.9.2,passing" in csv_text
