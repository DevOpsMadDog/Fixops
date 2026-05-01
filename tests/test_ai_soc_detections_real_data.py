"""Tests for DefenderXDRLiveConnector → /api/v1/ai-soc/detections fallback.

Validates the engine fallback added in
``ai_powered_soc_engine.list_detections_with_xdr_fallback``:

1. Org with registered aisoc_detections → returns those rows untouched
   (source="org_registered").
2. Org with no rows + connector unconfigured (no DEFENDER_TENANT_ID etc.) →
   structured needs_credentials hint (NEVER mocks).
3. Org with no rows + connector returns ok+alerts → projects each Defender
   alert as a derived detection (model_type=rule_based, severity mapped,
   source_data_type derived from finding_type, confidence_score=cvss*10).
4. Connector returns status="needs_credentials" → propagates needs_credentials
   envelope unchanged.
5. Connector raises Exception → captured as source="connector_error".
6. Filters apply against derived rows.
7. End-to-end through FastAPI router (auth bypassed) → structured envelope.
"""
from __future__ import annotations

import os
import sys
import uuid
from typing import Any, Dict, List

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def _make_engine(tmp_path):
    from core.ai_powered_soc_engine import AIPoweredSOCEngine
    db = os.path.join(str(tmp_path), f"aisoc_{uuid.uuid4().hex}.db")
    return AIPoweredSOCEngine(db_path=db)


class _FakeDefenderConnector:
    """Stand-in for DefenderXDRLiveConnector with controllable response."""

    def __init__(self, payload: Dict[str, Any] = None,
                 raise_exc: Exception = None):
        self._payload = payload or {}
        self._raise_exc = raise_exc
        self.calls: List[str] = []

    def fetch_alerts(self, org_id: str, *args, **kwargs):
        self.calls.append(org_id)
        if self._raise_exc is not None:
            raise self._raise_exc
        return self._payload


# ------------------------------------------------------------------
# Test 1 — org_registered precedence
# ------------------------------------------------------------------
def test_returns_org_registered_when_detections_exist(tmp_path):
    eng = _make_engine(tmp_path)
    eng.record_detection("acme", {
        "detection_name": "real-detection-1",
        "model_type":     "anomaly_detection",
        "severity":       "high",
        "source_data_type": "endpoint",
        "confidence_score": 90.0,
    })
    out = eng.list_detections_with_xdr_fallback("acme")
    assert out["source"] == "org_registered"
    assert out["total"] == 1
    assert out["detections"][0]["detection_name"] == "real-detection-1"


# ------------------------------------------------------------------
# Test 2 — needs_credentials when nothing configured (NEVER mocks)
# ------------------------------------------------------------------
def test_returns_needs_credentials_when_connector_absent(tmp_path, monkeypatch):
    eng = _make_engine(tmp_path)
    # Force creds absent in module-level resolution path
    for var in ("DEFENDER_TENANT_ID", "DEFENDER_CLIENT_ID", "DEFENDER_CLIENT_SECRET"):
        monkeypatch.delenv(var, raising=False)
    out = eng.list_detections_with_xdr_fallback("brand-new-org")
    assert out["source"] == "needs_credentials"
    assert out["detections"] == []
    assert out["total"] == 0
    assert "DEFENDER_TENANT_ID" in out["hint"]


# ------------------------------------------------------------------
# Test 3 — projects defender alerts into detection shape
# ------------------------------------------------------------------
def test_projects_defender_alerts_as_derived_detections(tmp_path):
    eng = _make_engine(tmp_path)
    fake = _FakeDefenderConnector(payload={
        "status": "ok",
        "mode":   "live",
        "org_id": "acme",
        "alert_count": 3,
        "alerts": [
            {
                "title":           "Suspicious PowerShell command line",
                "severity":        "high",
                "finding_type":    "anomaly",
                "cvss_score":      7.8,
                "asset_id":        "WIN-SRV-01.contoso.local",
                "asset_type":      "host",
                "alert_id":        "da1",
                "correlation_key": "defender_xdr|da1",
                "ingested_at":     "2026-04-25T14:32:11Z",
            },
            {
                "title":           "Ransomware behavior detected",
                "severity":        "critical",
                "finding_type":    "malware",
                "cvss_score":      9.5,
                "asset_id":        "WIN-WS-23.contoso.local",
                "asset_type":      "host",
                "alert_id":        "da2",
                "correlation_key": "defender_xdr|da2",
            },
            {
                "title":           "Credential dumping via LSASS",
                "severity":        "high",
                "finding_type":    "secret-exposure",
                "cvss_score":      7.8,
                "asset_id":        "WIN-DC-01.contoso.local",
                "asset_type":      "host",
                "alert_id":        "da3",
                "correlation_key": "defender_xdr|da3",
            },
        ],
        "ingested_at": "2026-05-02T12:00:00Z",
    })
    out = eng.list_detections_with_xdr_fallback("acme", xdr_connector=fake)

    assert out["source"] == "defender_xdr"
    assert out["total"] == 3
    assert fake.calls == ["acme"]
    by_alert = {d["alert_id"]: d for d in out["detections"]}

    # Anomaly → endpoint ... wait: actually anomaly→logs in our map.
    da1 = by_alert["da1"]
    assert da1["detection_name"] == "Suspicious PowerShell command line"
    assert da1["severity"] == "high"
    assert da1["source_data_type"] == "logs"  # anomaly → logs
    assert da1["model_type"] == "rule_based"
    assert da1["confidence_score"] == 78.0    # 7.8 * 10
    assert da1["status"] == "new"
    assert da1["auto_triaged"] is False

    # Malware → endpoint
    da2 = by_alert["da2"]
    assert da2["severity"] == "critical"
    assert da2["source_data_type"] == "endpoint"
    assert da2["confidence_score"] == 95.0

    # Secret-exposure → identity
    da3 = by_alert["da3"]
    assert da3["source_data_type"] == "identity"

    # Provenance
    assert all(d["source"] == "defender_xdr" for d in out["detections"])


# ------------------------------------------------------------------
# Test 4 — connector reports needs_credentials → propagated envelope
# ------------------------------------------------------------------
def test_connector_needs_credentials_propagates(tmp_path):
    eng = _make_engine(tmp_path)
    fake = _FakeDefenderConnector(payload={
        "status": "needs_credentials",
        "mode":   "no-op",
        "org_id": "acme",
        "alert_count": 0,
        "findings_recorded": 0,
        "alerts": [],
        "hint":   "Set DEFENDER_TENANT_ID...",
    })
    out = eng.list_detections_with_xdr_fallback("acme", xdr_connector=fake)
    assert out["source"] == "needs_credentials"
    assert out["detections"] == []
    assert "DEFENDER_TENANT_ID" in out["hint"]


# ------------------------------------------------------------------
# Test 5 — connector exception → connector_error envelope (never crashes)
# ------------------------------------------------------------------
def test_connector_exception_returns_connector_error(tmp_path):
    eng = _make_engine(tmp_path)
    fake = _FakeDefenderConnector(raise_exc=RuntimeError("graph 503"))
    out = eng.list_detections_with_xdr_fallback("acme", xdr_connector=fake)
    assert out["source"] == "connector_error"
    assert out["detections"] == []
    assert "graph 503" in out["error"]


# ------------------------------------------------------------------
# Test 6 — filters apply against derived rows + dedup + needs_data path
# ------------------------------------------------------------------
def test_filters_apply_against_derived_rows_and_dedup(tmp_path):
    eng = _make_engine(tmp_path)
    fake = _FakeDefenderConnector(payload={
        "status": "ok",
        "alerts": [
            {
                "title": "Phish A", "severity": "medium", "finding_type": "anomaly",
                "cvss_score": 5.0, "asset_id": "ws1", "asset_type": "host",
                "alert_id": "p1", "correlation_key": "defender_xdr|p1",
            },
            {
                "title": "Phish A dup", "severity": "medium",
                "finding_type": "anomaly", "cvss_score": 5.0,
                "asset_id": "ws1", "asset_type": "host",
                "alert_id": "p1",  # duplicate alert_id → dropped
                "correlation_key": "defender_xdr|p1",
            },
            {
                "title": "Cred dump", "severity": "high",
                "finding_type": "secret-exposure", "cvss_score": 7.8,
                "asset_id": "dc1", "asset_type": "host",
                "alert_id": "c1", "correlation_key": "defender_xdr|c1",
            },
            {
                "title": "Malformed - no severity", "finding_type": "anomaly",
                "cvss_score": 5.0, "alert_id": "bad",
            },  # rejected by projector
        ],
    })
    # Severity filter
    high = eng.list_detections_with_xdr_fallback(
        "acme", severity="high", xdr_connector=fake,
    )
    assert high["total"] == 1
    assert high["detections"][0]["alert_id"] == "c1"

    # source_data_type filter — "logs" matches the anomaly alerts
    logs = eng.list_detections_with_xdr_fallback(
        "acme", source_data_type="logs", xdr_connector=fake,
    )
    # 1 unique anomaly survived dedup
    assert logs["total"] == 1
    assert logs["detections"][0]["alert_id"] == "p1"

    # needs_data when zero projectable alerts
    fake_empty = _FakeDefenderConnector(payload={"status": "ok", "alerts": []})
    out_nd = eng.list_detections_with_xdr_fallback(
        "acme", xdr_connector=fake_empty,
    )
    assert out_nd["source"] == "needs_data"
    assert out_nd["total"] == 0


# ------------------------------------------------------------------
# Test 7 — end-to-end through the FastAPI router
# ------------------------------------------------------------------
def test_router_wired_to_fallback(tmp_path, monkeypatch):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from apps.api.ai_powered_soc_router import router as soc_router
    from apps.api.auth_deps import api_key_auth

    import apps.api.ai_powered_soc_router as soc_module
    soc_module._engine = None
    monkeypatch.setattr(
        "core.ai_powered_soc_engine._DEFAULT_DB",
        os.path.join(str(tmp_path), "aisoc_router.db"),
        raising=False,
    )
    # Force creds absent → should hit needs_credentials path
    for var in ("DEFENDER_TENANT_ID", "DEFENDER_CLIENT_ID", "DEFENDER_CLIENT_SECRET"):
        monkeypatch.delenv(var, raising=False)

    app = FastAPI()
    app.include_router(soc_router)
    app.dependency_overrides[api_key_auth] = lambda: True
    client = TestClient(app)

    r = client.get("/api/v1/ai-soc/detections?org_id=brand-new-org")
    assert r.status_code == 200, r.text
    body = r.json()
    # Must be the structured envelope, not a bare list.
    assert isinstance(body, dict)
    assert "detections" in body
    assert "source" in body
    assert body["source"] == "needs_credentials"
    assert body["detections"] == []
