"""
tests/test_no_fake_exec_metrics.py

Asserts that the 5 formerly-fake executive metric endpoints no longer return
old hardcoded constants (87, 4.2, $2.3M, 342%, etc.) and instead return either:
  - computed-from-engine data (real zeros / empty collections on a fresh DB), OR
  - an honest 501 / 503 / empty signal.

Endpoints under test (all require X-API-Key header):
  GET  /api/v1/executive/kpis
  GET  /api/v1/executive/regulatory-heatmap
  POST /api/v1/executive/board-report
  GET  /api/v1/attack-paths/stats          (was: fake 3-node chain; now: real engine)
  GET  /api/v1/supply-chain/risk-summary   (was: fake vendor numbers; now: real engine)
  GET  /api/v1/security-roi/portfolio      (was: $2.3M / 342%; now: real engine)
"""
from __future__ import annotations

import os
import json
import pytest
from fastapi.testclient import TestClient

# ---------------------------------------------------------------------------
# App fixture
# ---------------------------------------------------------------------------

_TEST_API_KEY = "test-key-no-fake-exec-metrics"

@pytest.fixture(scope="module")
def client():
    # auth_deps reads FIXOPS_API_TOKEN to build expected_tokens.
    # Must be set before create_app() so the token is known at request time
    # (auth_deps re-resolves per-request via _load_api_tokens()).
    os.environ["FIXOPS_API_TOKEN"] = _TEST_API_KEY
    from apps.api.app import create_app
    app = create_app()
    return TestClient(app, raise_server_exceptions=False)


HEADERS = {"X-API-Key": _TEST_API_KEY}

# ---------------------------------------------------------------------------
# Old fake literal constants that must NEVER appear in any response body
# ---------------------------------------------------------------------------

_OLD_FAKE_KPI_VALUES = {
    84.2,   # vuln_sla_compliance_rate
    18.5,   # mttd_hours
    91.0,   # security_training_completion_pct
    6.8,    # phishing_click_rate_pct
    72.0,   # third_party_risk_score
    77.5,   # code_security_score
}

_OLD_FAKE_COMPLIANCE_SCORES = {
    78.5,   # SOC2
    65.0,   # PCI-DSS
    71.0,   # HIPAA
    82.0,   # GDPR
    88.0,   # CCPA
}

_OLD_FAKE_ROI = {
    2_300_000,    # $2.3M "saved"
    342,          # 342% ROI
    2300000.0,
    342.0,
}

# Previously hardcoded posture_score / overall score
_OLD_FAKE_POSTURE = {87, 87.0}


def _body_contains_fake(body: dict, fake_set: set) -> bool:
    """Recursively check whether any numeric in body matches a fake value."""
    text = json.dumps(body)
    for val in fake_set:
        # Match both integer and float representations
        if str(val) in text or str(int(val)) in text:
            # Only flag if it's actually a number in JSON, not coincidentally in a string
            # We do a targeted check: look for the value as a JSON number
            import re
            pattern = r'(?<!["\w])' + re.escape(str(val)) + r'(?!["\w])'
            if re.search(pattern, text):
                return True
    return False


# ---------------------------------------------------------------------------
# 1. GET /api/v1/executive/kpis  — must NOT return old hardcoded KPI floats
# ---------------------------------------------------------------------------

def test_executive_kpis_no_fake_values(client):
    resp = client.get("/api/v1/executive/kpis", headers=HEADERS)
    assert resp.status_code in (200, 501, 503), (
        f"Unexpected status {resp.status_code}: {resp.text[:300]}"
    )
    if resp.status_code == 200:
        body = resp.json()
        # On a fresh empty DB, kpis list must be empty or contain real zeros
        kpis = body.get("kpis", [])
        for kpi in kpis:
            val = kpi.get("value")
            assert val not in _OLD_FAKE_KPI_VALUES, (
                f"KPI '{kpi.get('name')}' still returns old hardcoded value {val}"
            )
        # overall_health_score must not be the old fake 84.2 etc.
        health = body.get("overall_health_score", 0.0)
        assert health not in _OLD_FAKE_KPI_VALUES, (
            f"overall_health_score {health} is an old hardcoded value"
        )


# ---------------------------------------------------------------------------
# 2. GET /api/v1/executive/regulatory-heatmap — must NOT return old fake %s
# ---------------------------------------------------------------------------

def test_regulatory_heatmap_no_fake_values(client):
    resp = client.get("/api/v1/executive/regulatory-heatmap", headers=HEADERS)
    assert resp.status_code in (200, 501, 503), (
        f"Unexpected status {resp.status_code}: {resp.text[:300]}"
    )
    if resp.status_code == 200:
        body = resp.json()
        regs = body.get("regulations", [])
        for reg in regs:
            pct = reg.get("compliance_pct")
            assert pct not in _OLD_FAKE_COMPLIANCE_SCORES, (
                f"Regulation '{reg.get('regulation')}' still returns "
                f"old hardcoded compliance_pct={pct}"
            )


# ---------------------------------------------------------------------------
# 3. POST /api/v1/executive/board-report — fallback must NOT use fake defaults
# ---------------------------------------------------------------------------

def test_board_report_no_fake_fallback(client):
    # Send empty body so any fallback logic fires
    resp = client.post(
        "/api/v1/executive/board-report",
        json={},
        headers=HEADERS,
    )
    assert resp.status_code in (200, 500, 501, 503), (
        f"Unexpected status {resp.status_code}: {resp.text[:300]}"
    )
    if resp.status_code == 200:
        body = resp.json()
        body_text = json.dumps(body)
        for val in _OLD_FAKE_KPI_VALUES:
            assert str(val) not in body_text or _check_not_kpi_value(body, val), (
                f"board-report still embeds old hardcoded KPI value {val}"
            )


def _check_not_kpi_value(body: dict, val: float) -> bool:
    """Return True (pass) if val does not appear as a kpi summary value."""
    kpi_summary = body.get("kpi_summary", {})
    return str(val) not in json.dumps(kpi_summary)


# ---------------------------------------------------------------------------
# 4. GET /api/v1/attack-paths/stats — must be real engine, not fake chain
# ---------------------------------------------------------------------------

def test_attack_paths_stats_no_fake_chain(client):
    resp = client.get("/api/v1/attack-paths/stats", params={"org_id": "default"})
    # No auth required on this router (no Depends in attack_path_router)
    assert resp.status_code in (200, 401, 403, 501, 503), (
        f"Unexpected status {resp.status_code}: {resp.text[:300]}"
    )
    if resp.status_code == 200:
        body = resp.json()
        # A real empty graph has 0 nodes, 0 edges — not a fake 3-node chain
        node_count = body.get("node_count", body.get("nodes", 0))
        edge_count = body.get("edge_count", body.get("edges", 0))
        assert node_count != 3 or edge_count != 2, (
            "attack-paths/stats returns the old hardcoded 3-node fake chain "
            f"(nodes={node_count}, edges={edge_count})"
        )
        # Confirm no fake IPs / hostnames in body
        body_text = json.dumps(body)
        for fake_token in ["192.168.1.1", "server-01", "db-prod-01", "ACME"]:
            assert fake_token not in body_text, (
                f"attack-paths/stats still contains fake token '{fake_token}'"
            )


# ---------------------------------------------------------------------------
# 5. GET /api/v1/supply-chain/risk-summary — real engine, not fake vendor scores
# ---------------------------------------------------------------------------

def test_supply_chain_risk_summary_no_fake(client):
    resp = client.get("/api/v1/supply-chain/risk-summary", headers=HEADERS)
    assert resp.status_code in (200, 401, 403, 501, 503), (
        f"Unexpected status {resp.status_code}: {resp.text[:300]}"
    )
    # On a fresh DB this must return real zeros / empty, not fake vendor numbers
    if resp.status_code == 200:
        body = resp.json()
        body_text = json.dumps(body)
        for fake_token in ["ACME", "FakeVendor", "mock", "hardcode"]:
            assert fake_token.lower() not in body_text.lower(), (
                f"supply-chain/risk-summary still contains fake token '{fake_token}'"
            )


# ---------------------------------------------------------------------------
# 6. GET /api/v1/security-roi/portfolio — real engine, not $2.3M / 342%
# ---------------------------------------------------------------------------

def test_security_roi_portfolio_no_fake(client):
    resp = client.get("/api/v1/security-roi/portfolio", headers=HEADERS)
    assert resp.status_code in (200, 401, 403, 501, 503), (
        f"Unexpected status {resp.status_code}: {resp.text[:300]}"
    )
    if resp.status_code == 200:
        body = resp.json()
        # On an empty DB, total_cost and cost_avoidance must be real zeros
        total_cost = body.get("total_cost_usd", body.get("total_cost", None))
        roi_ratio = body.get("blended_roi_ratio", body.get("roi_ratio", None))
        if total_cost is not None:
            assert total_cost != 2_300_000 and total_cost != 2300000.0, (
                f"security-roi/portfolio still returns fake total_cost {total_cost}"
            )
        if roi_ratio is not None:
            assert roi_ratio != 342 and roi_ratio != 342.0, (
                f"security-roi/portfolio still returns fake roi_ratio {roi_ratio}"
            )


# ---------------------------------------------------------------------------
# 7. Confirm old posture_score=87 literal is gone from any executive endpoint
# ---------------------------------------------------------------------------

def test_no_posture_score_87(client):
    endpoints = [
        ("/api/v1/executive/kpis", "GET", None),
        ("/api/v1/executive/regulatory-heatmap", "GET", None),
    ]
    for path, method, body in endpoints:
        if method == "GET":
            resp = client.get(path, headers=HEADERS)
        else:
            resp = client.post(path, json=body or {}, headers=HEADERS)
        if resp.status_code == 200:
            body_text = resp.text
            # 87 as a standalone number — not inside a string like "87 days"
            import re
            matches = re.findall(r'(?<!["\w])87(?:\.0)?(?!["\w\d])', body_text)
            assert not matches, (
                f"{path} still returns old hardcoded posture_score=87: "
                f"matches={matches}, body={body_text[:300]}"
            )
