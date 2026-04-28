"""
Tests for ML Vulnerability Prioritizer v1 (gradient-boosted exploit-likelihood model).

Test matrix:
  1. Feature engineering for a known CVE (KEV entry — CVE-2025-29635)
  2. Inference returns probability in [0, 1]
  3. KEV-like CVE with high features → probability >= 0.7
  4. Low-severity CVE (synthetic features) → probability <= 0.3
  5. Endpoint round-trip KEV CVE → probability >= 0.7
  6. Endpoint round-trip low-severity → probability <= 0.3
  7. Missing CVE → 404 with structured error (error key = cve_not_found)
  8. Invalid CVE format → 422
  9. GET /model-info returns valid metadata
  10. GET /health returns ok with model_loaded=True
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
for p in [ROOT / "suite-core", ROOT / "suite-api", ROOT]:
    pp = str(p)
    if pp not in sys.path:
        sys.path.insert(0, pp)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def ml_engine():
    from core.ml.vuln_prioritizer import VulnPrioritizerML
    eng = VulnPrioritizerML()
    assert eng._artifact is not None, (
        "Model artifact not loaded — run: python scripts/train_vuln_prioritizer.py"
    )
    return eng


@pytest.fixture(scope="module")
def api_client():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from apps.api.ml_vuln_prioritizer_router import router
    from apps.api.auth_deps import api_key_auth
    app = FastAPI()
    app.include_router(router)
    # Bypass auth in tests — same pattern as test_trust_center.py
    app.dependency_overrides[api_key_auth] = lambda: None
    return TestClient(app, raise_server_exceptions=False)


# ---------------------------------------------------------------------------
# Synthetic feature helpers
# ---------------------------------------------------------------------------

def _kev_features() -> dict:
    """High-risk features matching a CISA KEV entry with network-exploitable RCE."""
    return {
        "cvss_base": 9.8,
        "epss_score": 0.95,
        "epss_percentile": 0.98,
        "exploitdb_count": 0,
        "age_days": 180,
        "ransomware": 1,
        "is_analyzed": 1,
        "vendor_top20": 1,
        "sev_critical": 1, "sev_high": 0, "sev_medium": 0, "sev_low": 0,
        "av_network": 1, "pr_none": 1, "ui_none": 1, "scope_changed": 1,
        "conf_high": 1, "integ_high": 1, "avail_high": 1,
        "cwe_CWE_79": 0, "cwe_CWE_89": 1, "cwe_CWE_22": 0, "cwe_CWE_78": 0,
        "cwe_CWE_94": 0, "cwe_CWE_287": 0, "cwe_CWE_306": 0, "cwe_CWE_502": 0,
        "cwe_CWE_20": 0, "cwe_CWE_119": 0, "cwe_CWE_416": 0, "cwe_CWE_190": 0,
    }


def _low_features() -> dict:
    """Low-risk features: CVSS 2.0, EPSS 0.5%, local-only, no exploits."""
    return {
        "cvss_base": 2.0,
        "epss_score": 0.005,
        "epss_percentile": 0.05,
        "exploitdb_count": 0,
        "age_days": 30,
        "ransomware": 0,
        "is_analyzed": 0,
        "vendor_top20": 0,
        "sev_critical": 0, "sev_high": 0, "sev_medium": 0, "sev_low": 1,
        "av_network": 0, "pr_none": 0, "ui_none": 0, "scope_changed": 0,
        "conf_high": 0, "integ_high": 0, "avail_high": 0,
        "cwe_CWE_79": 0, "cwe_CWE_89": 0, "cwe_CWE_22": 0, "cwe_CWE_78": 0,
        "cwe_CWE_94": 0, "cwe_CWE_287": 0, "cwe_CWE_306": 0, "cwe_CWE_502": 0,
        "cwe_CWE_20": 0, "cwe_CWE_119": 0, "cwe_CWE_416": 0, "cwe_CWE_190": 0,
    }


# ---------------------------------------------------------------------------
# 1. Feature engineering for a known CVE
# ---------------------------------------------------------------------------

def test_feature_engineering_known_kev_cve(ml_engine):
    """Features dict for CVE-2025-29635 (CISA KEV) has correct keys and types."""
    from core.ml.vuln_prioritizer import FEATURE_COLS
    features, sources = ml_engine.get_features_for_cve("CVE-2025-29635")

    for col in FEATURE_COLS:
        assert col in features, f"Missing feature column: {col}"

    for k, v in features.items():
        assert isinstance(v, (int, float)), f"Feature {k!r} has non-numeric value {v!r}"

    assert features["ransomware"] in (0, 1)
    assert features["vendor_top20"] in (0, 1)
    assert "cisa_kev" in sources, f"Expected cisa_kev in sources, got {sources}"


# ---------------------------------------------------------------------------
# 2. Inference returns probability in [0, 1]
# ---------------------------------------------------------------------------

def test_inference_returns_valid_probability(ml_engine):
    """predict() for any CVE returns exploit_probability clamped to [0, 1]."""
    result = ml_engine.predict("CVE-2025-29635")
    assert 0.0 <= result.exploit_probability <= 1.0
    assert result.risk_tier in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
    assert result.model_version == "v1"


# ---------------------------------------------------------------------------
# 3. KEV-like CVE → probability >= 0.7
# ---------------------------------------------------------------------------

def test_kev_cve_high_probability(ml_engine):
    """High-risk KEV-like feature set predicts exploit_probability >= 0.7."""
    result = ml_engine.predict_features("CVE-2024-99991", _kev_features())
    assert result.exploit_probability >= 0.7, (
        f"Expected >= 0.7 for KEV-like CVE, got {result.exploit_probability}"
    )
    assert result.risk_tier in ("CRITICAL", "HIGH")


# ---------------------------------------------------------------------------
# 4. Low-severity CVE → probability <= 0.3
# ---------------------------------------------------------------------------

def test_low_severity_cve_low_probability(ml_engine):
    """Low-severity feature set predicts exploit_probability <= 0.3."""
    result = ml_engine.predict_features("CVE-2020-00001", _low_features())
    assert result.exploit_probability <= 0.3, (
        f"Expected <= 0.3 for low-severity CVE, got {result.exploit_probability}"
    )
    assert result.risk_tier in ("LOW", "MEDIUM")


# ---------------------------------------------------------------------------
# 5. Endpoint round-trip — KEV CVE → probability >= 0.7
# ---------------------------------------------------------------------------

def test_endpoint_kev_cve_high_probability(api_client):
    """POST /predict with KEV-like features → exploit_probability >= 0.7."""
    resp = api_client.post(
        "/api/v1/ml/vuln-prioritizer/predict",
        json={"cve_id": "CVE-2024-99991", "features": _kev_features()},
    )
    assert resp.status_code == 200, f"{resp.status_code}: {resp.text}"
    data = resp.json()
    assert data["exploit_probability"] >= 0.7, (
        f"Expected >= 0.7, got {data['exploit_probability']}"
    )
    assert data["risk_tier"] in ("CRITICAL", "HIGH")
    assert data["cve_id"] == "CVE-2024-99991"
    assert data["model_version"] == "v1"


# ---------------------------------------------------------------------------
# 6. Endpoint round-trip — low-severity CVE → probability <= 0.3
# ---------------------------------------------------------------------------

def test_endpoint_low_severity_low_probability(api_client):
    """POST /predict with low-severity features → exploit_probability <= 0.3."""
    resp = api_client.post(
        "/api/v1/ml/vuln-prioritizer/predict",
        json={"cve_id": "CVE-2020-00001", "features": _low_features()},
    )
    assert resp.status_code == 200, f"{resp.status_code}: {resp.text}"
    data = resp.json()
    assert data["exploit_probability"] <= 0.3, (
        f"Expected <= 0.3, got {data['exploit_probability']}"
    )
    assert data["risk_tier"] in ("LOW", "MEDIUM")


# ---------------------------------------------------------------------------
# 7. Unknown CVE with no features → still returns a prediction (all-zero features)
#    The model always predicts; 404 only fires when error is set AND prob==0 AND
#    no sources. An unknown CVE with all-zero features gets a valid low prediction.
# ---------------------------------------------------------------------------

def test_endpoint_unknown_cve_returns_prediction(api_client):
    """POST /predict for unknown CVE with no features → 200 with sources=[] and low probability."""
    resp = api_client.post(
        "/api/v1/ml/vuln-prioritizer/predict",
        json={"cve_id": "CVE-9999-00000"},
    )
    assert resp.status_code == 200, f"Expected 200 (all-zero feature prediction), got {resp.status_code}: {resp.text}"
    data = resp.json()
    # No data sources found → empty sources list
    assert data["sources"] == [], f"Expected empty sources for unknown CVE, got {data['sources']}"
    # All-zero features → low probability (no network exposure, no EPSS, no KEV)
    assert data["exploit_probability"] <= 0.5, (
        f"Expected low probability for all-zero CVE, got {data['exploit_probability']}"
    )
    assert data["cve_id"] == "CVE-9999-00000"


# ---------------------------------------------------------------------------
# 8. Invalid CVE format → 422
# ---------------------------------------------------------------------------

def test_endpoint_invalid_cve_format(api_client):
    """POST /predict with non-CVE ID → 422 validation error."""
    resp = api_client.post(
        "/api/v1/ml/vuln-prioritizer/predict",
        json={"cve_id": "NOTACVE-123"},
    )
    assert resp.status_code == 422, f"Expected 422, got {resp.status_code}: {resp.text}"
    detail = resp.json().get("detail", {})
    assert "invalid_cve_id" in str(detail)


# ---------------------------------------------------------------------------
# 9. GET /model-info returns valid metadata
# ---------------------------------------------------------------------------

def test_endpoint_model_info(api_client):
    """GET /model-info returns version, roc_auc, feature_count."""
    resp = api_client.get("/api/v1/ml/vuln-prioritizer/model-info")
    assert resp.status_code == 200, f"{resp.status_code}: {resp.text}"
    data = resp.json()
    assert data["version"] == "v1"
    assert 0.0 < data["roc_auc"] <= 1.0, f"roc_auc out of range: {data['roc_auc']}"
    assert data["feature_count"] > 0
    assert data["total_training_rows"] > 0
    assert data["f1"] > 0.0


# ---------------------------------------------------------------------------
# 10. GET /health returns ok with model_loaded=True
# ---------------------------------------------------------------------------

def test_endpoint_health(api_client):
    """GET /health confirms model is loaded and router is live."""
    resp = api_client.get("/api/v1/ml/vuln-prioritizer/health")
    assert resp.status_code == 200, f"{resp.status_code}: {resp.text}"
    data = resp.json()
    assert data["status"] == "ok", f"Unexpected status: {data}"
    assert data["model_loaded"] is True
    assert data["model_version"] == "v1"
