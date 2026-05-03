"""
Router-level HTTP tests for Prometheus alerts capability API.

Covers /api/v1/prometheus/* via FastAPI TestClient with a real engine
(no mocks). Singleton is reset per test for isolation.

Tests:
  1. GET /              — capability summary, status=ok, rule_count >= 12
  2. GET /groups        — 4 groups, security has 12 canonical rules
  3. GET /rules         — full catalog includes all 12 canonical security rules
  4. GET /rules?group=security — filtered listing returns only security rules
  5. GET /rules/{id}    — known rule + unknown returns 404
  6. POST /alerts/test  — firing case (gt comparison)
  7. POST /alerts/test  — inactive case (gt comparison)
  8. POST /alerts/test  — degraded case (unsupported PromQL feature)
  9. POST /alerts/test  — unknown rule_id returns 404
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

for _p in ["suite-core", "suite-api"]:
    _abs = str(Path(__file__).parent.parent / _p)
    if _abs not in sys.path:
        sys.path.insert(0, _abs)

import core.prometheus_alerts_engine as _engine_mod
from core.prometheus_alerts_engine import (
    PrometheusAlertsEngine,
    RULE_GROUPS,
    evaluate_promql,
)
import apps.api.prometheus_alerts_router as _router_mod
from apps.api.prometheus_alerts_router import router


_CANONICAL_SECURITY_RULES = {
    "high-severity-finding-spike",
    "brain-pipeline-failure-rate",
    "scanner-error-rate",
    "trustgraph-emit-failures",
    "llm-consensus-disagreement-rate",
    "mttr-degradation",
    "finding-backlog-growth",
    "integration-down",
    "webhook-dlq-overflow",
    "license-expiry-warning",
    "evidence-vault-fail",
    "mfa-bypass-attempt",
}


@pytest.fixture(autouse=True)
def _reset_singleton():
    _engine_mod._engine_singleton = None
    yield
    _engine_mod._engine_singleton = None


@pytest.fixture
def engine():
    return PrometheusAlertsEngine()


@pytest.fixture
def client(engine, monkeypatch):
    monkeypatch.setattr(_router_mod, "_get_engine", lambda: engine)

    app = FastAPI()
    app.include_router(router)

    try:
        from apps.api.auth_deps import api_key_auth as _auth
        app.dependency_overrides[_auth] = lambda: None
    except ImportError:
        pass

    return TestClient(app, raise_server_exceptions=True)


# ---------------------------------------------------------------------------
# 1. GET /  — capability summary
# ---------------------------------------------------------------------------

def test_capability_summary(client):
    resp = client.get("/api/v1/prometheus/")
    assert resp.status_code == 200
    body = resp.json()
    assert body["service"] == "Prometheus"
    assert body["status"] == "ok"
    assert body["evaluation_engine"] == "PromQL-subset"
    assert set(body["rule_groups"]) == set(RULE_GROUPS)
    assert body["rule_count"] >= 12


# ---------------------------------------------------------------------------
# 2. GET /groups
# ---------------------------------------------------------------------------

def test_groups_lists_all_four(client):
    resp = client.get("/api/v1/prometheus/groups")
    assert resp.status_code == 200
    body = resp.json()
    assert body["count"] == 4
    by_group = {g["group"]: g["rule_count"] for g in body["groups"]}
    assert set(by_group.keys()) == set(RULE_GROUPS)
    # 12 canonical security rules required
    assert by_group["security"] >= 12


# ---------------------------------------------------------------------------
# 3. GET /rules — full catalog includes all canonical security rules
# ---------------------------------------------------------------------------

def test_rules_full_catalog_includes_canonical_security(client):
    resp = client.get("/api/v1/prometheus/rules")
    assert resp.status_code == 200
    body = resp.json()
    ids = {r["rule_id"] for r in body["rules"]}
    missing = _CANONICAL_SECURITY_RULES - ids
    assert not missing, f"missing canonical security rules: {sorted(missing)}"
    for r in body["rules"]:
        assert set(r.keys()) >= {
            "rule_id", "group", "name", "expr",
            "for_duration", "severity", "summary", "runbook_url",
        }


# ---------------------------------------------------------------------------
# 4. GET /rules?group=security
# ---------------------------------------------------------------------------

def test_rules_filtered_by_group(client):
    resp = client.get("/api/v1/prometheus/rules", params={"group": "security"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["count"] >= 12
    assert all(r["group"] == "security" for r in body["rules"])

    bad = client.get("/api/v1/prometheus/rules", params={"group": "no-such"})
    assert bad.status_code == 400


# ---------------------------------------------------------------------------
# 5. GET /rules/{id}
# ---------------------------------------------------------------------------

def test_get_rule_known_and_unknown(client):
    resp = client.get("/api/v1/prometheus/rules/mfa-bypass-attempt")
    assert resp.status_code == 200
    body = resp.json()
    assert body["rule_id"] == "mfa-bypass-attempt"
    assert body["group"] == "security"
    assert body["severity"] == "critical"

    missing = client.get("/api/v1/prometheus/rules/no-such-rule")
    assert missing.status_code == 404


# ---------------------------------------------------------------------------
# 6. POST /alerts/test — firing
# ---------------------------------------------------------------------------

def test_alerts_test_firing(client):
    payload = {
        "rule_id": "high-severity-finding-spike",
        "sample_metrics": {"rate_findings_high_5m": 25.0},
    }
    resp = client.post("/api/v1/prometheus/alerts/test", json=payload)
    assert resp.status_code == 200
    body = resp.json()
    assert body["rule_id"] == "high-severity-finding-spike"
    assert body["evaluation_result"] == "firing"
    assert "rate_findings_high_5m" in body["sample_metrics"]


# ---------------------------------------------------------------------------
# 7. POST /alerts/test — inactive
# ---------------------------------------------------------------------------

def test_alerts_test_inactive(client):
    payload = {
        "rule_id": "high-severity-finding-spike",
        "sample_metrics": {"rate_findings_high_5m": 1.0},
    }
    resp = client.post("/api/v1/prometheus/alerts/test", json=payload)
    assert resp.status_code == 200
    body = resp.json()
    assert body["evaluation_result"] == "inactive"


# ---------------------------------------------------------------------------
# 8. POST /alerts/test — degraded (unsupported PromQL feature)
# ---------------------------------------------------------------------------

def test_alerts_test_degraded_on_unsupported_feature(engine, monkeypatch, client):
    """Synthetic rule injected with a function call (unsupported in safe subset)."""
    from core.prometheus_alerts_engine import AlertRule

    bad_rule = AlertRule(
        rule_id="synthetic-bad-promql",
        group="security",
        name="Synthetic Bad",
        expr="rate(foo_total[5m]) > 0",
        for_duration="1m",
        severity="warning",
        summary="synthetic",
        runbook_url="https://runbooks.aldeci.io/synthetic",
    )
    engine.rules = engine.rules + (bad_rule,)

    payload = {"rule_id": "synthetic-bad-promql", "sample_metrics": {}}
    resp = client.post("/api/v1/prometheus/alerts/test", json=payload)
    assert resp.status_code == 200
    body = resp.json()
    assert body["evaluation_result"] == "degraded"
    assert body["evaluated_expr"] == "rate(foo_total[5m]) > 0"


# ---------------------------------------------------------------------------
# 9. POST /alerts/test — unknown rule_id
# ---------------------------------------------------------------------------

def test_alerts_test_unknown_rule(client):
    payload = {"rule_id": "no-such-rule-id", "sample_metrics": {"x": 1.0}}
    resp = client.post("/api/v1/prometheus/alerts/test", json=payload)
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# 10. Engine-level: PromQL-subset interpreter sanity
# ---------------------------------------------------------------------------

def test_promql_subset_interpreter_sanity():
    # Comparison
    assert evaluate_promql("a > 5", {"a": 10})[0] == "firing"
    assert evaluate_promql("a > 5", {"a": 1})[0] == "inactive"
    # Arithmetic
    assert evaluate_promql("a / b > 0.5", {"a": 8, "b": 10})[0] == "firing"
    assert evaluate_promql("a / b > 0.5", {"a": 1, "b": 10})[0] == "inactive"
    # Logical
    assert evaluate_promql("a > 1 and b > 1", {"a": 2, "b": 2})[0] == "firing"
    assert evaluate_promql("a > 1 and b > 1", {"a": 2, "b": 0})[0] == "inactive"
    assert evaluate_promql("a > 1 or b > 1", {"a": 0, "b": 2})[0] == "firing"
    assert evaluate_promql("a > 1 unless b > 1", {"a": 2, "b": 0})[0] == "firing"
    assert evaluate_promql("a > 1 unless b > 1", {"a": 2, "b": 2})[0] == "inactive"
    # Missing metric defaults to 0
    assert evaluate_promql("missing > 0", {})[0] == "inactive"
    # Unsupported function
    assert evaluate_promql("rate(x[1m]) > 0", {})[0] == "degraded"
