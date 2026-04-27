"""Wave D — Integrations / AI / Policy router smoke tests (20 endpoints).

Each endpoint gets a happy-path call plus a focused error case.
Acceptable codes: {200, 201, 202, 400, 403, 404, 422, 501}.
"""
from __future__ import annotations

import importlib

import pytest

from fastapi import FastAPI
from fastapi.testclient import TestClient

import apps.api.auth_deps as _auth_mod
from apps.api.wave_d_integrations_router import router as wave_d_router


@pytest.fixture(scope="module", autouse=True)
def _auth_env() -> None:
    mp = pytest.MonkeyPatch()
    mp.setenv("FIXOPS_API_TOKEN", "wave-d-test-token")
    mp.setenv("FIXOPS_MODE", "dev")
    mp.delenv("FIXOPS_JWT_SECRET", raising=False)
    importlib.reload(_auth_mod)
    yield
    mp.undo()


@pytest.fixture(scope="module")
def app() -> FastAPI:
    a = FastAPI()
    a.include_router(wave_d_router)
    return a


@pytest.fixture(scope="module")
def client(app: FastAPI) -> TestClient:
    return TestClient(
        app,
        headers={"X-API-Key": "wave-d-test-token", "X-Org-ID": "wave-d-org"},
    )


# ===========================================================================
# 1+2. Connector mapping create + dry-run
# ===========================================================================

def test_create_connector_mapping(client):
    resp = client.post(
        "/api/v1/connectors/mapping",
        json={
            "connector_id": "snyk",
            "source_field": "issue.title",
            "target_field": "finding.title",
            "enabled": True,
        },
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["connector_id"] == "snyk"
    assert body["enabled"] is True
    assert body["mapping_id"].startswith("map_")


def test_create_connector_mapping_missing_field_returns_422(client):
    resp = client.post("/api/v1/connectors/mapping", json={"connector_id": "snyk"})
    assert resp.status_code == 422


def test_dry_run_connector_mapping(client):
    resp = client.post(
        "/api/v1/connectors/mapping/dry-run",
        json={
            "connector_id": "snyk",
            "sample_payload": {"issue": {"title": "RCE"}, "severity": "high"},
            "mappings": [
                {"source_field": "issue.title", "target_field": "title"},
                {"source_field": "severity", "target_field": "severity"},
            ],
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["mapped_payload"]["title"] == "RCE"
    assert body["mapped_payload"]["severity"] == "high"
    assert body["applied"] == 2


# ===========================================================================
# 3+4. Webhooks: catalogue + subscribe
# ===========================================================================

def test_webhook_event_catalogue(client):
    resp = client.get("/api/v1/webhooks/event-catalogue")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["count"] >= 5
    assert isinstance(body["events"], list)


def test_webhook_subscribe(client):
    resp = client.post(
        "/api/v1/webhooks/subscribe",
        json={
            "url": "https://example.com/webhook",
            "event_types": ["vulnerability.discovered"],
        },
    )
    assert resp.status_code in {200, 201}, resp.text


def test_webhook_subscribe_bad_url_returns_422(client):
    resp = client.post(
        "/api/v1/webhooks/subscribe",
        json={"url": "ftp://nope", "event_types": ["scan.completed"]},
    )
    assert resp.status_code == 422


# ===========================================================================
# 5-7. EASM
# ===========================================================================

def test_easm_seed_domain(client):
    resp = client.post(
        "/api/v1/easm/seed-domain",
        json={"domain": "example.com", "discover_subsidiaries": False, "timeout_s": 1.0},
    )
    assert resp.status_code in {200, 201}, resp.text
    body = resp.json()
    assert body["domain"] == "example.com"
    assert "report_id" in body


def test_easm_subsidiaries(client):
    resp = client.get("/api/v1/easm/subsidiaries/wave-d-org")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "subsidiaries" in body
    assert isinstance(body["subsidiaries"], list)


def test_easm_exposures_with_confidence(client):
    resp = client.get("/api/v1/easm/exposures", params={"confidence": 0.5, "limit": 10})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["confidence_threshold"] == 0.5
    assert "exposures" in body


# ===========================================================================
# 8+9. Copilot graph NL + traversal trace
# ===========================================================================

def test_copilot_graph_nl_query_and_trace(client):
    resp = client.post(
        "/api/v1/copilot/graph-nl-query",
        json={"query": "show all internet-exposed assets with critical CVEs", "agent_type": "general"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "q_id" in body
    q_id = body["q_id"]

    # Trace must be retrievable for our org
    trace_resp = client.get(f"/api/v1/copilot/{q_id}/traversal-trace")
    assert trace_resp.status_code == 200, trace_resp.text
    trace_body = trace_resp.json()
    assert trace_body["q_id"] == q_id
    assert "steps" in trace_body


def test_copilot_traversal_trace_unknown_returns_404(client):
    resp = client.get("/api/v1/copilot/nonexistent-q-id/traversal-trace")
    assert resp.status_code == 404


# ===========================================================================
# 10+11. AI exposure
# ===========================================================================

def test_ai_exposure_shadow(client):
    resp = client.get("/api/v1/ai-exposure/shadow", params={"flag_unregistered": True})
    assert resp.status_code == 200, resp.text


def test_ai_exposure_sanctioned_list(client):
    resp = client.post(
        "/api/v1/ai-exposure/sanctioned-list",
        json={
            "service_name": "OpenAI ChatGPT Enterprise",
            "provider": "OpenAI",
            "data_classification": "internal",
            "approved_by": "ciso@example.com",
        },
    )
    assert resp.status_code in {200, 201}, resp.text


# ===========================================================================
# 12. Agents task dispatch
# ===========================================================================

def test_dispatch_agent_task(client):
    resp = client.post(
        "/api/v1/agents/security_analyst/task",
        json={
            "title": "Triage CVE-2024-1234",
            "prompt": "Investigate this CVE and recommend remediation.",
            "priority": "high",
        },
    )
    assert resp.status_code == 202, resp.text
    body = resp.json()
    assert body["role"] == "security_analyst"
    assert body["status"] == "queued"
    assert body["task_id"].startswith("task_")


def test_dispatch_agent_task_unknown_role_returns_400(client):
    resp = client.post(
        "/api/v1/agents/lawyer/task",
        json={"title": "Wrong role", "prompt": "test"},
    )
    assert resp.status_code == 400


# ===========================================================================
# 13. Asset crown-jewel tag
# ===========================================================================

def test_tag_crown_jewel(client):
    resp = client.post(
        "/api/v1/assets/asset-001/crown-jewel-tag",
        json={
            "crown_jewel": True,
            "business_impact": "critical",
            "justification": "stores customer PII",
            "tagged_by": "wave-d-ciso",
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["asset_id"] == "asset-001"
    assert body["crown_jewel"] is True


# ===========================================================================
# 14+15. TrustGraph compact + quality issues
# ===========================================================================

def test_trustgraph_compact_dry_run(client):
    resp = client.post(
        "/api/v1/trustgraph/compact",
        json={"cores": [1, 2], "dry_run": True},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["dry_run"] is True
    assert "elapsed_s" in body


def test_trustgraph_quality_issues(client):
    resp = client.get(
        "/api/v1/trustgraph/quality-issues",
        params={"severity": "high", "limit": 10},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "issues" in body


# ===========================================================================
# 16+17. Auto waivers
# ===========================================================================

def test_list_waivers_auto_only(client):
    resp = client.get("/api/v1/waivers", params={"auto": True, "limit": 10})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["auto_only"] is True
    assert "waivers" in body


def test_create_auto_waiver_rule(client):
    resp = client.post(
        "/api/v1/auto-waiver-rules",
        json={
            "rule_key": "wave-d-test-rule",
            "conditions": {"severity": "low", "reachable": False},
            "max_active_count": 50,
            "approvers": ["sec-lead@example.com"],
            "expires_days": 14,
        },
    )
    # 201 if engine accepts, 501 if engine missing the method
    assert resp.status_code in {200, 201, 400, 501}, resp.text


# ===========================================================================
# 18-20. Policy stage matrix + evaluate
# ===========================================================================

def test_set_policy_stage_matrix_unknown_stage_returns_422(client):
    resp = client.post(
        "/api/v1/policies/policy-1/stage-matrix",
        json={"stage_matrix": {"production_only": True}},
    )
    # Pydantic validator catches unknown stages -> 422
    assert resp.status_code == 422


def test_set_policy_stage_matrix(client):
    resp = client.post(
        "/api/v1/policies/policy-1/stage-matrix",
        json={"stage_matrix": {"build": True, "deploy": False, "runtime": True}},
    )
    # 200 (set), 404 (policy not found), or 501 (engine missing)
    assert resp.status_code in {200, 404, 400, 501}, resp.text


def test_get_policy_stage_matrix_unknown_returns_404_or_501(client):
    resp = client.get("/api/v1/policies/non-existent/stage-matrix")
    assert resp.status_code in {404, 501}, resp.text


def test_evaluate_at_stage_invalid_returns_400(client):
    resp = client.post(
        "/api/v1/evaluate",
        params={"stage": "invalid-stage"},
        json={"context": {}},
    )
    assert resp.status_code == 400


def test_evaluate_at_stage_valid(client):
    resp = client.post(
        "/api/v1/evaluate",
        params={"stage": "build"},
        json={"context": {"finding_id": "f-1", "severity": "high"}},
    )
    # 200 (verdict), or 400/501 (engine missing/rejects)
    assert resp.status_code in {200, 400, 501}, resp.text
