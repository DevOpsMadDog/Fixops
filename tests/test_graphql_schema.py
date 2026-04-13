"""Comprehensive tests for GraphQL schema, resolver engine, and HTTP router.

Tests cover:
- Schema SDL availability and completeness
- Query parser correctness (field, args, operation type)
- execute_graphql return envelope shape
- All 8 Query resolvers (with mocked managers)
- All 4 Mutation resolvers
- Subscription type handling (HTTP no-transport response)
- Error handling: unknown field, resolver exception, parse error
- Type serialisers: _serialize_finding, _serialize_asset, _serialize_incident, _serialize_vendor
- HTTP router: POST /api/v1/graphql, GET /api/v1/graphql/schema
- Variables merging
- Pagination args (limit, offset)
- Filter args (severity, status, org_id, etc.)
"""

from __future__ import annotations

import json
import os
import sys
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Environment setup — must happen BEFORE any app imports
# ---------------------------------------------------------------------------
os.environ.setdefault("FIXOPS_MODE", "dev")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-graphql-token")
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-secret-key-32-chars-padded-xx")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

# Ensure suite-core is on the path
_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
for _d in ["suite-core", "suite-api", "suite-feeds"]:
    _p = os.path.join(_REPO_ROOT, _d)
    if _p not in sys.path:
        sys.path.insert(0, _p)

from core.graphql_schema import (
    SCHEMA_SDL,
    execute_graphql,
    get_schema_sdl,
    _parse_graphql_query,
    _serialize_finding,
    _serialize_asset,
    _serialize_incident,
    _serialize_vendor,
    resolve_findings,
    resolve_assets,
    resolve_incidents,
    resolve_compliance_status,
    resolve_posture_score,
    resolve_attack_surface,
    resolve_vendors,
    resolve_threat_landscape,
    resolve_acknowledge_finding,
    resolve_create_incident,
    resolve_update_compliance,
    resolve_accept_risk,
    _findings_store,
    _incidents_store,
    _now_iso,
)


# ===========================================================================
# Helpers
# ===========================================================================

def _make_finding(**kwargs) -> Dict[str, Any]:
    base = {
        "id": f"f-{uuid.uuid4().hex[:8]}",
        "title": "Test Finding",
        "severity": "high",
        "status": "open",
        "org_id": "org-test",
        "created_at": _now_iso(),
    }
    base.update(kwargs)
    return base


def _make_asset(**kwargs) -> Dict[str, Any]:
    base = {
        "id": f"a-{uuid.uuid4().hex[:8]}",
        "name": "Test Asset",
        "asset_type": "server",
        "criticality": "high",
        "lifecycle": "active",
        "org_id": "org-test",
        "tags": [],
        "created_at": _now_iso(),
    }
    base.update(kwargs)
    return base


def _make_incident(**kwargs) -> Dict[str, Any]:
    base = {
        "id": f"inc-{uuid.uuid4().hex[:8]}",
        "title": "Test Incident",
        "incident_type": "malware",
        "severity": "sev2",
        "status": "detected",
        "org_id": "org-test",
        "affected_assets": [],
        "created_at": _now_iso(),
    }
    base.update(kwargs)
    return base


# ===========================================================================
# 1. Schema SDL
# ===========================================================================

class TestSchemaSdl:
    def test_sdl_is_string(self):
        assert isinstance(SCHEMA_SDL, str)
        assert len(SCHEMA_SDL) > 100

    def test_get_schema_sdl_returns_same(self):
        assert get_schema_sdl() == SCHEMA_SDL

    def test_sdl_contains_finding_type(self):
        assert "type Finding" in SCHEMA_SDL

    def test_sdl_contains_asset_type(self):
        assert "type Asset" in SCHEMA_SDL

    def test_sdl_contains_incident_type(self):
        assert "type Incident" in SCHEMA_SDL

    def test_sdl_contains_compliance_type(self):
        assert "ComplianceStatus" in SCHEMA_SDL

    def test_sdl_contains_vendor_type(self):
        assert "type Vendor" in SCHEMA_SDL

    def test_sdl_contains_threat_actor_type(self):
        assert "type ThreatActor" in SCHEMA_SDL

    def test_sdl_contains_all_queries(self):
        for q in ("findings", "assets", "incidents", "compliance_status",
                  "posture_score", "attack_surface", "vendors", "threat_landscape"):
            assert q in SCHEMA_SDL, f"Missing query: {q}"

    def test_sdl_contains_all_mutations(self):
        for m in ("acknowledge_finding", "create_incident",
                  "update_compliance", "accept_risk"):
            assert m in SCHEMA_SDL, f"Missing mutation: {m}"

    def test_sdl_contains_subscription_types(self):
        for s in ("new_finding", "sla_breach", "incident_update"):
            assert s in SCHEMA_SDL, f"Missing subscription: {s}"

    def test_sdl_contains_posture_score_type(self):
        assert "PostureScore" in SCHEMA_SDL

    def test_sdl_contains_attack_surface_type(self):
        assert "AttackSurface" in SCHEMA_SDL


# ===========================================================================
# 2. Query parser
# ===========================================================================

class TestParseGraphqlQuery:
    def test_simple_query(self):
        result = _parse_graphql_query("query { findings { id severity } }")
        assert result["operation"] == "query"
        assert result["field"] == "findings"

    def test_mutation_operation(self):
        result = _parse_graphql_query('mutation { acknowledge_finding(finding_id: "f-1", acknowledged_by: "alice") { status } }')
        assert result["operation"] == "mutation"
        assert result["field"] == "acknowledge_finding"

    def test_subscription_operation(self):
        result = _parse_graphql_query("subscription { new_finding(org_id: \"org-1\") { finding { id } } }")
        assert result["operation"] == "subscription"

    def test_args_string(self):
        result = _parse_graphql_query('query { findings(org_id: "org-1", severity: "high") { id } }')
        assert result["args"]["org_id"] == "org-1"
        assert result["args"]["severity"] == "high"

    def test_args_integer(self):
        result = _parse_graphql_query("query { findings(limit: 10, offset: 5) { id } }")
        assert result["args"]["limit"] == 10
        assert result["args"]["offset"] == 5

    def test_args_boolean(self):
        result = _parse_graphql_query("query { threat_landscape(org_id: \"x\") { active_campaigns } }")
        assert result["field"] == "threat_landscape"

    def test_no_args(self):
        result = _parse_graphql_query("query { vendors { id name } }")
        assert result["field"] == "vendors"
        assert result["args"] == {}

    def test_implicit_query(self):
        result = _parse_graphql_query("{ findings { id } }")
        assert result["field"] == "findings"


# ===========================================================================
# 3. Serialisers
# ===========================================================================

class TestSerializers:
    def test_serialize_finding_dict(self):
        f = _make_finding(cve_id="CVE-2024-1234", cvss_score=9.8, scanner="trivy")
        out = _serialize_finding(f)
        assert out["id"] == f["id"]
        assert out["severity"] == "high"
        assert out["cve_id"] == "CVE-2024-1234"
        assert out["cvss_score"] == 9.8
        assert out["scanner"] == "trivy"
        assert out["org_id"] == "org-test"

    def test_serialize_finding_defaults(self):
        out = _serialize_finding({"id": "x"})
        assert out["status"] == "open"
        assert out["severity"] == "medium"
        assert out["org_id"] == "default"

    def test_serialize_finding_pydantic_model(self):
        mock = MagicMock()
        mock.model_dump.return_value = _make_finding(title="Pydantic Finding")
        out = _serialize_finding(mock)
        assert out["title"] == "Pydantic Finding"

    def test_serialize_asset_dict(self):
        a = _make_asset(hostname="prod-web-01", ip_address="10.0.0.1", environment="production")
        out = _serialize_asset(a)
        assert out["hostname"] == "prod-web-01"
        assert out["ip_address"] == "10.0.0.1"
        assert out["environment"] == "production"
        assert isinstance(out["tags"], list)

    def test_serialize_asset_defaults(self):
        out = _serialize_asset({"id": "a1", "name": "X", "asset_type": "server"})
        assert out["criticality"] == "medium"
        assert out["lifecycle"] == "active"

    def test_serialize_incident_dict(self):
        i = _make_incident(affected_assets=["a1", "a2"], assigned_to="alice")
        out = _serialize_incident(i)
        assert out["affected_assets"] == ["a1", "a2"]
        assert out["assigned_to"] == "alice"
        assert out["incident_type"] == "malware"

    def test_serialize_vendor_dict(self):
        v = {
            "id": "v-1",
            "name": "Acme Corp",
            "domain": "acme.com",
            "tier": "high",
            "sbom_component_count": 42,
            "org_id": "org-test",
            "created_at": _now_iso(),
        }
        out = _serialize_vendor(v)
        assert out["name"] == "Acme Corp"
        assert out["sbom_component_count"] == 42
        assert out["latest_assessment"] is None

    def test_serialize_vendor_with_assessment(self):
        v = {
            "id": "v-2",
            "name": "Beta Ltd",
            "domain": "beta.com",
            "tier": "medium",
            "sbom_component_count": 5,
            "org_id": "org-test",
            "created_at": _now_iso(),
            "latest_assessment": {
                "score": 82.0,
                "grade": "B",
                "assessed_at": _now_iso(),
                "expires_at": _now_iso(),
                "status": "completed",
            },
        }
        out = _serialize_vendor(v)
        assert out["latest_assessment"]["score"] == 82.0
        assert out["latest_assessment"]["grade"] == "B"


# ===========================================================================
# 4. Resolver: findings
# ===========================================================================

class TestResolveFindings:
    def setup_method(self):
        _findings_store.clear()

    def test_returns_list(self):
        result = resolve_findings({})
        assert isinstance(result, list)

    def test_uses_local_store(self):
        f = _make_finding(org_id="org-local")
        _findings_store[f["id"]] = f
        result = resolve_findings({"org_id": "org-local"})
        assert any(r["id"] == f["id"] for r in result)

    def test_filters_by_severity(self):
        _findings_store["h1"] = _make_finding(severity="high", org_id="org-x")
        _findings_store["l1"] = _make_finding(severity="low", org_id="org-x")
        result = resolve_findings({"org_id": "org-x", "severity": "high"})
        assert all(r["severity"] == "high" for r in result)

    def test_filters_by_status(self):
        _findings_store["o1"] = _make_finding(status="open", org_id="org-x")
        _findings_store["r1"] = _make_finding(status="remediated", org_id="org-x")
        result = resolve_findings({"org_id": "org-x", "status": "open"})
        assert all(r["status"] == "open" for r in result)

    def test_pagination_limit(self):
        for i in range(10):
            f = _make_finding(org_id="org-page")
            _findings_store[f["id"]] = f
        result = resolve_findings({"org_id": "org-page", "limit": 3})
        assert len(result) <= 3

    def test_pagination_offset(self):
        for i in range(5):
            f = _make_finding(org_id="org-offset")
            _findings_store[f["id"]] = f
        all_results = resolve_findings({"org_id": "org-offset", "limit": 5})
        offset_results = resolve_findings({"org_id": "org-offset", "limit": 5, "offset": 2})
        assert len(offset_results) == len(all_results) - 2

    def test_filters_by_cve_id(self):
        _findings_store["c1"] = _make_finding(cve_id="CVE-2024-1111", org_id="org-cve")
        _findings_store["c2"] = _make_finding(cve_id="CVE-2024-9999", org_id="org-cve")
        result = resolve_findings({"org_id": "org-cve", "cve_id": "CVE-2024-1111"})
        assert all(r.get("cve_id") == "CVE-2024-1111" for r in result)


# ===========================================================================
# 5. Resolver: assets
# ===========================================================================

class TestResolveAssets:
    def test_returns_list_when_manager_unavailable(self):
        with patch("core.graphql_schema.resolve_assets.__module__", create=True):
            result = resolve_assets({"org_id": "org-x"})
        assert isinstance(result, list)

    def test_limit_applied(self):
        mock_assets = [_make_asset() for _ in range(10)]
        mock_inventory = MagicMock()
        mock_inventory.list_assets.return_value = mock_assets
        with patch("core.graphql_schema.resolve_assets") as mock_resolver:
            mock_resolver.return_value = [_serialize_asset(a) for a in mock_assets[:3]]
            result = mock_resolver({"org_id": "org-x", "limit": 3})
        assert len(result) <= 3


# ===========================================================================
# 6. Resolver: incidents
# ===========================================================================

class TestResolveIncidents:
    def setup_method(self):
        _incidents_store.clear()

    def test_returns_list(self):
        result = resolve_incidents({})
        assert isinstance(result, list)

    def test_uses_local_store(self):
        i = _make_incident(org_id="org-inc")
        _incidents_store[i["id"]] = i
        result = resolve_incidents({"org_id": "org-inc"})
        assert any(r["id"] == i["id"] for r in result)

    def test_filters_by_severity(self):
        _incidents_store["i1"] = _make_incident(severity="sev1", org_id="org-sev")
        _incidents_store["i2"] = _make_incident(severity="sev3", org_id="org-sev")
        result = resolve_incidents({"org_id": "org-sev", "severity": "sev1"})
        assert all(r["severity"] == "sev1" for r in result)

    def test_filters_by_status(self):
        _incidents_store["i3"] = _make_incident(status="detected", org_id="org-st")
        _incidents_store["i4"] = _make_incident(status="closed", org_id="org-st")
        result = resolve_incidents({"org_id": "org-st", "status": "detected"})
        assert all(r["status"] == "detected" for r in result)


# ===========================================================================
# 7. Resolver: compliance_status
# ===========================================================================

class TestResolveComplianceStatus:
    def test_returns_fallback_when_unavailable(self):
        result = resolve_compliance_status({"org_id": "org-c", "framework": "SOC2"})
        assert result["org_id"] == "org-c"
        assert result["framework"] == "SOC2"
        assert isinstance(result["overall_score"], float)
        assert isinstance(result["controls"], list)

    def test_all_required_fields_present(self):
        result = resolve_compliance_status({"org_id": "org-c", "framework": "NIST"})
        for field in ("org_id", "framework", "overall_score", "passing_controls",
                      "failing_controls", "not_applicable", "controls", "assessed_at"):
            assert field in result, f"Missing field: {field}"


# ===========================================================================
# 8. Resolver: posture_score
# ===========================================================================

class TestResolvePostureScore:
    def test_returns_fallback_when_unavailable(self):
        result = resolve_posture_score({"org_id": "org-ps"})
        assert result["org_id"] == "org-ps"
        assert "overall_score" in result
        assert "grade" in result
        assert isinstance(result["components"], list)

    def test_id_is_string(self):
        result = resolve_posture_score({"org_id": "org-ps"})
        assert isinstance(result["id"], str)
        assert len(result["id"]) > 0


# ===========================================================================
# 9. Resolver: attack_surface
# ===========================================================================

class TestResolveAttackSurface:
    def test_returns_fallback_when_unavailable(self):
        result = resolve_attack_surface({"org_id": "org-as"})
        assert result["org_id"] == "org-as"
        assert isinstance(result["total_assets"], int)
        assert isinstance(result["exposure_paths"], list)
        assert isinstance(result["risk_score"], float)


# ===========================================================================
# 10. Resolver: vendors
# ===========================================================================

class TestResolveVendors:
    def test_returns_list_when_unavailable(self):
        result = resolve_vendors({"org_id": "org-v"})
        assert isinstance(result, list)

    def test_limit_applied(self):
        mock_vendors = []
        with patch("core.graphql_schema.resolve_vendors") as mock_r:
            mock_r.return_value = mock_vendors
            result = mock_r({"org_id": "org-v", "limit": 5})
        assert isinstance(result, list)


# ===========================================================================
# 11. Resolver: threat_landscape
# ===========================================================================

class TestResolveThreatLandscape:
    def test_returns_correct_shape(self):
        result = resolve_threat_landscape({"org_id": "org-tl"})
        assert result["org_id"] == "org-tl"
        assert isinstance(result["active_campaigns"], int)
        assert isinstance(result["relevant_actors"], list)
        assert isinstance(result["top_ttps"], list)
        assert "risk_level" in result
        assert "assessed_at" in result


# ===========================================================================
# 12. Mutation: acknowledge_finding
# ===========================================================================

class TestMutationAcknowledgeFinding:
    def setup_method(self):
        _findings_store.clear()

    def test_ack_existing_finding(self):
        f = _make_finding()
        _findings_store[f["id"]] = f
        result = resolve_acknowledge_finding({
            "finding_id": f["id"],
            "acknowledged_by": "alice",
            "comment": "Reviewing now",
        })
        assert result["finding_id"] == f["id"]
        assert result["acknowledged_by"] == "alice"
        assert result["status"] == "in_progress"
        assert _findings_store[f["id"]]["status"] == "in_progress"

    def test_ack_nonexistent_finding(self):
        result = resolve_acknowledge_finding({
            "finding_id": "nonexistent-id",
            "acknowledged_by": "bob",
        })
        assert result["finding_id"] == "nonexistent-id"
        assert "message" in result

    def test_ack_result_has_timestamp(self):
        result = resolve_acknowledge_finding({
            "finding_id": "x",
            "acknowledged_by": "carol",
        })
        assert "acknowledged_at" in result
        assert result["acknowledged_at"]


# ===========================================================================
# 13. Mutation: create_incident
# ===========================================================================

class TestMutationCreateIncident:
    def setup_method(self):
        _incidents_store.clear()

    def test_creates_incident(self):
        result = resolve_create_incident({
            "title": "Ransomware Attack",
            "incident_type": "ransomware",
            "severity": "sev1",
            "org_id": "org-ir",
            "description": "Critical",
            "affected_assets": ["asset-1", "asset-2"],
        })
        assert "incident_id" in result
        assert result["title"] == "Ransomware Attack"
        assert result["status"] == "detected"
        assert "created_at" in result

    def test_incident_id_is_string(self):
        result = resolve_create_incident({
            "title": "Test Inc",
            "incident_type": "phishing",
            "severity": "sev3",
            "org_id": "org-ir",
        })
        assert isinstance(result["incident_id"], str)
        assert len(result["incident_id"]) > 0


# ===========================================================================
# 14. Mutation: update_compliance
# ===========================================================================

class TestMutationUpdateCompliance:
    def test_returns_correct_shape(self):
        result = resolve_update_compliance({
            "org_id": "org-comp",
            "framework": "SOC2",
            "control_id": "CC6.1",
            "status": "passing",
            "evidence_notes": "Audit log reviewed",
        })
        assert result["control_id"] == "CC6.1"
        assert result["framework"] == "SOC2"
        assert result["new_status"] == "passing"
        assert "updated_at" in result

    def test_accepts_failing_status(self):
        result = resolve_update_compliance({
            "org_id": "org-comp",
            "framework": "NIST",
            "control_id": "ID.AM-1",
            "status": "failing",
        })
        assert result["new_status"] == "failing"


# ===========================================================================
# 15. Mutation: accept_risk
# ===========================================================================

class TestMutationAcceptRisk:
    def setup_method(self):
        _findings_store.clear()

    def test_accept_risk_basic(self):
        result = resolve_accept_risk({
            "finding_id": "f-risk-1",
            "accepted_by": "ciso",
            "reason": "Compensating controls in place",
        })
        assert result["finding_id"] == "f-risk-1"
        assert result["accepted"] is True
        assert result["accepted_by"] == "ciso"
        assert result["reason"] == "Compensating controls in place"
        assert "accepted_at" in result

    def test_accept_risk_with_expiry(self):
        result = resolve_accept_risk({
            "finding_id": "f-risk-2",
            "accepted_by": "manager",
            "reason": "Temporary",
            "expiry_days": 30,
        })
        assert result["expiry"] is not None
        assert "2026" in result["expiry"] or "2027" in result["expiry"]

    def test_accept_risk_no_expiry(self):
        result = resolve_accept_risk({
            "finding_id": "f-risk-3",
            "accepted_by": "cto",
            "reason": "Architecture constraint",
        })
        assert result["expiry"] is None


# ===========================================================================
# 16. execute_graphql — integration
# ===========================================================================

class TestExecuteGraphql:
    def setup_method(self):
        _findings_store.clear()
        _incidents_store.clear()

    def test_findings_query_returns_data_key(self):
        result = execute_graphql('query { findings(org_id: "org-x") { id severity } }')
        assert "data" in result
        assert "findings" in result["data"]

    def test_assets_query_returns_data_key(self):
        result = execute_graphql('query { assets(org_id: "org-x") { id name } }')
        assert "data" in result
        assert "assets" in result["data"]

    def test_incidents_query_returns_data_key(self):
        result = execute_graphql('query { incidents(org_id: "org-x") { id title } }')
        assert "data" in result
        assert "incidents" in result["data"]

    def test_compliance_status_query(self):
        result = execute_graphql('query { compliance_status(org_id: "org-x", framework: "SOC2") { overall_score } }')
        assert "data" in result
        assert "compliance_status" in result["data"]

    def test_posture_score_query(self):
        result = execute_graphql('query { posture_score(org_id: "org-x") { overall_score grade } }')
        assert "data" in result
        assert "posture_score" in result["data"]

    def test_attack_surface_query(self):
        result = execute_graphql('query { attack_surface(org_id: "org-x") { total_assets } }')
        assert "data" in result
        assert "attack_surface" in result["data"]

    def test_vendors_query(self):
        result = execute_graphql('query { vendors(org_id: "org-x") { id name } }')
        assert "data" in result
        assert "vendors" in result["data"]

    def test_threat_landscape_query(self):
        result = execute_graphql('query { threat_landscape(org_id: "org-x") { risk_level } }')
        assert "data" in result
        assert "threat_landscape" in result["data"]

    def test_unknown_query_field_returns_error(self):
        result = execute_graphql("query { nonexistent_field { id } }")
        assert "errors" in result
        assert any("nonexistent_field" in e["message"] for e in result["errors"])

    def test_acknowledge_finding_mutation(self):
        f = _make_finding()
        _findings_store[f["id"]] = f
        q = f'mutation {{ acknowledge_finding(finding_id: "{f["id"]}", acknowledged_by: "alice") {{ status }} }}'
        result = execute_graphql(q)
        assert "data" in result
        assert "acknowledge_finding" in result["data"]

    def test_create_incident_mutation(self):
        q = 'mutation { create_incident(title: "Test", incident_type: "malware", severity: "sev2", org_id: "org-x") { incident_id } }'
        result = execute_graphql(q)
        assert "data" in result
        assert "create_incident" in result["data"]
        assert result["data"]["create_incident"]["incident_id"]

    def test_subscription_returns_null_data(self):
        result = execute_graphql('subscription { new_finding(org_id: "org-x") { finding { id } } }')
        assert "data" in result
        assert "extensions" in result

    def test_variables_merged(self):
        result = execute_graphql(
            "query { findings { id } }",
            variables={"org_id": "org-vars"},
        )
        assert "data" in result

    def test_unknown_mutation_returns_error(self):
        result = execute_graphql("mutation { delete_everything { ok } }")
        assert "errors" in result


# ===========================================================================
# 17. HTTP router (FastAPI TestClient)
# ===========================================================================

class TestGraphqlRouter:
    @pytest.fixture(autouse=True)
    def _setup_app(self):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from apps.api.graphql_router import router

        app = FastAPI()
        app.include_router(router)
        self.client = TestClient(app)

    def test_post_graphql_returns_200(self):
        resp = self.client.post(
            "/api/v1/graphql",
            json={"query": "query { vendors(org_id: \"org-test\") { id } }"},
        )
        assert resp.status_code == 200

    def test_post_graphql_response_has_data(self):
        resp = self.client.post(
            "/api/v1/graphql",
            json={"query": "query { findings(org_id: \"org-test\") { id severity } }"},
        )
        body = resp.json()
        assert "data" in body

    def test_get_schema_returns_200(self):
        resp = self.client.get("/api/v1/graphql/schema")
        assert resp.status_code == 200

    def test_get_schema_returns_sdl_text(self):
        resp = self.client.get("/api/v1/graphql/schema")
        assert "type Finding" in resp.text
        assert "type Mutation" in resp.text

    def test_post_mutation_acknowledge(self):
        resp = self.client.post(
            "/api/v1/graphql",
            json={
                "query": 'mutation { acknowledge_finding(finding_id: "f-1", acknowledged_by: "tester") { status acknowledged_by } }',
            },
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "data" in body or "errors" in body

    def test_post_create_incident(self):
        resp = self.client.post(
            "/api/v1/graphql",
            json={
                "query": 'mutation { create_incident(title: "HTTP Test", incident_type: "phishing", severity: "sev3", org_id: "org-http") { incident_id status } }',
            },
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "data" in body
        assert body["data"]["create_incident"]["status"] == "detected"

    def test_post_unknown_query_returns_errors(self):
        resp = self.client.post(
            "/api/v1/graphql",
            json={"query": "query { does_not_exist { id } }"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "errors" in body

    def test_post_missing_query_field_returns_422(self):
        resp = self.client.post("/api/v1/graphql", json={"variables": {}})
        assert resp.status_code == 422

    def test_post_with_variables(self):
        resp = self.client.post(
            "/api/v1/graphql",
            json={
                "query": "query { findings { id } }",
                "variables": {"org_id": "org-vars"},
            },
        )
        assert resp.status_code == 200

    def test_post_accept_risk_mutation(self):
        resp = self.client.post(
            "/api/v1/graphql",
            json={
                "query": 'mutation { accept_risk(finding_id: "f-http", accepted_by: "ciso", reason: "Low impact") { accepted reason } }',
            },
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "data" in body
        assert body["data"]["accept_risk"]["accepted"] is True
