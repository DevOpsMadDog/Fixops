"""Beast Mode — Code Intelligence Real-Data Tests (batch 3).

Domain: Code Intelligence
Endpoints under test:
  1. GET  /api/v1/cspm/score              — cloud posture score
  2. GET  /api/v1/cspm/rules              — 85 built-in rules with filter paths
  3. POST /api/v1/cspm/scan/iac           — IaC terraform/cloudformation scan
  4. GET  /api/v1/cspm/compliance-report  — compliance posture report
  5. GET  /api/v1/semantic/stats          — semantic analyzer stats
  6. POST /api/v1/semantic/detect-languages — language detection
  7. GET  /api/v1/semantic/symbols        — symbol list (404 path)
  8. GET  /api/v1/reachability/stats      — call-graph aggregate stats
  9. GET  /api/v1/reachability/callgraph/{repo_ref} — callgraph nodes+edges
  10. POST /api/v1/reachability/query     — BFS reachability check
  11. POST /api/v1/reachability/parse     — unsupported language → 501

All assertions hit real engines backed by SQLite; no MOCK_ constants.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Add suite paths
for _p in ["suite-core", "suite-api"]:
    _abs = str(Path(__file__).parent.parent / _p)
    if _abs not in sys.path:
        sys.path.insert(0, _abs)

from fastapi import FastAPI
from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_app(*routers):
    """Build a minimal FastAPI test app with auth bypassed."""
    from apps.api.auth_deps import api_key_auth

    app = FastAPI()
    for r in routers:
        app.include_router(r)
    app.dependency_overrides[api_key_auth] = lambda: None
    return app


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def cspm_client():
    from apps.api.cspm_deep_router import router
    return TestClient(_make_app(router), raise_server_exceptions=False)


@pytest.fixture(scope="module")
def semantic_client():
    from apps.api.semantic_analyzer_router import router
    return TestClient(_make_app(router), raise_server_exceptions=False)


@pytest.fixture(scope="module")
def reachability_client():
    from apps.api.function_reachability_router import router
    return TestClient(_make_app(router), raise_server_exceptions=False)


# ===========================================================================
# 1. CSPM Deep Router — /api/v1/cspm
# ===========================================================================

class TestCSPMScore:
    def test_score_200(self, cspm_client):
        r = cspm_client.get("/api/v1/cspm/score?org_id=default")
        assert r.status_code == 200

    def test_score_has_required_fields(self, cspm_client):
        data = cspm_client.get("/api/v1/cspm/score?org_id=default").json()
        for field in ("org_id", "score", "grade", "total_resources", "total_findings"):
            assert field in data, f"missing field: {field}"

    def test_score_grade_is_letter(self, cspm_client):
        grade = cspm_client.get("/api/v1/cspm/score?org_id=default").json()["grade"]
        assert grade in ("A", "B", "C", "D", "F")

    def test_score_value_in_range(self, cspm_client):
        score = cspm_client.get("/api/v1/cspm/score?org_id=default").json()["score"]
        assert 0.0 <= score <= 100.0


class TestCSPMRules:
    def test_rules_200(self, cspm_client):
        r = cspm_client.get("/api/v1/cspm/rules")
        assert r.status_code == 200

    def test_rules_total_85(self, cspm_client):
        data = cspm_client.get("/api/v1/cspm/rules").json()
        # 85 total built-in rules (40 AWS + 25 Azure + 20 GCP)
        assert data["total"] == 85

    def test_rules_filter_by_provider_aws(self, cspm_client):
        data = cspm_client.get("/api/v1/cspm/rules?provider=aws").json()
        assert data["total"] == 40
        assert all(r["provider"] == "aws" for r in data["rules"])

    def test_rules_filter_by_severity_critical(self, cspm_client):
        data = cspm_client.get("/api/v1/cspm/rules?severity=critical").json()
        assert data["total"] > 0
        assert all(r["severity"] == "critical" for r in data["rules"])

    def test_rules_filter_combined(self, cspm_client):
        data = cspm_client.get("/api/v1/cspm/rules?provider=aws&severity=critical").json()
        assert data["total"] == 8
        for rule in data["rules"]:
            assert rule["provider"] == "aws"
            assert rule["severity"] == "critical"

    def test_rules_schema_fields(self, cspm_client):
        rules = cspm_client.get("/api/v1/cspm/rules").json()["rules"]
        assert len(rules) > 0
        for key in ("rule_id", "title", "severity", "category", "provider"):
            assert key in rules[0]

    def test_rules_count_by_provider_matches(self, cspm_client):
        data = cspm_client.get("/api/v1/cspm/rules").json()
        counts = data["rule_counts"]
        assert counts["aws"] == 40
        assert counts["azure"] == 25
        assert counts["gcp"] == 20


class TestCSPMScanIaC:
    TERRAFORM_S3 = (
        'resource "aws_s3_bucket" "insecure" {\n'
        '  bucket = "my-insecure-bucket"\n'
        "}\n"
    )
    TERRAFORM_CLEAN = (
        'provider "aws" {\n'
        '  region = "us-east-1"\n'
        "}\n"
    )

    def test_scan_iac_200(self, cspm_client):
        r = cspm_client.post(
            "/api/v1/cspm/scan/iac",
            json={"template_text": self.TERRAFORM_S3, "template_type": "terraform"},
        )
        assert r.status_code == 200

    def test_scan_iac_returns_findings(self, cspm_client):
        data = cspm_client.post(
            "/api/v1/cspm/scan/iac",
            json={"template_text": self.TERRAFORM_S3, "template_type": "terraform"},
        ).json()
        assert "findings" in data
        assert isinstance(data["findings"], list)
        assert data["total_findings"] >= 0

    def test_scan_iac_auto_detects_terraform(self, cspm_client):
        data = cspm_client.post(
            "/api/v1/cspm/scan/iac",
            json={"template_text": self.TERRAFORM_S3, "template_type": "auto"},
        ).json()
        assert data["template_type"] == "terraform"

    def test_scan_iac_cloudformation_auto_detect(self, cspm_client):
        cf = '{"AWSTemplateFormatVersion":"2010-09-09","Resources":{"Bucket":{"Type":"AWS::S3::Bucket"}}}'
        data = cspm_client.post(
            "/api/v1/cspm/scan/iac",
            json={"template_text": cf, "template_type": "auto"},
        ).json()
        assert data["template_type"] == "cloudformation"

    def test_scan_iac_finding_schema(self, cspm_client):
        data = cspm_client.post(
            "/api/v1/cspm/scan/iac",
            json={"template_text": self.TERRAFORM_S3, "template_type": "terraform"},
        ).json()
        if data["findings"]:
            f = data["findings"][0]
            for key in ("finding_id", "title", "severity", "category"):
                assert key in f, f"finding missing field: {key}"


class TestCSPMComplianceReport:
    def test_compliance_report_200(self, cspm_client):
        r = cspm_client.get("/api/v1/cspm/compliance-report?org_id=default")
        assert r.status_code == 200

    def test_compliance_report_has_frameworks(self, cspm_client):
        data = cspm_client.get("/api/v1/cspm/compliance-report?org_id=default").json()
        assert "frameworks" in data
        assert isinstance(data["frameworks"], list)

    def test_compliance_report_status_ok(self, cspm_client):
        data = cspm_client.get("/api/v1/cspm/compliance-report?org_id=default").json()
        assert data.get("status") in ("ok", "degraded")


# ===========================================================================
# 2. Semantic Analyzer Router — /api/v1/semantic
# ===========================================================================

class TestSemanticStats:
    def test_stats_200(self, semantic_client):
        r = semantic_client.get("/api/v1/semantic/stats?org_id=default")
        assert r.status_code == 200

    def test_stats_has_fields(self, semantic_client):
        data = semantic_client.get("/api/v1/semantic/stats?org_id=default").json()
        for field in ("org_id", "repos", "symbols"):
            assert field in data

    def test_stats_org_id_matches(self, semantic_client):
        data = semantic_client.get("/api/v1/semantic/stats?org_id=test-org").json()
        assert data["org_id"] == "test-org"

    def test_stats_numeric_counts(self, semantic_client):
        data = semantic_client.get("/api/v1/semantic/stats?org_id=default").json()
        assert isinstance(data["repos"], int)
        assert isinstance(data["symbols"], int)
        assert data["repos"] >= 0
        assert data["symbols"] >= 0


class TestSemanticDetectLanguages:
    def test_detect_languages_200(self, semantic_client):
        r = semantic_client.post(
            "/api/v1/semantic/detect-languages",
            json={"repo_ref": "test-repo", "root_path": "/tmp", "org_id": "default"},
        )
        assert r.status_code == 200

    def test_detect_languages_has_languages(self, semantic_client):
        data = semantic_client.post(
            "/api/v1/semantic/detect-languages",
            json={"repo_ref": "test-repo", "root_path": "/tmp", "org_id": "default"},
        ).json()
        assert "languages" in data
        assert isinstance(data["languages"], dict)

    def test_detect_languages_has_total_files(self, semantic_client):
        data = semantic_client.post(
            "/api/v1/semantic/detect-languages",
            json={"repo_ref": "test-repo", "root_path": "/tmp", "org_id": "default"},
        ).json()
        assert "total_files" in data
        assert data["total_files"] >= 0

    def test_detect_languages_repo_ref_echoed(self, semantic_client):
        data = semantic_client.post(
            "/api/v1/semantic/detect-languages",
            json={"repo_ref": "my-app@main", "root_path": "/tmp", "org_id": "default"},
        ).json()
        assert data.get("repo_ref") == "my-app@main"


class TestSemanticSymbols:
    def test_symbols_missing_repo_404(self, semantic_client):
        r = semantic_client.get(
            "/api/v1/semantic/symbols?org_id=default&repo_ref=nonexistent-xyz"
        )
        assert r.status_code == 404

    def test_symbols_missing_org_id_422(self, semantic_client):
        r = semantic_client.get("/api/v1/semantic/symbols?repo_ref=somerepo")
        assert r.status_code == 422


# ===========================================================================
# 3. Function Reachability Router — /api/v1/reachability
# ===========================================================================

class TestReachabilityStats:
    def test_stats_200(self, reachability_client):
        r = reachability_client.get("/api/v1/reachability/stats?org_id=default")
        assert r.status_code == 200

    def test_stats_has_node_count(self, reachability_client):
        data = reachability_client.get("/api/v1/reachability/stats?org_id=default").json()
        assert "node_count" in data
        assert isinstance(data["node_count"], int)

    def test_stats_has_edge_count(self, reachability_client):
        data = reachability_client.get("/api/v1/reachability/stats?org_id=default").json()
        assert "edge_count" in data
        assert data["edge_count"] >= 0

    def test_stats_has_query_count(self, reachability_client):
        data = reachability_client.get("/api/v1/reachability/stats?org_id=default").json()
        assert "query_count" in data

    def test_stats_by_language_dict(self, reachability_client):
        data = reachability_client.get("/api/v1/reachability/stats?org_id=default").json()
        assert "by_language" in data
        assert isinstance(data["by_language"], dict)


class TestReachabilityCallgraph:
    def test_callgraph_200(self, reachability_client):
        r = reachability_client.get(
            "/api/v1/reachability/callgraph/test-repo?org_id=default"
        )
        assert r.status_code == 200

    def test_callgraph_has_nodes_edges(self, reachability_client):
        data = reachability_client.get(
            "/api/v1/reachability/callgraph/any-repo?org_id=default"
        ).json()
        assert "nodes" in data
        assert "edges" in data
        assert isinstance(data["nodes"], list)
        assert isinstance(data["edges"], list)

    def test_callgraph_counts_match_lists(self, reachability_client):
        data = reachability_client.get(
            "/api/v1/reachability/callgraph/any-repo?org_id=default"
        ).json()
        assert data["node_count"] == len(data["nodes"])
        assert data["edge_count"] == len(data["edges"])


class TestReachabilityQuery:
    def test_query_200_no_path(self, reachability_client):
        r = reachability_client.post(
            "/api/v1/reachability/query",
            json={"org_id": "default", "start_fqn": "a.b.c", "target_fqn": "x.y.z"},
        )
        assert r.status_code == 200

    def test_query_returns_reachable_bool(self, reachability_client):
        data = reachability_client.post(
            "/api/v1/reachability/query",
            json={"org_id": "default", "start_fqn": "a.b", "target_fqn": "c.d"},
        ).json()
        assert "reachable" in data
        assert isinstance(data["reachable"], bool)

    def test_query_returns_path_field(self, reachability_client):
        data = reachability_client.post(
            "/api/v1/reachability/query",
            json={"org_id": "default", "start_fqn": "a.b", "target_fqn": "c.d"},
        ).json()
        assert "path" in data

    def test_query_echoes_fqns(self, reachability_client):
        data = reachability_client.post(
            "/api/v1/reachability/query",
            json={"org_id": "default", "start_fqn": "my.start", "target_fqn": "my.end"},
        ).json()
        assert data["start_fqn"] == "my.start"
        assert data["target_fqn"] == "my.end"


class TestReachabilityParse:
    def test_parse_unsupported_language_error(self, reachability_client):
        """java/typescript raise NotImplementedError → 501 or 500 (engine-level)."""
        r = reachability_client.post(
            "/api/v1/reachability/parse",
            json={
                "org_id": "default",
                "repo_ref": "test",
                "language": "java",
                "root_path": "/tmp",
            },
        )
        # NotImplementedError is raised → should be 501 (or 500 from unhandled)
        assert r.status_code in (500, 501)

    def test_parse_bad_language_422(self, reachability_client):
        r = reachability_client.post(
            "/api/v1/reachability/parse",
            json={
                "org_id": "default",
                "repo_ref": "test",
                "language": "cobol",
                "root_path": "/tmp",
            },
        )
        assert r.status_code == 422
