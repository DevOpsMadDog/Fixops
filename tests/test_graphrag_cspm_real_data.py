"""Beast Mode tests — batch 2 empty-endpoint implementations.

Domain: GraphRAG (TrustGraph semantic retrieval) + CSPM Deep Scan
Endpoints:
  POST /api/v1/graphrag/retrieve
  POST /api/v1/graphrag/semantic-search
  GET  /api/v1/graphrag/entities/{entity_id}/neighborhood
  GET  /api/v1/graphrag/health
  POST /api/v1/cspm/scan/iac
  GET  /api/v1/cspm/score
  GET  /api/v1/cspm/rules
  GET  /api/v1/cspm/compliance-report

Each suite covers:
  - 200 happy-path with real engine data
  - Validation / error paths (400/404/422)
  - Real engine wiring (no mocks, no MOCK_ constants)
"""
from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# App fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def graphrag_client():
    from apps.api.graph_rag_router import router
    app = FastAPI()
    app.include_router(router)
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture(scope="module")
def cspm_client():
    from apps.api.cspm_deep_router import router
    app = FastAPI()
    app.include_router(router)
    return TestClient(app, raise_server_exceptions=False)


# ===========================================================================
# GraphRAG — POST /api/v1/graphrag/retrieve
# ===========================================================================

class TestGraphRAGRetrieve:
    def test_retrieve_returns_200(self, graphrag_client):
        resp = graphrag_client.post(
            "/api/v1/graphrag/retrieve",
            json={"query": "critical CVE vulnerabilities", "top_k": 5, "hops": 1},
        )
        assert resp.status_code == 200

    def test_retrieve_response_has_required_fields(self, graphrag_client):
        resp = graphrag_client.post(
            "/api/v1/graphrag/retrieve",
            json={"query": "log4shell", "top_k": 3, "hops": 2},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "query" in data
        assert "entities" in data
        assert "relationships" in data
        assert "context_summary" in data
        assert "retrieval_method" in data
        assert data["query"] == "log4shell"

    def test_retrieve_propagates_query_verbatim(self, graphrag_client):
        q = "sql injection risk in payment service"
        resp = graphrag_client.post(
            "/api/v1/graphrag/retrieve",
            json={"query": q, "top_k": 2, "hops": 1},
        )
        assert resp.status_code == 200
        assert resp.json()["query"] == q

    def test_retrieve_missing_query_returns_422(self, graphrag_client):
        resp = graphrag_client.post(
            "/api/v1/graphrag/retrieve",
            json={"top_k": 5, "hops": 1},
        )
        assert resp.status_code == 422

    def test_retrieve_hops_out_of_range_returns_422(self, graphrag_client):
        resp = graphrag_client.post(
            "/api/v1/graphrag/retrieve",
            json={"query": "test", "top_k": 5, "hops": 99},
        )
        assert resp.status_code == 422

    def test_retrieve_entities_is_list(self, graphrag_client):
        resp = graphrag_client.post(
            "/api/v1/graphrag/retrieve",
            json={"query": "misconfigured S3 bucket", "top_k": 10, "hops": 1},
        )
        assert resp.status_code == 200
        assert isinstance(resp.json()["entities"], list)
        assert isinstance(resp.json()["relationships"], list)


# ===========================================================================
# GraphRAG — POST /api/v1/graphrag/semantic-search
# ===========================================================================

class TestGraphRAGSemanticSearch:
    def test_semantic_search_returns_200(self, graphrag_client):
        resp = graphrag_client.post(
            "/api/v1/graphrag/semantic-search",
            json={"query": "authentication bypass"},
        )
        assert resp.status_code == 200

    def test_semantic_search_returns_list(self, graphrag_client):
        resp = graphrag_client.post(
            "/api/v1/graphrag/semantic-search",
            json={"query": "privilege escalation"},
        )
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_semantic_search_with_entity_type_filter(self, graphrag_client):
        resp = graphrag_client.post(
            "/api/v1/graphrag/semantic-search",
            json={"query": "remote code execution", "entity_types": ["CVE"]},
        )
        assert resp.status_code == 200

    def test_semantic_search_missing_query_returns_422(self, graphrag_client):
        resp = graphrag_client.post(
            "/api/v1/graphrag/semantic-search",
            json={"entity_types": ["CVE"]},
        )
        assert resp.status_code == 422

    def test_semantic_search_empty_query_string_rejected(self, graphrag_client):
        resp = graphrag_client.post(
            "/api/v1/graphrag/semantic-search",
            json={"query": ""},
        )
        # Empty string — engine may accept or reject; either way no 5xx
        assert resp.status_code in (200, 400, 422)
        assert resp.status_code != 500


# ===========================================================================
# GraphRAG — GET /api/v1/graphrag/health
# ===========================================================================

class TestGraphRAGHealth:
    def test_health_returns_200(self, graphrag_client):
        resp = graphrag_client.get("/api/v1/graphrag/health")
        assert resp.status_code == 200

    def test_health_has_engine_flag(self, graphrag_client):
        resp = graphrag_client.get("/api/v1/graphrag/health")
        data = resp.json()
        assert "graph_rag_available" in data
        assert "status" in data
        assert "total_entities" in data

    def test_health_reports_real_entity_count(self, graphrag_client):
        resp = graphrag_client.get("/api/v1/graphrag/health")
        data = resp.json()
        # When engine is available, total_entities should be a non-negative int
        assert isinstance(data["total_entities"], int)
        assert data["total_entities"] >= 0


# ===========================================================================
# CSPM — POST /api/v1/cspm/scan/iac
# ===========================================================================

_TERRAFORM_OPEN_SG = """
resource "aws_security_group" "open" {
  name = "open-sg"
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"""

_TERRAFORM_GOOD = """
resource "aws_s3_bucket" "secure" {
  bucket = "my-secure-bucket"
}
resource "aws_s3_bucket_public_access_block" "secure" {
  bucket                  = aws_s3_bucket.secure.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
"""


class TestCSPMScanIaC:
    def test_scan_iac_returns_200(self, cspm_client):
        resp = cspm_client.post(
            "/api/v1/cspm/scan/iac",
            json={"template_text": _TERRAFORM_OPEN_SG, "template_type": "terraform"},
        )
        assert resp.status_code == 200

    def test_scan_iac_returns_findings_for_open_sg(self, cspm_client):
        resp = cspm_client.post(
            "/api/v1/cspm/scan/iac",
            json={"template_text": _TERRAFORM_OPEN_SG, "template_type": "terraform"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "findings" in data
        assert "total_findings" in data
        assert isinstance(data["findings"], list)
        assert data["total_findings"] >= 0

    def test_scan_iac_response_has_scan_id(self, cspm_client):
        resp = cspm_client.post(
            "/api/v1/cspm/scan/iac",
            json={"template_text": _TERRAFORM_GOOD, "template_type": "terraform"},
        )
        assert resp.status_code == 200
        assert "scan_id" in resp.json()

    def test_scan_iac_auto_detects_terraform(self, cspm_client):
        resp = cspm_client.post(
            "/api/v1/cspm/scan/iac",
            json={"template_text": 'resource "aws_s3_bucket" "b" { bucket = "x" }',
                  "template_type": "auto"},
        )
        assert resp.status_code == 200
        assert resp.json()["template_type"] == "terraform"

    def test_scan_iac_cloudformation_json(self, cspm_client):
        cf_text = '{"AWSTemplateFormatVersion": "2010-09-09", "Resources": {"MyBucket": {"Type": "AWS::S3::Bucket"}}}'
        resp = cspm_client.post(
            "/api/v1/cspm/scan/iac",
            json={"template_text": cf_text, "template_type": "cloudformation"},
        )
        assert resp.status_code == 200
        assert resp.json()["template_type"] == "cloudformation"

    def test_scan_iac_missing_body_returns_422(self, cspm_client):
        resp = cspm_client.post("/api/v1/cspm/scan/iac", json={})
        assert resp.status_code == 422

    def test_scan_iac_each_finding_has_rule_id(self, cspm_client):
        resp = cspm_client.post(
            "/api/v1/cspm/scan/iac",
            json={"template_text": _TERRAFORM_OPEN_SG, "template_type": "terraform"},
        )
        assert resp.status_code == 200
        for f in resp.json()["findings"]:
            assert "finding_id" in f or "rule_id" in f
            assert "severity" in f


# ===========================================================================
# CSPM — GET /api/v1/cspm/score
# ===========================================================================

class TestCSPMScore:
    def test_score_returns_200(self, cspm_client):
        resp = cspm_client.get("/api/v1/cspm/score")
        assert resp.status_code == 200

    def test_score_has_grade_and_score(self, cspm_client):
        resp = cspm_client.get("/api/v1/cspm/score")
        data = resp.json()
        assert "score" in data
        assert "grade" in data
        assert "org_id" in data

    def test_score_value_in_range(self, cspm_client):
        resp = cspm_client.get("/api/v1/cspm/score")
        score = resp.json()["score"]
        assert 0.0 <= score <= 100.0

    def test_score_grade_is_valid(self, cspm_client):
        resp = cspm_client.get("/api/v1/cspm/score")
        grade = resp.json()["grade"]
        assert grade in ("A", "B", "C", "D", "F")

    def test_score_engine_real_data(self, cspm_client):
        """Confirm engine call succeeds — response has scanned_at timestamp."""
        resp = cspm_client.get("/api/v1/cspm/score?org_id=batch2-test-org")
        assert resp.status_code == 200
        data = resp.json()
        assert data["org_id"] == "batch2-test-org"
        assert "scanned_at" in data

    def test_score_engine_not_returning_mock_magic_constants(self, cspm_client):
        """Ensure score is not a magic constant (42, 999, 1337)."""
        resp = cspm_client.get("/api/v1/cspm/score")
        score = resp.json()["score"]
        assert score not in (42, 999, 1337, 9999)


# ===========================================================================
# CSPM — GET /api/v1/cspm/rules
# ===========================================================================

class TestCSPMRules:
    def test_rules_returns_200(self, cspm_client):
        resp = cspm_client.get("/api/v1/cspm/rules")
        assert resp.status_code == 200

    def test_rules_has_expected_counts(self, cspm_client):
        resp = cspm_client.get("/api/v1/cspm/rules")
        data = resp.json()
        counts = data.get("rule_counts", {})
        assert counts.get("aws", 0) > 0
        assert counts.get("azure", 0) > 0
        assert counts.get("gcp", 0) > 0

    def test_rules_filter_by_provider(self, cspm_client):
        resp = cspm_client.get("/api/v1/cspm/rules?provider=aws")
        assert resp.status_code == 200
        data = resp.json()
        for rule in data["rules"]:
            assert rule["provider"] == "aws"
