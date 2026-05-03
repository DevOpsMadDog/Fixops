"""Tests for POST /api/v1/iac/policy/eval endpoint.

Covers:
- Terraform HCL evaluated against a passing policy
- Terraform HCL with a violation (missing encryption flag)
- Multi-rule policy: partial pass / partial fail
- Invalid operator returns 400
- Empty content (no parseable resources) returns pass with resources_found=0
- Response shape: policy_id, iac_format, verdict fields present
"""

from __future__ import annotations

import os
import sys

import pytest

# ---------------------------------------------------------------------------
# Env setup before any app import
# ---------------------------------------------------------------------------
os.environ.setdefault("FIXOPS_MODE", "enterprise")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-key")
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-secret-key-32-chars-minimum!")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

from fastapi import FastAPI
from fastapi.testclient import TestClient

# ---------------------------------------------------------------------------
# Build a minimal app with only the IaC router so we avoid the full
# multi-router create_app() timeout in the Beast Mode test harness.
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def client():
    from apps.api.iac_scanner_router import router as iac_router

    mini_app = FastAPI()
    # Wire auth bypass: override the dependency globally
    from apps.api.auth_deps import api_key_auth
    mini_app.dependency_overrides[api_key_auth] = lambda: None
    mini_app.include_router(iac_router)

    with TestClient(mini_app, raise_server_exceptions=True) as c:
        yield c


# ---------------------------------------------------------------------------
# IaC content fixtures
# ---------------------------------------------------------------------------

TF_ENCRYPTED = """
resource "aws_ebs_volume" "good" {
  availability_zone = "us-east-1a"
  size              = 40
  encrypted         = true
}
"""

TF_NOT_ENCRYPTED = """
resource "aws_ebs_volume" "bad" {
  availability_zone = "us-east-1a"
  size              = 40
  encrypted         = false
}
"""

# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

ENCRYPTION_RULE = {
    "rule_id": "TF-EBS-001",
    "name": "EBS volumes must be encrypted",
    "provider": "aws",
    "resource_type": "aws_ebs_volume",
    "property_path": "encrypted",
    "expected_value": True,
    "operator": "equals",
    "severity": "high",
}


def _eval(client, content, filename, rules, policy_id="test-policy"):
    return client.post(
        "/api/v1/iac/policy/eval",
        json={
            "content": content,
            "filename": filename,
            "policy_id": policy_id,
            "rules": rules,
        },
    )


# ---------------------------------------------------------------------------
# Tests: passing policy
# ---------------------------------------------------------------------------


class TestPolicyEvalPass:
    def test_returns_200(self, client):
        r = _eval(client, TF_ENCRYPTED, "main.tf", [ENCRYPTION_RULE])
        assert r.status_code == 200

    def test_verdict_pass_when_compliant(self, client):
        r = _eval(client, TF_ENCRYPTED, "main.tf", [ENCRYPTION_RULE])
        body = r.json()
        assert body["passed"] is True
        assert body["verdict"] == "pass"

    def test_no_violations_returned(self, client):
        r = _eval(client, TF_ENCRYPTED, "main.tf", [ENCRYPTION_RULE])
        assert r.json()["violations"] == []

    def test_resources_found_positive(self, client):
        r = _eval(client, TF_ENCRYPTED, "main.tf", [ENCRYPTION_RULE])
        assert r.json()["resources_found"] >= 1


# ---------------------------------------------------------------------------
# Tests: failing policy
# ---------------------------------------------------------------------------


class TestPolicyEvalFail:
    def test_verdict_fail_when_violation(self, client):
        r = _eval(client, TF_NOT_ENCRYPTED, "main.tf", [ENCRYPTION_RULE])
        body = r.json()
        assert body["passed"] is False
        assert body["verdict"] == "fail"

    def test_violation_contains_rule_id(self, client):
        r = _eval(client, TF_NOT_ENCRYPTED, "main.tf", [ENCRYPTION_RULE])
        rule_ids = [v["rule_id"] for v in r.json()["violations"]]
        assert "TF-EBS-001" in rule_ids

    def test_violation_resource_details_present(self, client):
        r = _eval(client, TF_NOT_ENCRYPTED, "main.tf", [ENCRYPTION_RULE])
        viols = r.json()["violations"]
        assert len(viols) > 0
        rv = viols[0]["resources_violated"]
        assert len(rv) > 0
        assert "resource_name" in rv[0]
        assert "actual_value" in rv[0]


# ---------------------------------------------------------------------------
# Tests: multi-rule / edge cases
# ---------------------------------------------------------------------------


class TestPolicyEvalMultiRule:
    def test_partial_fail_counts_correctly(self, client):
        rules = [
            ENCRYPTION_RULE,
            {
                "rule_id": "TF-EBS-002",
                "name": "EBS size check",
                "provider": "aws",
                "resource_type": "aws_ebs_volume",
                "property_path": "size",
                "expected_value": 100,
                "operator": "equals",
                "severity": "low",
            },
        ]
        # TF_ENCRYPTED: encrypted=true (passes rule1), size=40 (fails rule2)
        r = _eval(client, TF_ENCRYPTED, "main.tf", rules)
        body = r.json()
        assert body["rules_evaluated"] == 2
        assert body["rules_passed"] == 1
        assert body["rules_failed"] == 1
        assert body["passed"] is False


class TestPolicyEvalEdgeCases:
    def test_invalid_operator_returns_400(self, client):
        bad_rule = dict(ENCRYPTION_RULE)
        bad_rule["operator"] = "regex_match"
        r = _eval(client, TF_ENCRYPTED, "main.tf", [bad_rule])
        assert r.status_code == 400

    def test_empty_content_returns_pass_no_resources(self, client):
        r = _eval(client, "# empty terraform file\n", "empty.tf", [ENCRYPTION_RULE])
        body = r.json()
        assert r.status_code == 200
        assert body["resources_found"] == 0
        assert body["passed"] is True

    def test_response_contains_policy_id(self, client):
        r = _eval(client, TF_ENCRYPTED, "main.tf", [ENCRYPTION_RULE], policy_id="my-org-policy-v2")
        assert r.json()["policy_id"] == "my-org-policy-v2"

    def test_iac_format_detected_as_terraform(self, client):
        r = _eval(client, TF_ENCRYPTED, "main.tf", [ENCRYPTION_RULE])
        assert r.json()["iac_format"] == "terraform"
