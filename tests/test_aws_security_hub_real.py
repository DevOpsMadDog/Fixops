"""
Real-boto3 tests for AWSSecurityHubClient using botocore.stub.Stubber.

These exercise the actual boto3 code path (no mock data) by injecting
canned ASFF responses through Stubber. Proves the client speaks
GetFindings + pagination correctly and normalizes ASFF properly.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List

import pytest

# ── Environment setup ──────────────────────────────────────────────────────
os.environ.setdefault("FIXOPS_MODE", "enterprise")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

# Mask any developer ~/.aws so unconfigured tests are deterministic.
os.environ["AWS_SHARED_CREDENTIALS_FILE"] = "/dev/null"
os.environ["AWS_CONFIG_FILE"] = "/dev/null"
for _k in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
           "AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_SESSION_TOKEN"):
    os.environ.pop(_k, None)

boto3 = pytest.importorskip("boto3")
botocore_stub = pytest.importorskip("botocore.stub")
Stubber = botocore_stub.Stubber


# ── Helpers ────────────────────────────────────────────────────────────────


def _asff(finding_id: str = "f-1", severity: str = "HIGH") -> Dict[str, Any]:
    """Build a minimal-valid ASFF finding accepted by boto3 GetFindings shape."""
    return {
        "SchemaVersion": "2018-10-08",
        "Id": f"arn:aws:securityhub:us-east-1:123456789012:finding/{finding_id}",
        "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/securityhub",
        "Region": "us-east-1",
        "GeneratorId": f"gen-{finding_id}",
        "AwsAccountId": "123456789012",
        "Types": ["Software and Configuration Checks/Industry/Test"],
        "CreatedAt": "2026-05-01T00:00:00.000Z",
        "UpdatedAt": "2026-05-01T00:00:00.000Z",
        "Severity": {"Label": severity, "Normalized": 70},
        "Title": f"Test finding {finding_id}",
        "Description": "Stubber-injected ASFF finding.",
        "Resources": [{
            "Type": "AwsAccount",
            "Id": "AWS::::Account:123456789012",
            "Partition": "aws",
            "Region": "us-east-1",
        }],
        "Compliance": {"Status": "FAILED"},
        "Workflow": {"Status": "NEW"},
        "RecordState": "ACTIVE",
    }


def _make_stubbed_client(findings_pages: List[List[Dict[str, Any]]]):
    """
    Return ``(AWSSecurityHubClient, Stubber)`` wired so that get_findings()
    yields the supplied pages in order, with NextToken chaining.
    """
    from core.aws_security_hub import AWSSecurityHubClient

    real_boto = boto3.client(
        "securityhub",
        region_name="us-east-1",
        aws_access_key_id="AKIAFAKE",
        aws_secret_access_key="fake-secret",
    )
    stubber = Stubber(real_boto)
    for idx, page in enumerate(findings_pages):
        is_last = idx == len(findings_pages) - 1
        resp: Dict[str, Any] = {"Findings": page}
        if not is_last:
            resp["NextToken"] = f"token-{idx + 1}"
        expected_params: Dict[str, Any] = {}
        if idx > 0:
            expected_params["NextToken"] = f"token-{idx}"
        stubber.add_response("get_findings", resp, expected_params)
    stubber.activate()

    client = AWSSecurityHubClient(
        region="us-east-1",
        access_key="AKIAFAKE",
        secret_key="fake-secret",
    )
    # Inject stubbed boto3 client
    client._client = real_boto
    return client, stubber


# ── Test 1 — unconfigured returns empty (NEVER mock data) ──────────────────


def test_unconfigured_returns_empty():
    """Without credentials, all reads return empty — never synthetic data."""
    from core.aws_security_hub import AWSSecurityHubClient

    client = AWSSecurityHubClient(access_key="", secret_key="")
    assert client.is_configured() is False
    assert client.get_findings() == []
    assert client.get_insights() == []
    assert client.get_standards_status() == {"standards": [], "is_mock": False}

    # Module exports no _MOCK_FINDINGS — assert the symbol is gone.
    import core.aws_security_hub as mod
    assert not hasattr(mod, "_MOCK_FINDINGS"), \
        "_MOCK_FINDINGS must be removed — NO MOCK DATA rule"


# ── Test 2 — real get_findings via Stubber ─────────────────────────────────


def test_real_get_findings_with_stubbed_response():
    """get_findings() calls real boto3 get_findings() and returns the ASFF page."""
    page = [_asff("f-1", "CRITICAL"), _asff("f-2", "HIGH")]
    client, stubber = _make_stubbed_client([page])
    try:
        findings = client.get_findings()
        assert len(findings) == 2
        assert findings[0]["Id"].endswith("/f-1")
        assert findings[0]["Severity"]["Label"] == "CRITICAL"
        assert findings[1]["Severity"]["Label"] == "HIGH"
        stubber.assert_no_pending_responses()
    finally:
        stubber.deactivate()


# ── Test 3 — pagination via NextToken ──────────────────────────────────────


def test_pagination_handles_next_token():
    """Multi-page responses are concatenated by following NextToken."""
    page_a = [_asff("a-1"), _asff("a-2")]
    page_b = [_asff("b-1")]
    page_c = [_asff("c-1"), _asff("c-2"), _asff("c-3")]
    client, stubber = _make_stubbed_client([page_a, page_b, page_c])
    try:
        findings = client.get_findings()
        # 2 + 1 + 3 = 6 across three pages
        assert len(findings) == 6
        ids = [f["Id"].rsplit("/", 1)[-1] for f in findings]
        assert ids == ["a-1", "a-2", "b-1", "c-1", "c-2", "c-3"]
        stubber.assert_no_pending_responses()
    finally:
        stubber.deactivate()


# ── Test 4 — ASFF normalization to UnifiedFinding ──────────────────────────


def test_normalize_asff_to_finding():
    """normalize_asff transforms ASFF dicts to UnifiedFinding dicts."""
    from core.aws_security_hub import AWSSecurityHubClient

    client = AWSSecurityHubClient(access_key="", secret_key="")
    raw = [
        _asff("crit-1", "CRITICAL"),
        _asff("info-1", "INFORMATIONAL"),
    ]
    normalized = client.normalize_asff(raw)
    assert len(normalized) == 2

    # Severity mapping
    sevs = {n["source_id"].rsplit("/", 1)[-1]: n["severity"] for n in normalized}
    assert sevs["crit-1"] == "critical"
    assert sevs["info-1"] == "info"

    # Field shape
    for n in normalized:
        assert n["source_tool"] == "aws_security_hub"
        assert n["aws_account_id"] == "123456789012"
        assert n["aws_region"] == "us-east-1"
        assert n["resource_type"] == "AwsAccount"
        assert "id" in n  # unique uuid
