"""Tests for CIS Benchmark XCCDF importer.

Covers:
1. Parse a 10-control fixture XCCDF doc
2. NIST/ISO mapping extraction works
3. Severity bucketing
4. List endpoint returns controls after import
5. Filter by profile=L1 and severity=high
6. Idempotent re-import (no duplicate rows)
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from textwrap import dedent

import pytest

# ---------------------------------------------------------------------------
# Path setup — suite-feeds, suite-core, suite-api must be importable
# ---------------------------------------------------------------------------
REPO_ROOT = Path(__file__).resolve().parent.parent
for _sub in ("suite-feeds", "suite-core", "suite-api"):
    _p = str(REPO_ROOT / _sub)
    if _p not in sys.path:
        sys.path.insert(0, _p)

from feeds.cis_benchmark.importer import (  # noqa: E402
    CisBenchmarkImporter,
    parse_xccdf,
    _reset_conn,
)


# ---------------------------------------------------------------------------
# Fixture: 10-control XCCDF doc with NIST + ISO references, two profiles
# ---------------------------------------------------------------------------

_FIXTURE_XML = dedent("""\
<?xml version="1.0" encoding="UTF-8"?>
<Benchmark id="xccdf_org.cisecurity.benchmarks_benchmark_CIS_AWS_v1.5.0"
           xmlns="http://checklists.nist.gov/xccdf/1.2">
  <title>CIS Amazon Web Services Foundations Benchmark</title>
  <version>1.5.0</version>

  <Profile id="xccdf_org.cisecurity.benchmarks_profile_Level_1">
    <title>Level 1 - AWS Foundations</title>
    <select idref="rule_1_1" selected="true"/>
    <select idref="rule_1_2" selected="true"/>
    <select idref="rule_1_3" selected="true"/>
    <select idref="rule_2_1" selected="true"/>
    <select idref="rule_3_1" selected="true"/>
    <select idref="rule_4_1" selected="true"/>
  </Profile>

  <Profile id="xccdf_org.cisecurity.benchmarks_profile_Level_2">
    <title>Level 2 - AWS Foundations</title>
    <select idref="rule_1_1" selected="true"/>
    <select idref="rule_1_2" selected="true"/>
    <select idref="rule_1_3" selected="true"/>
    <select idref="rule_2_1" selected="true"/>
    <select idref="rule_3_1" selected="true"/>
    <select idref="rule_4_1" selected="true"/>
    <select idref="rule_5_1" selected="true"/>
    <select idref="rule_5_2" selected="true"/>
    <select idref="rule_6_1" selected="true"/>
    <select idref="rule_6_2" selected="true"/>
  </Profile>

  <Group id="grp_iam">
    <title>1 Identity and Access Management</title>
    <Rule id="rule_1_1" severity="high">
      <title>Maintain current contact details</title>
      <description>Ensure contact email is monitored.</description>
      <reference href="https://csrc.nist.gov/projects/risk-management/sp800-53-controls">NIST 800-53: AC-2, AC-3</reference>
      <reference href="https://www.iso.org/standard/27001">ISO 27001: A.9.2.1</reference>
      <check>
        <check-content>aws iam get-account-summary</check-content>
      </check>
      <fixtext>Update contact details in AWS account settings.</fixtext>
    </Rule>
    <Rule id="rule_1_2" severity="medium">
      <title>Ensure security questions are registered</title>
      <description>Security questions must be set.</description>
      <reference href="">NIST 800-53: IA-5</reference>
      <reference href="">ISO 27001: A.9.4.3</reference>
      <check><check-content>Manual review</check-content></check>
      <fixtext>Configure security questions.</fixtext>
    </Rule>
    <Rule id="rule_1_3" severity="high">
      <title>Ensure no root access keys exist</title>
      <description>Root account must not have active access keys.</description>
      <reference>NIST 800-53: AC-6(7)</reference>
      <reference>ISO 27001: A.9.2.3</reference>
      <check><check-content>aws iam list-access-keys</check-content></check>
      <fixtext>Delete root access keys.</fixtext>
    </Rule>
  </Group>

  <Group id="grp_logging">
    <title>2 Logging</title>
    <Rule id="rule_2_1" severity="high">
      <title>Ensure CloudTrail is enabled in all regions</title>
      <description>CloudTrail multi-region trail required.</description>
      <reference>NIST 800-53: AU-2</reference>
      <reference>ISO 27001: A.12.4.1</reference>
      <check><check-content>aws cloudtrail describe-trails</check-content></check>
      <fixtext>Enable multi-region CloudTrail.</fixtext>
    </Rule>
  </Group>

  <Group id="grp_monitoring">
    <title>3 Monitoring</title>
    <Rule id="rule_3_1" severity="medium">
      <title>Ensure log metric filter for unauthorized API calls</title>
      <description>Unauthorized API call metric filter required.</description>
      <reference>NIST 800-53: SI-4</reference>
      <reference>ISO 27001: A.12.4.1</reference>
      <check><check-content>aws logs describe-metric-filters</check-content></check>
      <fixtext>Create CloudWatch metric filter.</fixtext>
    </Rule>
  </Group>

  <Group id="grp_networking">
    <title>4 Networking</title>
    <Rule id="rule_4_1" severity="high">
      <title>Ensure no security groups allow ingress from 0.0.0.0/0 to port 22</title>
      <description>SSH must not be open to the world.</description>
      <reference>NIST 800-53: SC-7(3)</reference>
      <reference>ISO 27001: A.13.1.3</reference>
      <check><check-content>aws ec2 describe-security-groups</check-content></check>
      <fixtext>Restrict SSH ingress.</fixtext>
    </Rule>
  </Group>

  <Group id="grp_storage">
    <title>5 Storage</title>
    <Rule id="rule_5_1" severity="medium">
      <title>Ensure S3 bucket policy denies HTTP requests</title>
      <description>S3 buckets must enforce TLS.</description>
      <reference>NIST 800-53: SC-8</reference>
      <reference>ISO 27001: A.13.2.1</reference>
      <check><check-content>aws s3api get-bucket-policy</check-content></check>
      <fixtext>Add Deny policy for non-TLS requests.</fixtext>
    </Rule>
    <Rule id="rule_5_2" severity="low">
      <title>Ensure MFA Delete is enabled on S3 buckets</title>
      <description>MFA Delete adds extra protection.</description>
      <reference>NIST 800-53: AC-3</reference>
      <reference>ISO 27001: A.9.4.2</reference>
      <check><check-content>aws s3api get-bucket-versioning</check-content></check>
      <fixtext>Enable MFA Delete.</fixtext>
    </Rule>
  </Group>

  <Group id="grp_databases">
    <title>6 Databases</title>
    <Rule id="rule_6_1" severity="informational">
      <title>Ensure RDS instances are encrypted</title>
      <description>Storage encryption at rest required.</description>
      <reference>NIST 800-53: SC-28</reference>
      <reference>ISO 27001: A.10.1.1</reference>
      <check><check-content>aws rds describe-db-instances</check-content></check>
      <fixtext>Enable storage encryption.</fixtext>
    </Rule>
    <Rule id="rule_6_2" severity="medium">
      <title>Ensure RDS instances have backup retention &gt;= 7 days</title>
      <description>Sufficient backup window required.</description>
      <reference>NIST 800-53: CP-9</reference>
      <reference>ISO 27001: A.12.3.1</reference>
      <check><check-content>aws rds describe-db-instances</check-content></check>
      <fixtext>Configure backup retention period.</fixtext>
    </Rule>
  </Group>
</Benchmark>
""")


@pytest.fixture
def fixture_path(tmp_path):
    p = tmp_path / "cis_aws_fixture.xml"
    p.write_text(_FIXTURE_XML, encoding="utf-8")
    return str(p)


@pytest.fixture
def db_path(tmp_path):
    path = str(tmp_path / "test_cis_benchmark.db")
    yield path
    _reset_conn(path)


@pytest.fixture
def importer(db_path, fixture_path):
    return CisBenchmarkImporter(db_path=db_path, file_path=fixture_path)


# ---------------------------------------------------------------------------
# Test 1: Parse a 10-control fixture XCCDF doc
# ---------------------------------------------------------------------------

def test_parse_ten_controls():
    parsed = parse_xccdf(_FIXTURE_XML.encode("utf-8"))
    assert len(parsed["benchmarks"]) == 1
    bench = parsed["benchmarks"][0]
    assert bench["id"] == "xccdf_org.cisecurity.benchmarks_benchmark_CIS_AWS_v1.5.0"
    assert bench["version"] == "1.5.0"
    assert bench["rule_count"] == 10
    assert len(parsed["controls"]) == 10

    rule_ids = {c["control_id"] for c in parsed["controls"]}
    expected = {f"rule_{m}_{n}" for m, n in [
        (1, 1), (1, 2), (1, 3),
        (2, 1),
        (3, 1),
        (4, 1),
        (5, 1), (5, 2),
        (6, 1), (6, 2),
    ]}
    assert rule_ids == expected


# ---------------------------------------------------------------------------
# Test 2: NIST/ISO mapping extraction
# ---------------------------------------------------------------------------

def test_nist_iso_mappings_extracted():
    parsed = parse_xccdf(_FIXTURE_XML.encode("utf-8"))
    by_id = {c["control_id"]: c for c in parsed["controls"]}

    ssh_rule = by_id["rule_4_1"]
    assert "SC-7(3)" in ssh_rule["nist_references"]
    assert "13.1.3" in ssh_rule["iso_references"]

    iam_rule = by_id["rule_1_1"]
    assert "AC-2" in iam_rule["nist_references"]
    assert "AC-3" in iam_rule["nist_references"]
    assert "9.2.1" in iam_rule["iso_references"]

    rds_enc = by_id["rule_6_1"]
    assert "SC-28" in rds_enc["nist_references"]
    assert "10.1.1" in rds_enc["iso_references"]


# ---------------------------------------------------------------------------
# Test 3: Severity bucketing
# ---------------------------------------------------------------------------

def test_severity_bucketing(importer):
    result = importer.run(idempotent=True)
    by_sev = result["by_severity"]
    # Fixture: 4 high (1_1, 1_3, 2_1, 4_1), 4 medium (1_2, 3_1, 5_1, 6_2),
    # 1 low (5_2), 1 informational (6_1)
    assert by_sev["high"] == 4
    assert by_sev["medium"] == 4
    assert by_sev["low"] == 1
    assert by_sev["informational"] == 1

    # All buckets are in the canonical set
    assert set(by_sev.keys()).issubset(
        {"informational", "low", "medium", "high", "unknown"}
    )


# ---------------------------------------------------------------------------
# Test 4: List endpoint returns controls after import
# ---------------------------------------------------------------------------

def test_list_after_import(importer):
    importer.run(idempotent=True)

    page = importer.list_controls(page=1, page_size=100)
    assert page["total"] == 10
    assert len(page["entries"]) == 10

    sample = page["entries"][0]
    for key in (
        "benchmark_id", "benchmark_version", "control_id", "control_title",
        "audit", "remediation", "severity", "profiles",
        "nist_references", "iso_references", "all_references", "imported_at",
    ):
        assert key in sample, f"Missing field: {key}"

    # Pagination
    half = importer.list_controls(page=1, page_size=5)
    assert len(half["entries"]) == 5
    assert half["total"] == 10


# ---------------------------------------------------------------------------
# Test 5: Filter by profile=L1 and severity=high
# ---------------------------------------------------------------------------

def test_filter_l1_and_high(importer):
    importer.run(idempotent=True)

    # L1 profile selects 6 rules: 1_1, 1_2, 1_3, 2_1, 3_1, 4_1
    l1 = importer.list_controls(profile="L1", page_size=100)
    l1_ids = {e["control_id"] for e in l1["entries"]}
    assert l1_ids == {"rule_1_1", "rule_1_2", "rule_1_3", "rule_2_1", "rule_3_1", "rule_4_1"}

    # severity=high alone — 4 controls
    highs = importer.list_controls(severity="high", page_size=100)
    high_ids = {e["control_id"] for e in highs["entries"]}
    assert high_ids == {"rule_1_1", "rule_1_3", "rule_2_1", "rule_4_1"}
    for e in highs["entries"]:
        assert e["severity"] == "high"

    # Combined: L1 AND high — should be the intersection (1_1, 1_3, 2_1, 4_1)
    combined = importer.list_controls(profile="L1", severity="high", page_size=100)
    combined_ids = {e["control_id"] for e in combined["entries"]}
    assert combined_ids == {"rule_1_1", "rule_1_3", "rule_2_1", "rule_4_1"}


# ---------------------------------------------------------------------------
# Bonus: 501 stub is gone — POST /import-cis returns real result with file_path
# ---------------------------------------------------------------------------

def test_import_cis_endpoint_no_longer_501(monkeypatch, fixture_path, tmp_path):
    """The POST /api/v1/posture-benchmarking/import-cis endpoint must not 501."""
    os.environ["FIXOPS_MODE"] = "demo"
    monkeypatch.setenv("FIXOPS_MODE", "demo")
    db_path = str(tmp_path / "endpoint_cis.db")

    from apps.api import security_posture_benchmarking_router as router_mod
    from apps.api.auth_deps import api_key_auth
    from feeds.cis_benchmark.importer import CisBenchmarkImporter

    def _factory(file_path=None, url=None):
        return CisBenchmarkImporter(
            db_path=db_path,
            file_path=file_path or fixture_path,
            url=url,
        )

    monkeypatch.setattr(router_mod, "_get_cis_importer", _factory)

    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    app = FastAPI()
    app.include_router(router_mod.router)
    app.dependency_overrides[api_key_auth] = lambda: None
    client = TestClient(app)

    resp = client.post(
        "/api/v1/posture-benchmarking/import-cis",
        json={"file_path": fixture_path, "idempotent": True},
    )
    assert resp.status_code != 501, f"Endpoint still 501: {resp.json()}"
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["benchmarks"] == 1
    assert body["controls"] == 10
    assert "by_severity" in body
    assert "by_profile" in body


# ---------------------------------------------------------------------------
# Test 6: Idempotent re-import (no duplicates)
# ---------------------------------------------------------------------------

def test_idempotent_reimport(importer):
    first = importer.run(idempotent=True)
    assert first["imported"] == 10
    assert first["skipped"] == 0
    assert first["controls"] == 10

    second = importer.run(idempotent=True)
    assert second["imported"] == 0
    assert second["skipped"] == 10
    assert second["controls"] == 10

    assert importer.total_count() == 10
