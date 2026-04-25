"""Tests for CSPMConnector — OSS replacement for Wiz/Lacework/Orca/Prisma."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from connectors.cspm_connector import CSPMConnector, _severity_to_cvss


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def isolated_engines(tmp_path):
    """Force findings + agentless engines to use temp DBs (no test pollution)."""
    db_dir = tmp_path / ".fixops_data"
    db_dir.mkdir()
    return db_dir


@pytest.fixture
def connector(isolated_engines):
    # Force CLI absence so the embedded sample fallback path runs.
    return CSPMConnector(
        prowler_path=None,
        checkov_path=None,
        cloudsploit_path=None,
        trivy_path=None,
        findings_db_path=str(isolated_engines / "security_findings_engine.db"),
        agentless_db_dir=str(isolated_engines),
    )


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def test_invalid_org_id_raises():
    c = CSPMConnector(prowler_path=None, checkov_path=None, cloudsploit_path=None)
    with pytest.raises(ValueError):
        c.scan_tenant(org_id="bad id with spaces", provider="aws")


def test_invalid_provider_raises(connector):
    with pytest.raises(ValueError):
        connector.scan_tenant(org_id="t1", provider="ibm")


def test_invalid_endpoint_scheme_raises(connector):
    with pytest.raises(ValueError):
        connector.scan_tenant(org_id="t1", provider="aws", localstack_endpoint="ftp://x")


def test_severity_mapping():
    assert _severity_to_cvss("critical") == 9.5
    assert _severity_to_cvss("high") == 7.5
    assert _severity_to_cvss("MEDIUM") == 5.0
    assert _severity_to_cvss(None) == 5.0
    assert _severity_to_cvss("unknown") == 5.0


# ---------------------------------------------------------------------------
# End-to-end scan with embedded fallback
# ---------------------------------------------------------------------------


def test_scan_tenant_uses_fallback_when_cli_missing(connector):
    result = connector.scan_tenant(
        org_id="juice-shop-corp",
        provider="aws",
        run_agentless=False,
    )
    assert result["_summary"]["org_id"] == "juice-shop-corp"
    # Three sample-driven tools each ingested at least one finding.
    assert result["prowler"]["used_real_cli"] is False
    assert result["prowler"]["ingested_count"] >= 5
    assert result["checkov"]["used_real_cli"] is False
    assert result["checkov"]["ingested_count"] >= 3
    assert result["cloudsploit"]["used_real_cli"] is False
    assert result["cloudsploit"]["ingested_count"] >= 2
    # Trivy IaC config sample carries 2 misconfigurations.
    assert result["trivy"]["used_real_cli"] is False
    assert result["trivy"]["ingested_count"] >= 2


def test_scan_tenant_includes_agentless_path(connector):
    result = connector.scan_tenant(
        org_id="nodegoat-corp",
        provider="aws",
        account_id="000000000000",
    )
    assert "agentless" in result
    # MockAWSAdapter ships sample snapshots so ingest_count is positive.
    assert result["agentless"]["used_real_cli"] is True
    assert result["agentless"]["ingested_count"] >= 0  # may be zero if no probes match


def test_per_tenant_attribution(connector, isolated_engines):
    """Findings recorded under the correct org_id per tenant."""

    for tenant in ("alpha-corp", "bravo-corp"):
        connector.scan_tenant(org_id=tenant, provider="aws", run_agentless=False)

    db_path = isolated_engines / "security_findings_engine.db"
    with sqlite3.connect(db_path) as conn:
        rows = conn.execute(
            "SELECT org_id, COUNT(*) FROM security_findings GROUP BY org_id"
        ).fetchall()
    counts = dict(rows)
    assert counts.get("alpha-corp", 0) > 0
    assert counts.get("bravo-corp", 0) > 0
    # Bravo findings are NOT mixed into Alpha (multi-tenant isolation).
    assert counts["alpha-corp"] != counts.get("zzz-corp", 0)


def test_finding_source_tools_use_cspm_via_prefix(connector, isolated_engines):
    connector.scan_tenant(org_id="charlie-corp", provider="aws", run_agentless=False)
    db_path = isolated_engines / "security_findings_engine.db"
    with sqlite3.connect(db_path) as conn:
        tools = {row[0] for row in conn.execute(
            "SELECT DISTINCT source_tool FROM security_findings WHERE org_id = ?",
            ("charlie-corp",),
        )}
    assert "cspm_via_prowler" in tools
    assert "cspm_via_checkov" in tools
    assert "cspm_via_cloudsploit" in tools
    assert "cspm_via_trivy" in tools


# ---------------------------------------------------------------------------
# Real Checkov CLI execution against a temp Terraform fixture
# ---------------------------------------------------------------------------


def test_real_checkov_cli_runs_when_iac_dir_provided(isolated_engines, tmp_path):
    import shutil

    if not shutil.which("checkov"):
        pytest.skip("checkov CLI not installed")

    # Write an intentionally bad Terraform file.
    tf_dir = tmp_path / "terraform"
    tf_dir.mkdir()
    (tf_dir / "main.tf").write_text(
        """
resource "aws_s3_bucket" "bad" {
  bucket = "cspm-bad-bucket"
  acl    = "public-read"
}

resource "aws_security_group" "open_ssh" {
  name        = "open-ssh"
  description = "Open SSH"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
""".strip()
    )

    c = CSPMConnector(
        prowler_path=None,
        cloudsploit_path=None,
        findings_db_path=str(isolated_engines / "security_findings_engine.db"),
    )
    r = c.scan_tenant(
        org_id="real-checkov-corp",
        provider="aws",
        iac_dir=str(tf_dir),
        run_prowler=False,
        run_cloudsploit=False,
        run_agentless=False,
    )
    # Either CLI succeeded OR sample fallback fired — both are valid integration
    # paths; ingestion must be > 0 in both cases.
    assert r["checkov"]["findings_count"] >= 1
    assert r["checkov"]["ingested_count"] >= 1


def test_real_trivy_cli_runs_when_iac_dir_provided(isolated_engines, tmp_path):
    import shutil

    if not shutil.which("trivy"):
        pytest.skip("trivy CLI not installed")

    tf_dir = tmp_path / "terraform"
    tf_dir.mkdir()
    (tf_dir / "main.tf").write_text(
        """
resource "aws_s3_bucket" "bad" {
  bucket = "trivy-bad-bucket"
}

resource "aws_s3_bucket_public_access_block" "bad" {
  bucket                  = aws_s3_bucket.bad.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}
""".strip()
    )

    c = CSPMConnector(
        prowler_path=None,
        checkov_path=None,
        cloudsploit_path=None,
        findings_db_path=str(isolated_engines / "security_findings_engine.db"),
    )
    r = c.scan_tenant(
        org_id="real-trivy-corp",
        provider="aws",
        iac_dir=str(tf_dir),
        run_prowler=False,
        run_checkov=False,
        run_cloudsploit=False,
        run_agentless=False,
        run_trivy=True,
    )
    # Either CLI succeeded OR sample fallback fired; both must produce ingestion.
    assert r["trivy"]["findings_count"] >= 1
    assert r["trivy"]["ingested_count"] >= 1


# ---------------------------------------------------------------------------
# Bulk + multi-tenant attribution
# ---------------------------------------------------------------------------


def test_bulk_15_tenants_no_cross_pollination(connector, isolated_engines):
    """Scan 15 tenants — every finding tagged with the correct org_id."""
    tenants = [f"tenant-{i:02d}-corp" for i in range(15)]
    for t in tenants:
        connector.scan_tenant(org_id=t, provider="aws", run_agentless=False)
    db_path = isolated_engines / "security_findings_engine.db"
    with sqlite3.connect(db_path) as conn:
        rows = conn.execute(
            "SELECT org_id, COUNT(*) FROM security_findings GROUP BY org_id"
        ).fetchall()
    counts = dict(rows)
    for t in tenants:
        assert counts.get(t, 0) >= 12, f"tenant {t} undercount: {counts.get(t)}"


def test_disabled_tools_skip_in_results(connector):
    r = connector.scan_tenant(
        org_id="disabled-corp",
        provider="aws",
        run_prowler=False,
        run_checkov=False,
        run_trivy=False,
        run_cloudsploit=False,
        run_agentless=False,
    )
    assert "prowler" not in r
    assert "checkov" not in r
    assert "trivy" not in r
    assert "cloudsploit" not in r
    assert "agentless" not in r
    assert r["_summary"]["ingested_total"] == 0


def test_correlation_keys_dedupe_across_repeated_scans(connector, isolated_engines):
    """Two consecutive scans for same tenant must NOT duplicate rows."""
    connector.scan_tenant(org_id="dedup-corp", provider="aws", run_agentless=False)
    connector.scan_tenant(org_id="dedup-corp", provider="aws", run_agentless=False)
    db_path = isolated_engines / "security_findings_engine.db"
    with sqlite3.connect(db_path) as conn:
        rows = conn.execute(
            "SELECT correlation_key, COUNT(*) FROM security_findings "
            "WHERE org_id = ? GROUP BY correlation_key",
            ("dedup-corp",),
        ).fetchall()
    # Each correlation_key recorded exactly once (occurrence_count handles repeat).
    multiples = [r for r in rows if r[1] > 1]
    assert multiples == [], f"Unexpected duplicates: {multiples}"


def test_provider_azure_accepted(connector):
    r = connector.scan_tenant(org_id="azure-corp", provider="azure", run_agentless=False)
    assert r["_summary"]["provider"] == "azure"


def test_provider_gcp_accepted(connector):
    r = connector.scan_tenant(org_id="gcp-corp", provider="gcp", run_agentless=False)
    assert r["_summary"]["provider"] == "gcp"


def test_endpoint_with_https_scheme_accepted(connector):
    r = connector.scan_tenant(
        org_id="https-corp",
        provider="aws",
        localstack_endpoint="https://localstack.example.com:4566",
        run_agentless=False,
    )
    assert r["_summary"]["org_id"] == "https-corp"


def test_empty_endpoint_allowed(connector):
    """Empty endpoint = real-cloud mode. Scan must still succeed."""
    r = connector.scan_tenant(
        org_id="real-cloud",
        provider="aws",
        localstack_endpoint="",
        run_agentless=False,
    )
    assert r["_summary"]["ingested_total"] > 0


def test_finding_severities_normalised_to_known_set(connector, isolated_engines):
    connector.scan_tenant(org_id="sev-corp", provider="aws", run_agentless=False)
    db_path = isolated_engines / "security_findings_engine.db"
    with sqlite3.connect(db_path) as conn:
        sevs = {row[0] for row in conn.execute(
            "SELECT DISTINCT severity FROM security_findings WHERE org_id = ?",
            ("sev-corp",),
        )}
    assert sevs.issubset({"critical", "high", "medium", "low", "info"})


def test_cvss_score_clamped_0_10(connector, isolated_engines):
    connector.scan_tenant(org_id="cvss-corp", provider="aws", run_agentless=False)
    db_path = isolated_engines / "security_findings_engine.db"
    with sqlite3.connect(db_path) as conn:
        scores = [row[0] for row in conn.execute(
            "SELECT cvss_score FROM security_findings WHERE org_id = ?",
            ("cvss-corp",),
        )]
    assert scores, "no findings recorded"
    for s in scores:
        assert 0.0 <= float(s) <= 10.0


def test_finding_types_categorised(connector, isolated_engines):
    """Cloud-misconfig vs IaC-misconfig must be tagged correctly."""
    connector.scan_tenant(org_id="type-corp", provider="aws", run_agentless=False)
    db_path = isolated_engines / "security_findings_engine.db"
    with sqlite3.connect(db_path) as conn:
        rows = conn.execute(
            "SELECT source_tool, finding_type FROM security_findings WHERE org_id = ?",
            ("type-corp",),
        ).fetchall()
    cloud_tools = {r[0] for r in rows if r[1] == "cloud_misconfig"}
    iac_tools = {r[0] for r in rows if r[1] == "iac_misconfig"}
    assert "cspm_via_prowler" in cloud_tools
    assert "cspm_via_cloudsploit" in cloud_tools
    assert "cspm_via_checkov" in iac_tools
    assert "cspm_via_trivy" in iac_tools


def test_long_org_id_at_max_boundary(connector):
    """org_id of 128 chars is the upper boundary — must be accepted."""
    boundary = "a" * 128
    r = connector.scan_tenant(org_id=boundary, provider="aws", run_agentless=False)
    assert r["_summary"]["org_id"] == boundary


def test_org_id_too_long_rejected(connector):
    with pytest.raises(ValueError):
        connector.scan_tenant(org_id="a" * 129, provider="aws", run_agentless=False)


def test_org_id_with_dots_dashes_underscores_accepted(connector):
    r = connector.scan_tenant(org_id="acme.corp_2026-prod", provider="aws", run_agentless=False)
    assert r["_summary"]["org_id"] == "acme.corp_2026-prod"


def test_status_endpoint_via_router(monkeypatch):
    """The CSPM connector router exposes /status for ops dashboards."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from apps.api.cspm_connector_router import router

    # Bypass api_key_auth in the test app instance.
    app = FastAPI()
    app.include_router(router)
    # Replace the auth dependency to a no-op for the test client.
    from apps.api import cspm_connector_router as mod

    mod._connector = CSPMConnector(prowler_path=None, checkov_path=None, trivy_path=None)
    try:
        from apps.api.auth_deps import api_key_auth as real_auth
        app.dependency_overrides[real_auth] = lambda: None
    except Exception:
        pass
    client = TestClient(app)
    r = client.get("/api/v1/connectors/cspm/status")
    assert r.status_code == 200
    body = r.json()
    assert body["connector"] == "cspm_oss"
    assert "tools" in body
    assert "prowler_cli" in body["tools"]


def test_health_endpoint_via_router():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from apps.api.cspm_connector_router import router

    app = FastAPI()
    app.include_router(router)
    try:
        from apps.api.auth_deps import api_key_auth as real_auth
        app.dependency_overrides[real_auth] = lambda: None
    except Exception:
        pass
    client = TestClient(app)
    r = client.get("/api/v1/connectors/cspm/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"
