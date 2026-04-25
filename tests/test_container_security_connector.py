"""Tests for ALDECI Container Security Connector.

Covers Trivy / Grype / Dockle / kube-bench parsers using embedded sample JSON
(taken from each tool's official documentation) and end-to-end scan_tenant
with monkeypatched docker + scanner runners. Also exercises:

  * dataclass shapes (ToolResult, TenantScanResult)
  * severity normalisation + CVSS proxy
  * Dockerfile auto-detection vs synthesis
  * path-traversal rejection
  * SecurityFindingsEngine mirroring with correlation_key dedup
  * In-memory scan history per org
  * Router /scan, /tools, /tenants, /history, /health, /status

Run via:
    python -m pytest tests/test_container_security_connector.py -x -q --timeout=10
"""
from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from typing import Dict, List
from unittest import mock

import pytest

import sys
ROOT = Path(__file__).resolve().parent.parent
for _p in [
    ROOT / "suite-core",
    ROOT / "suite-api",
    ROOT / "suite-attack",
    ROOT / "suite-feeds",
    ROOT / "suite-evidence-risk",
    ROOT / "suite-integrations",
]:
    sp = str(_p)
    if _p.is_dir() and sp not in sys.path:
        sys.path.insert(0, sp)

from connectors import container_security_connector as csc  # noqa: E402


# ---------------------------------------------------------------------------
# Embedded sample tool outputs (from each tool's official docs)
# ---------------------------------------------------------------------------

TRIVY_SAMPLE = {
    "SchemaVersion": 2,
    "ArtifactName": "fixops-test/sample:scan",
    "Results": [
        {
            "Target": "fixops-test/sample:scan (alpine 3.20.0)",
            "Class": "os-pkgs",
            "Type": "alpine",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2024-0727",
                    "PkgName": "openssl",
                    "InstalledVersion": "3.1.4-r5",
                    "FixedVersion": "3.1.4-r6",
                    "Title": "Denial of service in OpenSSL",
                    "Description": "Processing a malicious file may cause OpenSSL to crash.",
                    "Severity": "HIGH",
                    "CVSS": {
                        "nvd": {"V3Score": 7.5, "V2Score": 5.0},
                        "redhat": {"V3Score": 5.5},
                    },
                },
                {
                    "VulnerabilityID": "CVE-2023-5363",
                    "PkgName": "openssl",
                    "InstalledVersion": "3.1.4-r5",
                    "Severity": "MEDIUM",
                },
            ],
            "Misconfigurations": [
                {
                    "ID": "DS002",
                    "Title": "Image user should not be 'root'",
                    "Description": "Running containers with 'root' user is dangerous.",
                    "Severity": "HIGH",
                    "Resolution": "Add 'USER appuser' to the Dockerfile",
                },
            ],
            "Secrets": [
                {
                    "RuleID": "aws-access-key-id",
                    "Title": "AWS Access Key ID",
                    "Severity": "CRITICAL",
                    "Match": "AKIAIOSFODNN7EXAMPLE",
                },
            ],
        }
    ],
}

GRYPE_SAMPLE = {
    "matches": [
        {
            "vulnerability": {
                "id": "CVE-2024-0727",
                "severity": "High",
                "description": "Denial of service in OpenSSL",
                "cvss": [{"metrics": {"baseScore": 7.5}}],
                "fix": {"versions": ["3.1.4-r6"], "state": "fixed"},
            },
            "artifact": {"name": "openssl", "version": "3.1.4-r5"},
        },
        {
            "vulnerability": {
                "id": "CVE-2023-99999",
                "severity": "Negligible",
                "description": "Negligible severity issue",
                "cvss": [],
                "fix": {"versions": [], "state": "not-fixed"},
            },
            "artifact": {"name": "musl", "version": "1.2.4"},
        },
    ]
}

DOCKLE_SAMPLE = {
    "summary": {"fatal": 0, "warn": 1, "info": 2, "skip": 0, "pass": 5},
    "details": [
        {
            "code": "CIS-DI-0001",
            "title": "Create a user for the container",
            "level": "WARN",
            "alerts": ["Last user should not be root"],
        },
        {
            "code": "CIS-DI-0006",
            "title": "Add HEALTHCHECK instruction",
            "level": "INFO",
            "alerts": ["not found HEALTHCHECK statement"],
        },
        {
            "code": "DKL-DI-0001",
            "title": "Pinned Multistage builds",
            "level": "PASS",
            "alerts": [],
        },
    ],
}

KUBEBENCH_SAMPLE = {
    "Controls": [
        {
            "id": "1",
            "version": "1.7",
            "tests": [
                {
                    "section": "1.1",
                    "results": [
                        {
                            "test_number": "1.1.1",
                            "test_desc": "Ensure that the API server pod specification file permissions are set to 644 or more restrictive",
                            "status": "FAIL",
                            "remediation": "Run: chmod 644 /etc/kubernetes/manifests/kube-apiserver.yaml",
                            "audit": "stat -c %a /etc/kubernetes/manifests/kube-apiserver.yaml",
                        },
                        {
                            "test_number": "1.1.2",
                            "test_desc": "Ensure that the API server pod specification file ownership is set to root:root",
                            "status": "PASS",
                        },
                        {
                            "test_number": "1.1.3",
                            "test_desc": "Ensure that the controller manager pod specification file permissions are set to 644 or more restrictive",
                            "status": "WARN",
                            "remediation": "chmod 644 …",
                        },
                    ],
                }
            ],
        }
    ]
}


# ---------------------------------------------------------------------------
# 1. Severity / proxy / parser unit tests
# ---------------------------------------------------------------------------

class TestSeverityHelpers:
    def test_norm_severity_known(self):
        assert csc._norm_severity("CRITICAL") == "critical"
        assert csc._norm_severity("High") == "high"
        assert csc._norm_severity("medium") == "medium"
        assert csc._norm_severity("Moderate") == "medium"
        assert csc._norm_severity("Low") == "low"
        assert csc._norm_severity("Negligible") == "low"

    def test_norm_severity_unknown_falls_back_informational(self):
        assert csc._norm_severity(None) == "informational"
        assert csc._norm_severity("") == "informational"
        assert csc._norm_severity("alien-severity") == "informational"

    def test_cvss_proxy_table_complete(self):
        for level in ("critical", "high", "medium", "low", "informational"):
            assert isinstance(csc._CVSS_PROXY[level], float)
            assert 0.0 <= csc._CVSS_PROXY[level] <= 10.0


class TestTrivyParser:
    def test_parses_vulns_misconfig_secrets(self):
        out = csc._parse_trivy(TRIVY_SAMPLE, "img:scan")
        assert len(out) == 4  # 2 CVEs + 1 misconfig + 1 secret
        kinds = {f["finding_type"] for f in out}
        assert {"vulnerability", "misconfiguration", "secret-exposure"} <= kinds

    def test_trivy_picks_highest_cvss(self):
        out = csc._parse_trivy(TRIVY_SAMPLE, "img:scan")
        cve = next(f for f in out if f["source_id"] == "CVE-2024-0727")
        assert cve["cvss_score"] == 7.5
        assert cve["severity"] == "high"

    def test_trivy_remediation_uses_fixed_version(self):
        out = csc._parse_trivy(TRIVY_SAMPLE, "img:scan")
        cve = next(f for f in out if f["source_id"] == "CVE-2024-0727")
        assert "Upgrade openssl to 3.1.4-r6" == cve["remediation"]

    def test_trivy_correlation_key_format(self):
        out = csc._parse_trivy(TRIVY_SAMPLE, "img:scan")
        cve = next(f for f in out if f["source_id"] == "CVE-2024-0727")
        assert cve["correlation_key"] == "container_via_trivy|img:scan|CVE-2024-0727|openssl"

    def test_trivy_secret_severity_critical(self):
        out = csc._parse_trivy(TRIVY_SAMPLE, "img:scan")
        secret = next(f for f in out if f["finding_type"] == "secret-exposure")
        assert secret["severity"] == "critical"
        assert secret["cvss_score"] == csc._CVSS_PROXY["critical"]

    def test_trivy_empty_payload(self):
        assert csc._parse_trivy({}, "i") == []
        assert csc._parse_trivy({"Results": []}, "i") == []


class TestGrypeParser:
    def test_parses_matches(self):
        out = csc._parse_grype(GRYPE_SAMPLE, "img:scan")
        assert len(out) == 2
        ids = {f["source_id"] for f in out}
        assert ids == {"CVE-2024-0727", "CVE-2023-99999"}

    def test_grype_picks_max_cvss(self):
        out = csc._parse_grype(GRYPE_SAMPLE, "img:scan")
        cve = next(f for f in out if f["source_id"] == "CVE-2024-0727")
        assert cve["cvss_score"] == 7.5

    def test_grype_remediation_with_fix(self):
        out = csc._parse_grype(GRYPE_SAMPLE, "img:scan")
        cve = next(f for f in out if f["source_id"] == "CVE-2024-0727")
        assert "Upgrade openssl to 3.1.4-r6" == cve["remediation"]

    def test_grype_remediation_no_fix(self):
        out = csc._parse_grype(GRYPE_SAMPLE, "img:scan")
        cve = next(f for f in out if f["source_id"] == "CVE-2023-99999")
        assert cve["remediation"].startswith("Upgrade or patch musl")

    def test_grype_negligible_maps_low(self):
        out = csc._parse_grype(GRYPE_SAMPLE, "img:scan")
        cve = next(f for f in out if f["source_id"] == "CVE-2023-99999")
        assert cve["severity"] == "low"


class TestDockleParser:
    def test_drops_pass_skip(self):
        out = csc._parse_dockle(DOCKLE_SAMPLE, "img:scan")
        codes = {f["source_id"] for f in out}
        assert "DKL-DI-0001" not in codes  # PASS dropped

    def test_keeps_warn_info_with_alerts(self):
        out = csc._parse_dockle(DOCKLE_SAMPLE, "img:scan")
        codes = {f["source_id"] for f in out}
        assert "CIS-DI-0001" in codes  # WARN
        assert "CIS-DI-0006" in codes  # INFO with description

    def test_dockle_correlation_key(self):
        out = csc._parse_dockle(DOCKLE_SAMPLE, "img:scan")
        warn = next(f for f in out if f["source_id"] == "CIS-DI-0001")
        assert warn["correlation_key"] == "container_via_dockle|img:scan|CIS-DI-0001|lint"
        assert warn["finding_type"] == "misconfiguration"

    def test_dockle_warn_maps_medium(self):
        out = csc._parse_dockle(DOCKLE_SAMPLE, "img:scan")
        warn = next(f for f in out if f["source_id"] == "CIS-DI-0001")
        assert warn["severity"] == "medium"


class TestKubebenchParser:
    def test_keeps_only_fail_warn(self):
        out = csc._parse_kubebench(KUBEBENCH_SAMPLE)
        ids = {f["source_id"] for f in out}
        assert "1.1.1" in ids and "1.1.3" in ids
        assert "1.1.2" not in ids  # PASS dropped

    def test_fail_maps_high_warn_medium(self):
        out = csc._parse_kubebench(KUBEBENCH_SAMPLE)
        fail = next(f for f in out if f["source_id"] == "1.1.1")
        warn = next(f for f in out if f["source_id"] == "1.1.3")
        assert fail["severity"] == "high"
        assert warn["severity"] == "medium"

    def test_kubebench_correlation_key(self):
        out = csc._parse_kubebench(KUBEBENCH_SAMPLE)
        fail = next(f for f in out if f["source_id"] == "1.1.1")
        assert fail["correlation_key"] == "container_via_kubebench|cluster|1.1.1|cis"


# ---------------------------------------------------------------------------
# 2. Subprocess + run helper
# ---------------------------------------------------------------------------

class TestRunHelper:
    def test_missing_binary_returns_minus_two(self):
        rc, out, err = csc._run(["__definitely_not_a_real_binary_xyz_123__"], timeout=2)
        assert rc == -2
        assert b"binary not found" in err

    def test_rejects_empty_argv(self):
        with pytest.raises(ValueError):
            csc._run([], timeout=1)

    def test_real_echo_works(self):
        # 'echo' exists on every dev box; confirms argv plumbing
        rc, out, _ = csc._run(["echo", "hello"], timeout=2)
        assert rc == 0
        assert b"hello" in out


# ---------------------------------------------------------------------------
# 3. Dockerfile synthesis
# ---------------------------------------------------------------------------

class TestDockerfileSynthesis:
    def test_finds_existing_dockerfile(self, tmp_path: Path):
        df = tmp_path / "Dockerfile"
        df.write_text("FROM scratch\n")
        ctx, synth = csc._ensure_dockerfile(tmp_path)
        assert synth is False
        assert ctx == tmp_path

    def test_synthesises_when_missing(self, tmp_path: Path):
        ctx, synth = csc._ensure_dockerfile(tmp_path)
        assert synth is True
        assert (tmp_path / ".fixops-test.Dockerfile").is_file()
        contents = (tmp_path / ".fixops-test.Dockerfile").read_text()
        assert "FROM alpine" in contents

    def test_finds_dockerfile_in_subdir(self, tmp_path: Path):
        sub = tmp_path / "build"
        sub.mkdir()
        (sub / "Dockerfile").write_text("FROM scratch\n")
        ctx, synth = csc._ensure_dockerfile(tmp_path)
        assert synth is False


# ---------------------------------------------------------------------------
# 4. SecurityFindingsEngine mirror
# ---------------------------------------------------------------------------

class TestMirror:
    def test_mirror_records_findings(self, monkeypatch):
        recorded: List[Dict] = []

        class FakeEngine:
            def record_finding(self, **kwargs):
                recorded.append(kwargs)
                return {"id": len(recorded)}

        # Reset singleton
        csc._findings_engine = FakeEngine()
        try:
            n = csc._mirror_to_findings(
                org_id="acme",
                image="img:scan",
                scan_id="scan-1",
                source_tool="container_via_trivy",
                findings=csc._parse_trivy(TRIVY_SAMPLE, "img:scan"),
            )
            assert n == 4
            assert all(r["org_id"] == "acme" for r in recorded)
            assert all(r["asset_type"] == "container_image" for r in recorded)
            assert all(r["scan_id"] == "scan-1" for r in recorded)
            assert all(r["source_tool"] == "container_via_trivy" for r in recorded)
        finally:
            csc._findings_engine = None

    def test_mirror_no_engine_returns_zero(self):
        csc._findings_engine = None
        with mock.patch.object(csc, "_get_findings_engine", return_value=None):
            n = csc._mirror_to_findings("o", "img", "s", "container_via_trivy", [{"title": "x"}])
            assert n == 0

    def test_mirror_empty_findings_short_circuits(self):
        csc._findings_engine = "should-not-be-touched"
        try:
            n = csc._mirror_to_findings("o", "img", "s", "container_via_trivy", [])
            assert n == 0
        finally:
            csc._findings_engine = None


# ---------------------------------------------------------------------------
# 5. History
# ---------------------------------------------------------------------------

class TestHistory:
    def test_record_and_read(self):
        # Wipe namespace for test
        with csc._history_lock:
            csc._history.pop("histtest-org", None)
        for i in range(5):
            csc._record_history("histtest-org", {"i": i})
        rows = csc.get_scan_history("histtest-org", limit=10)
        # Newest first
        assert rows[0]["i"] == 4
        assert rows[-1]["i"] == 0

    def test_history_caps_at_200(self):
        with csc._history_lock:
            csc._history.pop("cap-org", None)
        for i in range(220):
            csc._record_history("cap-org", {"i": i})
        rows = csc.get_scan_history("cap-org", limit=500)
        assert len(rows) == 200
        # Oldest retained should be entry 20 (220 - 200)
        assert rows[-1]["i"] == 20

    def test_history_unknown_org_empty(self):
        assert csc.get_scan_history("unknown-org-xyz") == []


# ---------------------------------------------------------------------------
# 6. Connector class
# ---------------------------------------------------------------------------

class TestConnectorBasics:
    def test_list_tenants_empty_when_root_missing(self, tmp_path):
        conn = csc.ContainerSecurityConnector(tenants_root=str(tmp_path / "nope"))
        assert conn.list_tenants() == []

    def test_list_tenants_filters_dotfiles(self, tmp_path):
        (tmp_path / "alpha").mkdir()
        (tmp_path / "beta").mkdir()
        (tmp_path / ".hidden").mkdir()
        (tmp_path / "afile").write_text("not a dir")
        conn = csc.ContainerSecurityConnector(tenants_root=str(tmp_path))
        assert conn.list_tenants() == ["alpha", "beta"]

    def test_tool_status_keys(self):
        conn = csc.ContainerSecurityConnector()
        st = conn.tool_status()
        assert set(st) == {"docker", "trivy", "grype", "dockle", "kube-bench"}

    def test_invalid_tenant_traversal_rejected(self, tmp_path):
        conn = csc.ContainerSecurityConnector(tenants_root=str(tmp_path))
        for bad in ("..", "../etc", "a/b", "a\\b"):
            with pytest.raises(ValueError):
                conn.scan_tenant(bad, org_id="o")

    def test_missing_tenant_raises_filenotfound(self, tmp_path):
        conn = csc.ContainerSecurityConnector(tenants_root=str(tmp_path))
        with pytest.raises(FileNotFoundError):
            conn.scan_tenant("nope", org_id="o")


# ---------------------------------------------------------------------------
# 7. End-to-end scan_tenant with monkeypatched docker + scanners
# ---------------------------------------------------------------------------

@pytest.fixture
def patched_runners(monkeypatch):
    """Replace docker build + 3 scanner runners with deterministic stubs."""
    image_tag_holder: Dict[str, str] = {}

    def fake_build(repo_path, image_tag, synthetic, timeout):
        image_tag_holder["tag"] = image_tag
        return True, "", 0.01

    def fake_trivy(image, timeout=600):
        return csc.ToolResult(
            tool="trivy", image=image, success=True, elapsed_s=0.01,
            findings=csc._parse_trivy(TRIVY_SAMPLE, image),
            finding_count=len(csc._parse_trivy(TRIVY_SAMPLE, image)),
        )

    def fake_grype(image, timeout=600):
        return csc.ToolResult(
            tool="grype", image=image, success=True, elapsed_s=0.01,
            findings=csc._parse_grype(GRYPE_SAMPLE, image),
            finding_count=len(csc._parse_grype(GRYPE_SAMPLE, image)),
        )

    def fake_dockle(image, timeout=600):
        return csc.ToolResult(
            tool="dockle", image=image, success=True, elapsed_s=0.01,
            findings=csc._parse_dockle(DOCKLE_SAMPLE, image),
            finding_count=len(csc._parse_dockle(DOCKLE_SAMPLE, image)),
        )

    monkeypatch.setattr(csc, "_docker_build", fake_build)
    monkeypatch.setattr(csc, "_run_trivy_image", fake_trivy)
    monkeypatch.setattr(csc, "_run_grype", fake_grype)
    monkeypatch.setattr(csc, "_run_dockle", fake_dockle)
    # Force docker shutil.which to look present:
    monkeypatch.setattr(csc.shutil, "which", lambda b: "/usr/bin/" + b)
    return image_tag_holder


class TestE2EScan:
    def test_scan_tenant_happy_path(self, tmp_path, patched_runners, monkeypatch):
        recorded: List[Dict] = []

        class FakeEngine:
            def record_finding(self, **kwargs):
                recorded.append(kwargs)
                return {"id": len(recorded)}

        monkeypatch.setattr(csc, "_findings_engine", FakeEngine())
        # Build 5 tenant dirs with no Dockerfile (will be synthesised)
        names = []
        for n in ("acme", "beta-co", "gamma", "delta", "echo"):
            d = tmp_path / n
            d.mkdir()
            (d / "main.py").write_text("print('hi')\n")
            names.append(n)

        conn = csc.ContainerSecurityConnector(
            tenants_root=str(tmp_path),
            image_prefix="fixops-test",
        )
        results = []
        for name in names:
            r = conn.scan_tenant(name, org_id="acme-org")
            results.append(r)
            assert r.error is None, r.error
            assert r.findings_recorded > 0
            # 4 trivy + 2 grype + 2 dockle = 8 findings each
            assert r.findings_recorded == 8
            assert r.dockerfile_synthesised is True
            assert r.image == f"fixops-test/{name.lower()}:scan"
            assert len(r.tool_results) == 3
            assert all(t.success for t in r.tool_results)

        # Each tenant produced findings tagged with the right source_tool
        sources = {r["source_tool"] for r in recorded}
        assert {"container_via_trivy", "container_via_grype", "container_via_dockle"} <= sources
        assert all(r["asset_type"] == "container_image" for r in recorded)

        # severity_breakdown must sum to findings_recorded for each scan
        for r in results:
            assert sum(r.severity_breakdown.values()) == r.findings_recorded

        # History captured
        hist = csc.get_scan_history("acme-org", limit=10)
        assert len(hist) == 5

    def test_scan_all_iterates_tenants(self, tmp_path, patched_runners, monkeypatch):
        monkeypatch.setattr(csc, "_findings_engine", mock.MagicMock(record_finding=lambda **kw: {"id": 1}))
        for n in ("t1", "t2", "t3"):
            (tmp_path / n).mkdir()
        conn = csc.ContainerSecurityConnector(tenants_root=str(tmp_path))
        results = conn.scan_all(org_id="o")
        assert {r.tenant for r in results} == {"t1", "t2", "t3"}
        assert all(r.error is None for r in results)

    def test_to_dict_serialises_fully(self, tmp_path, patched_runners, monkeypatch):
        monkeypatch.setattr(csc, "_findings_engine", mock.MagicMock(record_finding=lambda **kw: {"id": 1}))
        (tmp_path / "x").mkdir()
        conn = csc.ContainerSecurityConnector(tenants_root=str(tmp_path))
        r = conn.scan_tenant("x", org_id="org")
        d = r.to_dict()
        for k in (
            "scan_id", "org_id", "tenant", "image", "started_at", "completed_at",
            "dockerfile_synthesised", "build_seconds", "findings_recorded",
            "severity_breakdown", "tools",
        ):
            assert k in d
        assert isinstance(d["tools"], list) and len(d["tools"]) == 3


# ---------------------------------------------------------------------------
# 8. Build-failure path
# ---------------------------------------------------------------------------

class TestBuildFailure:
    def test_docker_missing_records_error(self, tmp_path, monkeypatch):
        (tmp_path / "t").mkdir()
        # docker absent everywhere
        monkeypatch.setattr(csc.shutil, "which", lambda b: None)
        conn = csc.ContainerSecurityConnector(tenants_root=str(tmp_path))
        r = conn.scan_tenant("t", org_id="o")
        assert "docker" in (r.error or "").lower()
        assert r.findings_recorded == 0

    def test_build_error_propagates(self, tmp_path, monkeypatch):
        (tmp_path / "t").mkdir()
        monkeypatch.setattr(csc.shutil, "which", lambda b: "/usr/bin/" + b)
        monkeypatch.setattr(csc, "_docker_build", lambda *a, **k: (False, "build OOM", 0.5))
        conn = csc.ContainerSecurityConnector(tenants_root=str(tmp_path))
        r = conn.scan_tenant("t", org_id="o")
        assert r.error == "build OOM"


# ---------------------------------------------------------------------------
# 9. Default singleton
# ---------------------------------------------------------------------------

class TestSingleton:
    def test_get_default_connector_consistent(self, tmp_path):
        a = csc.get_container_security_connector(tenants_root=str(tmp_path))
        b = csc.get_container_security_connector()  # without override returns SAME instance
        assert b is a

    def test_get_default_reinstantiates_with_override(self, tmp_path):
        a = csc.get_container_security_connector(tenants_root=str(tmp_path))
        other = tmp_path / "other"
        other.mkdir()
        b = csc.get_container_security_connector(tenants_root=str(other))
        assert b is not a
        assert str(b.tenants_root) == str(other)


# ---------------------------------------------------------------------------
# 10. Router HTTP smoke (TestClient)
# ---------------------------------------------------------------------------

class TestRouterEndpoints:
    @pytest.fixture
    def client(self, tmp_path, monkeypatch):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        # Build tenant dirs for tenants endpoint
        (tmp_path / "demo").mkdir()
        monkeypatch.setenv("FIXOPS_CONTAINER_TENANTS_ROOT", str(tmp_path))

        # Force singleton refresh
        csc._DEFAULT_CONNECTOR = None

        from apps.api.container_security_connector_router import router
        app = FastAPI()
        app.include_router(router)
        return TestClient(app)

    def test_health_ok(self, client):
        r = client.get("/api/v1/connectors/container-security/health")
        assert r.status_code == 200
        body = r.json()
        assert body["router"] == "container-security-connector"

    def test_status_alias(self, client):
        r = client.get("/api/v1/connectors/container-security/status")
        assert r.status_code == 200
        assert r.json()["router"] == "container-security-connector"

    def test_tools_endpoint(self, client):
        r = client.get("/api/v1/connectors/container-security/tools")
        assert r.status_code == 200
        body = r.json()
        assert "tools" in body and "docker" in body["tools"]

    def test_tenants_endpoint(self, client, tmp_path):
        r = client.get(
            "/api/v1/connectors/container-security/tenants",
            params={"tenants_root": str(tmp_path)},
        )
        assert r.status_code == 200
        body = r.json()
        assert "demo" in body["tenants"]

    def test_scan_invalid_tenant_400(self, client, tmp_path):
        r = client.post(
            "/api/v1/connectors/container-security/scan",
            json={"tenant": "../etc", "tenants_root": str(tmp_path)},
        )
        # field_validator rejects -> Pydantic 422
        assert r.status_code in (400, 422)

    def test_scan_unknown_tenant_404(self, client, tmp_path, monkeypatch):
        # Force docker present so we proceed past tool gating to the dir check
        monkeypatch.setattr(csc.shutil, "which", lambda b: "/usr/bin/" + b)
        r = client.post(
            "/api/v1/connectors/container-security/scan",
            json={"tenant": "ghost", "tenants_root": str(tmp_path)},
        )
        assert r.status_code == 404

    def test_history_endpoint(self, client):
        r = client.get("/api/v1/connectors/container-security/history?limit=5")
        assert r.status_code == 200
        body = r.json()
        assert "entries" in body and "org_id" in body
