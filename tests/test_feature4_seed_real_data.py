"""Tests for ``scripts/seed_real_data.py`` (FEATURE-4 seed data pipeline).

The script is exercised through fully mocked subprocess (no real cloning),
mocked engine instances (no real scanning), and mocked HTTP (no real network).
We verify the wire shape: URLs, headers, body keys.
"""

from __future__ import annotations

import importlib
import os
import sys
import types
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"


@pytest.fixture
def seed_module(monkeypatch, tmp_path):
    """Import scripts/seed_real_data.py as a module on a fresh sys.path."""
    sys.path.insert(0, str(SCRIPTS_DIR))
    if "seed_real_data" in sys.modules:
        del sys.modules["seed_real_data"]
    mod = importlib.import_module("seed_real_data")
    yield mod
    # Cleanup
    if str(SCRIPTS_DIR) in sys.path:
        sys.path.remove(str(SCRIPTS_DIR))
    sys.modules.pop("seed_real_data", None)


# ---------------------------------------------------------------------------
# Fake engine outputs
# ---------------------------------------------------------------------------


class _FakeSeverity:
    def __init__(self, value: str):
        self.value = value


class _FakeSastFinding:
    def __init__(self, rule_id, title, severity, file_path, line):
        self.rule_id = rule_id
        self.title = title
        self.severity = _FakeSeverity(severity)
        self.file_path = file_path
        self.line_number = line


class _FakeSastResult:
    def __init__(self, findings: List[_FakeSastFinding]):
        self.findings = findings
        self.total_findings = len(findings)
        self.files_scanned = 1
        self.duration_ms = 1.23


class _FakeCspmFinding:
    def __init__(self, finding_id, title, severity, resource_id):
        self.finding_id = finding_id
        self.title = title
        self.severity = _FakeSeverity(severity)
        self.resource_id = resource_id


class _FakeCspmResult:
    def __init__(self, findings: List[_FakeCspmFinding]):
        self.findings = findings


def _make_sast_engine_with(findings: List[_FakeSastFinding]) -> MagicMock:
    eng = MagicMock()
    eng.scan_path.return_value = _FakeSastResult(findings)
    return eng


def _make_cspm_engine_with(findings: List[_FakeCspmFinding]) -> MagicMock:
    eng = MagicMock()
    eng.scan_terraform.return_value = _FakeCspmResult(findings)
    return eng


def _install_fake_engines(monkeypatch, sast_findings, cspm_findings):
    """Inject fake `core.sast_engine` + `core.cspm_engine` modules."""

    sast_mod = types.ModuleType("core.sast_engine")
    sast_mod.SASTEngine = lambda: _make_sast_engine_with(sast_findings)
    cspm_mod = types.ModuleType("core.cspm_engine")
    cspm_mod.CSPMEngine = lambda: _make_cspm_engine_with(cspm_findings)
    core_mod = sys.modules.setdefault("core", types.ModuleType("core"))
    monkeypatch.setitem(sys.modules, "core", core_mod)
    monkeypatch.setitem(sys.modules, "core.sast_engine", sast_mod)
    monkeypatch.setitem(sys.modules, "core.cspm_engine", cspm_mod)


# ---------------------------------------------------------------------------
# Fake clone — simulate filesystem layout
# ---------------------------------------------------------------------------


def _make_fake_repos(workdir: Path) -> Dict[str, Path]:
    paths = {}
    for repo_name, has_tf in [
        ("juice-shop", False),
        ("dvna", False),
        ("terragoat", True),
    ]:
        d = workdir / repo_name
        d.mkdir(parents=True, exist_ok=True)
        # one js file so SAST sees something even if we mock
        (d / "app.js").write_text("var x = 1;\n")
        if has_tf:
            tf_dir = d / "terraform"
            tf_dir.mkdir(parents=True, exist_ok=True)
            (tf_dir / "main.tf").write_text(
                'resource "aws_s3_bucket" "b" { bucket = "x" }\n'
            )
        paths[repo_name] = d
    return paths


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_cli_help_exits_zero(seed_module):
    """`--help` must print and exit cleanly without any IO."""
    with pytest.raises(SystemExit) as exc:
        seed_module.build_parser().parse_args(["--help"])
    assert exc.value.code == 0


def test_clone_repos_skip_existing(seed_module, tmp_path):
    """`--skip-clone` reuses existing checkouts and never invokes git."""
    _make_fake_repos(tmp_path)
    with patch.object(seed_module.subprocess, "run") as run_mock:
        cloned, result = seed_module.clone_repos(tmp_path, skip_clone=True)
    assert run_mock.call_count == 0
    assert set(cloned.keys()) == {"juice-shop", "dvna", "terragoat"}
    assert result.success is True


def test_clone_repos_runs_git(seed_module, tmp_path):
    """When repos are missing, we shell out to `git clone --depth 1`."""
    with patch.object(seed_module.subprocess, "run") as run_mock:
        run_mock.return_value = MagicMock(returncode=0, stderr=b"", stdout=b"")
        # pretend clone worked: create dirs after each call
        def _side_effect(cmd, *a, **kw):
            target = Path(cmd[-1])
            target.mkdir(parents=True, exist_ok=True)
            (target / "x.js").write_text("// stub")
            return MagicMock(returncode=0, stderr=b"", stdout=b"")
        run_mock.side_effect = _side_effect
        cloned, result = seed_module.clone_repos(tmp_path, skip_clone=False)
    assert run_mock.call_count == 3
    # All calls must use --depth 1
    for call in run_mock.call_args_list:
        cmd = call.args[0]
        assert cmd[:4] == ["git", "clone", "--depth", "1"]
    assert result.success is True
    assert set(cloned.keys()) == {"juice-shop", "dvna", "terragoat"}


def test_run_sast_maps_findings_to_ingest_shape(seed_module, monkeypatch, tmp_path):
    """SAST findings must be mapped to {finding_id, title, severity, source}."""
    sast_findings = [
        _FakeSastFinding("SAST-001", "SQL Injection", "critical", "/r/app.js", 12),
        _FakeSastFinding("SAST-002", "XSS", "high", "/r/foo.ts", 5),
    ]
    _install_fake_engines(monkeypatch, sast_findings, [])
    paths = _make_fake_repos(tmp_path)
    out, result = seed_module.run_sast(paths, run_nonce="abcd1234")
    assert result.success is True
    # 2 sast repos x 2 findings each (same engine returns same value) = 4
    assert len(out) == 4
    for item in out:
        assert set(item.keys()) >= {"finding_id", "title", "severity", "source"}
        assert item["finding_id"].startswith("seed-")
        assert item["finding_id"].endswith("-abcd1234")
        assert item["source"].startswith("sast:")


def test_run_cspm_maps_findings_to_ingest_shape(seed_module, monkeypatch, tmp_path):
    cspm_findings = [
        _FakeCspmFinding("CSPM-AWS-001", "S3 public", "high", "main.tf"),
        _FakeCspmFinding("CSPM-AWS-007", "SG open world", "critical", "main.tf"),
    ]
    _install_fake_engines(monkeypatch, [], cspm_findings)
    paths = _make_fake_repos(tmp_path)
    out, result = seed_module.run_cspm(paths, run_nonce="ffff0000")
    assert result.success is True
    # only terragoat is cspm-kind, 1 .tf file, 2 findings
    assert len(out) == 2
    for item in out:
        assert set(item.keys()) >= {"finding_id", "title", "severity", "source"}
        assert item["source"] == "cspm:terragoat"


def test_post_findings_uses_correct_url_and_headers(seed_module, monkeypatch):
    """Verify the POST URL, X-API-Key + Bearer headers, and body shape."""
    captured: List[Dict[str, Any]] = []

    def fake_http_post(client, url, headers, body):
        captured.append({"url": url, "headers": headers, "body": body})
        return 200, {"node_id": "node-x", "ingested": True}

    monkeypatch.setattr(seed_module, "_http_post", fake_http_post)

    findings = [
        {"finding_id": f"seed-x-{i}", "title": "t", "severity": "high", "source": "sast:x"}
        for i in range(3)
    ]
    result = seed_module.post_findings(
        api_url="http://127.0.0.1:8000",
        api_key="test-key-abc",
        findings=findings,
        org_id="default",
        batch_size=50,
    )
    assert result.success is True
    assert result.payload["posted"] == 3
    assert result.payload["failed"] == 0
    # Same URL on every call
    for c in captured:
        assert c["url"] == "http://127.0.0.1:8000/api/v1/brain/ingest/finding"
        assert c["headers"]["X-API-Key"] == "test-key-abc"
        assert c["headers"]["Authorization"] == "Bearer test-key-abc"
        assert c["body"]["org_id"] == "default"
        assert "finding_id" in c["body"]
        assert "title" in c["body"]


def test_post_findings_records_failures_and_returns_failure(seed_module, monkeypatch):
    """Non-2xx responses must increment failure counter and flip success=False."""

    def fake_http_post(client, url, headers, body):
        return 401, {"detail": "unauthorized"}

    monkeypatch.setattr(seed_module, "_http_post", fake_http_post)
    findings = [{"finding_id": "x", "title": "t", "severity": "low", "source": "sast"}]
    result = seed_module.post_findings(
        api_url="http://x", api_key="k", findings=findings, org_id="o"
    )
    assert result.success is False
    assert result.payload["failed"] == 1


def test_create_ctem_cycle_happy_path(seed_module, monkeypatch):
    """create_ctem_cycle must POST {name, org_id} and surface returned cycle_id."""
    captured: List[Dict[str, Any]] = []

    def fake_http_post(client, url, headers, body):
        captured.append({"url": url, "headers": headers, "body": body})
        if url.endswith("/cycles"):
            return 201, {"cycle_id": "ctem-cycle-123", "name": body["name"]}
        if url.endswith("/scope"):
            return 200, {"scoped": True}
        return 404, {}

    monkeypatch.setattr(seed_module, "_http_post", fake_http_post)
    result = seed_module.create_ctem_cycle(
        api_url="http://x:8000",
        api_key="k",
        org_id="default",
        asset_ids=["a1", "a2"],
    )
    assert result.success is True
    assert result.payload["cycle_id"] == "ctem-cycle-123"
    assert result.payload["cycle_name"].startswith("Seed Cycle - ")
    # Two HTTP calls (cycle create + scope)
    urls = [c["url"] for c in captured]
    assert any(u.endswith("/api/v1/ctem/cycles") for u in urls)
    assert any("/scope" in u for u in urls)


def test_create_ctem_cycle_returns_failure_when_cycle_post_fails(seed_module, monkeypatch):
    """If the cycle POST fails, the step is marked failed and cycle_id=None."""

    def fake_http_post(client, url, headers, body):
        return 500, {"detail": "db unavailable"}

    monkeypatch.setattr(seed_module, "_http_post", fake_http_post)
    result = seed_module.create_ctem_cycle(
        api_url="http://x", api_key="k", org_id="o", asset_ids=["a"]
    )
    assert result.success is False
    assert result.payload["cycle_id"] is None


def test_run_full_pipeline_exit_zero_on_happy_path(seed_module, monkeypatch, tmp_path):
    """Top-level run() integration test — every step mocked happy."""
    sast_findings = [_FakeSastFinding("SAST-001", "SQLi", "critical", "/x/a.js", 1)]
    cspm_findings = [_FakeCspmFinding("CSPM-AWS-001", "S3 public", "high", "main.tf")]
    _install_fake_engines(monkeypatch, sast_findings, cspm_findings)
    _make_fake_repos(tmp_path)

    # Skip clone (re-use the fake dirs)
    args = seed_module.build_parser().parse_args(
        [
            "--api-url", "http://127.0.0.1:8888",
            "--api-key", "test-key",
            "--workdir", str(tmp_path),
            "--skip-clone",
        ]
    )

    def fake_http_post(client, url, headers, body):
        if url.endswith("/cycles"):
            return 201, {"cycle_id": "ctem-cycle-z", "name": body["name"]}
        if "/scope" in url:
            return 200, {"scoped": True}
        # ingest_finding
        return 200, {"node_id": "n1", "ingested": True}

    monkeypatch.setattr(seed_module, "_http_post", fake_http_post)
    rc = seed_module.run(args)
    assert rc == 0


def test_run_full_pipeline_exit_one_when_cycle_fails(seed_module, monkeypatch, tmp_path):
    """If the cycle creation 5xx's, top-level run() returns exit code 1."""
    sast_findings = [_FakeSastFinding("SAST-001", "SQLi", "critical", "/x/a.js", 1)]
    cspm_findings = [_FakeCspmFinding("CSPM-AWS-001", "S3 public", "high", "main.tf")]
    _install_fake_engines(monkeypatch, sast_findings, cspm_findings)
    _make_fake_repos(tmp_path)

    args = seed_module.build_parser().parse_args(
        [
            "--api-url", "http://127.0.0.1:8888",
            "--api-key", "k",
            "--workdir", str(tmp_path),
            "--skip-clone",
        ]
    )

    def fake_http_post(client, url, headers, body):
        if url.endswith("/cycles"):
            return 503, {"detail": "ctem engine down"}
        return 200, {"node_id": "n", "ingested": True}

    monkeypatch.setattr(seed_module, "_http_post", fake_http_post)
    rc = seed_module.run(args)
    assert rc == 1


def test_run_missing_api_key_returns_one(seed_module, monkeypatch, tmp_path):
    """No env, no flag -> immediate exit code 1 with auth.missing log."""
    monkeypatch.delenv("FIXOPS_API_KEY", raising=False)
    monkeypatch.delenv("FIXOPS_API_TOKEN", raising=False)
    args = seed_module.build_parser().parse_args(
        ["--api-url", "http://x", "--workdir", str(tmp_path)]
    )
    args.api_key = None
    rc = seed_module.run(args)
    assert rc == 1
