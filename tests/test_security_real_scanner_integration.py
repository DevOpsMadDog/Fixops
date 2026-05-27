"""Real-binary integration tests for semgrep_integration and trivy_integration.

Requirements:
  - /opt/homebrew/bin/semgrep must be installed (version 1.x)
  - /opt/homebrew/bin/trivy must be installed (version 0.x)
  Both are present on this machine — tests are NOT skipped.

What these tests prove:
  1. Real semgrep: runs against a fixture with a deliberate shell-injection vuln
     and returns a real finding (not the _MOCK_SEMGREP_OUTPUT SQLi/XSS literals).
  2. Real trivy:   runs against a requirements.txt with known-vulnerable pins
     and returns real CVE IDs (not the _MOCK_TRIVY_OUTPUT CVE-2023-0001/0002
     literals).
  3. Binary-absent path (monkeypatched which→None):
     - SemgrepScanner._run_semgrep raises SemgrepUnavailableError (not mock).
     - TrivyScanner._run_trivy  raises TrivyUnavailableError  (not mock).
     - scan_and_ingest returns status="unavailable", findings=[], is_mock=False.
  4. scan_and_ingest provenance flags: is_real=True when binary runs,
     scanner_available=True, is_mock=False on production scanner instances.
"""
from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

# Ensure suite paths are on sys.path
for _suite in ("suite-core", "suite-api"):
    _p = str(Path(__file__).parent.parent / _suite)
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("FIXOPS_MODE", "enterprise")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")

# ---------------------------------------------------------------------------
# Fixture paths
# ---------------------------------------------------------------------------
_FIXTURES = Path(__file__).parent / "fixtures" / "scanner_targets"
_SEMGREP_FIXTURE_DIR = _FIXTURES / "semgrep_vuln"
_SEMGREP_FIXTURE_FILE = _SEMGREP_FIXTURE_DIR / "vuln_app.py"
_TRIVY_FIXTURE_DIR = _FIXTURES / "trivy_vuln"
_TRIVY_FIXTURE_REQTXT = _TRIVY_FIXTURE_DIR / "requirements.txt"

# ---------------------------------------------------------------------------
# Binary availability marks
# ---------------------------------------------------------------------------
_SEMGREP_BIN = shutil.which("semgrep") or shutil.which("/opt/homebrew/bin/semgrep")
_TRIVY_BIN = shutil.which("trivy") or shutil.which("/opt/homebrew/bin/trivy")

requires_semgrep = pytest.mark.skipif(
    _SEMGREP_BIN is None,
    reason="semgrep binary not on PATH — install semgrep to run real scanner tests",
)
requires_trivy = pytest.mark.skipif(
    _TRIVY_BIN is None,
    reason="trivy binary not on PATH — install trivy to run real scanner tests",
)

# The mock CVE/rule IDs that must NOT appear in real output
_MOCK_SEMGREP_RULE_IDS = {
    "python.lang.security.audit.exec-detected.exec-detected",
    "python.lang.security.audit.hardcoded-password.hardcoded-password-string",
}
_MOCK_TRIVY_CVE_IDS = {"CVE-2023-0001", "CVE-2023-0002", "CVE-2024-MOCK-001",
                       "CVE-2024-MOCK-002", "CVE-2024-MOCK-003"}
# Real CVEs present in our fixture (Pillow 8.2.0 has many; at least one of these)
_REAL_TRIVY_CVE_IDS = {"CVE-2021-34552", "CVE-2022-22817", "CVE-2023-50447",
                       "CVE-2021-23437", "CVE-2022-24303"}
# Real semgrep rule found in our fixture
_REAL_SEMGREP_RULE = "python.lang.security.audit.subprocess-shell-true.subprocess-shell-true"


# ===========================================================================
# Semgrep real-binary tests
# ===========================================================================

class TestSemgrepRealBinary:

    @requires_semgrep
    def test_real_scan_finds_subprocess_shell_true(self):
        """Real semgrep finds the subprocess shell=True vuln in the fixture."""
        from core.semgrep_integration import SemgrepScanner
        scanner = SemgrepScanner()
        assert scanner.is_semgrep_available(), "semgrep binary should be available"

        raw = scanner.scan_file(str(_SEMGREP_FIXTURE_FILE), rules="p/python")

        results = raw.get("results", [])
        rule_ids = {r.get("check_id", "") for r in results}

        # Must find the real subprocess-shell-true rule
        assert _REAL_SEMGREP_RULE in rule_ids, (
            f"Expected real semgrep finding {_REAL_SEMGREP_RULE!r} but got: {rule_ids}"
        )

        # Must NOT be the mock exec-detected or hardcoded-password literals
        assert not (_MOCK_SEMGREP_RULE_IDS & rule_ids), (
            f"Mock rule IDs leaked into real scan output: {_MOCK_SEMGREP_RULE_IDS & rule_ids}"
        )

    @requires_semgrep
    def test_real_scan_and_ingest_provenance_flags(self):
        """scan_and_ingest with real binary sets is_real=True, is_mock=False.

        We scan the fixture FILE directly (not the directory) because semgrep
        only scans git-tracked files when given a directory, but always scans a
        single file regardless of git status.
        """
        from core.semgrep_integration import SemgrepScanner
        scanner = SemgrepScanner()
        scanner._try_ingest_to_pipeline = lambda *a, **kw: None  # skip pipeline

        # Use scan_file + normalize_results to check provenance, then manually
        # build the ingest entry — mirrors what scan_and_ingest does internally.
        raw = scanner.scan_file(str(_SEMGREP_FIXTURE_FILE), rules="p/python")
        findings = scanner.normalize_results(raw)

        # Basic provenance checks that don't depend on git-tracked status
        assert scanner.is_semgrep_available() is True
        assert scanner._use_mock is False
        assert scanner._use_mock is False

        # Confirm at least one real finding
        assert len(findings) >= 1, "Expected at least one real finding from scan_file"

        # Verify no mock rule IDs in real findings
        found_rule_ids = {f.get("rule_id", "") for f in findings}
        assert not (_MOCK_SEMGREP_RULE_IDS & found_rule_ids), (
            f"Mock rule IDs in real findings: {_MOCK_SEMGREP_RULE_IDS & found_rule_ids}"
        )

        # Also verify scan_and_ingest provenance flags on a direct file path
        result = scanner.scan_and_ingest(
            str(_SEMGREP_FIXTURE_FILE), org_id="integration-test", rules="p/python"
        )
        assert result["status"] == "completed", (
            f"Expected completed, got: {result.get('status')} / {result.get('error')}"
        )
        assert result["scanner_available"] is True
        assert result["is_real"] is True
        assert result["is_mock"] is False

    @requires_semgrep
    def test_real_scan_normalize_results_shape(self):
        """normalize_results produces list of dicts with required keys from real output."""
        from core.semgrep_integration import SemgrepScanner
        scanner = SemgrepScanner()

        raw = scanner.scan_file(str(_SEMGREP_FIXTURE_FILE), rules="p/python")
        findings = scanner.normalize_results(raw)

        assert isinstance(findings, list)
        assert len(findings) >= 1

        for f in findings:
            assert isinstance(f, dict)
            assert "source_tool" in f
            assert f["source_tool"] == "semgrep"
            assert "severity" in f
            assert "file_path" in f


# ===========================================================================
# Trivy real-binary tests
# ===========================================================================

class TestTrivyRealBinary:

    @requires_trivy
    def test_real_scan_filesystem_finds_pillow_cves(self):
        """Real trivy finds known CVEs in Pillow 8.2.0 in the fixture."""
        from core.trivy_integration import TrivyScanner
        scanner = TrivyScanner()
        assert scanner.is_trivy_available(), "trivy binary should be available"

        raw = scanner.scan_filesystem(str(_TRIVY_FIXTURE_DIR))

        all_vulns = []
        for result in raw.get("Results", []):
            all_vulns.extend(result.get("Vulnerabilities") or [])

        found_ids = {v.get("VulnerabilityID", "") for v in all_vulns}

        # At least one real Pillow CVE must be present
        assert _REAL_TRIVY_CVE_IDS & found_ids, (
            f"Expected at least one of {_REAL_TRIVY_CVE_IDS} but got: {list(found_ids)[:10]}"
        )

        # Mock CVEs must NOT appear in real output
        assert not (_MOCK_TRIVY_CVE_IDS & found_ids), (
            f"Mock CVE IDs leaked into real scan output: {_MOCK_TRIVY_CVE_IDS & found_ids}"
        )

    @requires_trivy
    def test_real_scan_and_ingest_provenance_flags(self):
        """scan_and_ingest with real binary sets is_real=True, is_mock=False."""
        from core.trivy_integration import TrivyScanner
        scanner = TrivyScanner()
        scanner._try_ingest_to_pipeline = lambda *a, **kw: None  # skip pipeline

        result = scanner.scan_and_ingest(
            str(_TRIVY_FIXTURE_DIR),
            org_id="integration-test",
            scan_type="filesystem",
        )

        assert result["status"] == "completed", (
            f"Expected completed, got: {result.get('status')} / {result.get('error')}"
        )
        assert result["scanner_available"] is True
        assert result["is_real"] is True
        assert result["is_mock"] is False
        assert result["findings_count"] >= 1, "Expected at least one real CVE finding"

        # Verify no mock CVE IDs in real findings
        found_cve_ids = {f.get("cve_id", "") or f.get("source_id", "") for f in result["findings"]}
        assert not (_MOCK_TRIVY_CVE_IDS & found_cve_ids), (
            f"Mock CVE IDs in real findings: {_MOCK_TRIVY_CVE_IDS & found_cve_ids}"
        )

    @requires_trivy
    def test_real_scan_normalize_results_shape(self):
        """normalize_results produces list of dicts with required keys from real output."""
        from core.trivy_integration import TrivyScanner
        scanner = TrivyScanner()

        raw = scanner.scan_filesystem(str(_TRIVY_FIXTURE_DIR))
        findings = scanner.normalize_results(raw)

        assert isinstance(findings, list)
        assert len(findings) >= 1

        for f in findings:
            assert isinstance(f, dict)
            assert "source_tool" in f
            assert f["source_tool"] == "trivy"
            assert "severity" in f


# ===========================================================================
# Binary-absent (monkeypatched) honest-error tests
# ===========================================================================

class TestBinaryAbsentHonestError:

    def test_semgrep_run_raises_unavailable_error(self):
        """_run_semgrep raises SemgrepUnavailableError when binary absent — NOT mock."""
        from core.semgrep_integration import SemgrepScanner, SemgrepUnavailableError
        scanner = SemgrepScanner()
        with patch("shutil.which", return_value=None):
            with pytest.raises(SemgrepUnavailableError) as exc_info:
                scanner._run_semgrep(["--config", "p/default", "/tmp"])
        assert "not found" in str(exc_info.value).lower()

    def test_semgrep_scan_and_ingest_unavailable_no_fabrication(self):
        """scan_and_ingest with absent semgrep returns unavailable, not fake findings."""
        from core.semgrep_integration import SemgrepScanner
        scanner = SemgrepScanner()
        scanner._try_ingest_to_pipeline = lambda *a, **kw: None
        with patch("shutil.which", return_value=None):
            result = scanner.scan_and_ingest("/tmp/nonexistent", org_id="test")
        assert result["status"] == "unavailable"
        assert result["findings"] == []
        assert result["findings_count"] == 0
        assert result["is_mock"] is False
        assert result["scanner_available"] is False
        assert result["is_real"] is False
        # Confirm no mock exec-detected / hardcoded-password findings leaked
        assert "error" in result  # honest error message present

    def test_semgrep_use_mock_opt_in_returns_mock_data(self):
        """_use_mock=True on SemgrepScanner returns mock output — explicit test opt-in."""
        from core.semgrep_integration import SemgrepScanner
        scanner = SemgrepScanner(_use_mock=True)
        with patch("shutil.which", return_value=None):
            result = scanner._run_semgrep(["--config", "p/default", "/tmp"])
        # Mock output has results but they are clearly labeled MOCK
        assert "results" in result
        assert len(result["results"]) > 0
        for r in result["results"]:
            msg = r.get("extra", {}).get("message", "")
            assert "MOCK" in msg, f"Expected MOCK label in message: {msg!r}"

    def test_trivy_run_raises_unavailable_error(self):
        """_run_trivy raises TrivyUnavailableError when binary absent — NOT mock."""
        from core.trivy_integration import TrivyScanner, TrivyUnavailableError
        scanner = TrivyScanner()
        with patch("shutil.which", return_value=None):
            with pytest.raises(TrivyUnavailableError) as exc_info:
                scanner._run_trivy(["image", "nginx:latest"])
        assert "not found" in str(exc_info.value).lower()

    def test_trivy_scan_and_ingest_unavailable_no_fabrication(self):
        """scan_and_ingest with absent trivy returns unavailable, not fake CVEs."""
        from core.trivy_integration import TrivyScanner
        scanner = TrivyScanner()
        scanner._try_ingest_to_pipeline = lambda *a, **kw: None
        with patch("shutil.which", return_value=None):
            result = scanner.scan_and_ingest("nginx:latest", org_id="test")
        assert result["status"] == "unavailable"
        assert result["findings"] == []
        assert result["findings_count"] == 0
        assert result["is_mock"] is False
        assert result["scanner_available"] is False
        assert result["is_real"] is False
        assert "error" in result

    def test_trivy_use_mock_opt_in_returns_mock_data(self):
        """_use_mock=True on TrivyScanner returns mock output — explicit test opt-in."""
        from core.trivy_integration import TrivyScanner
        scanner = TrivyScanner(_use_mock=True)
        with patch("shutil.which", return_value=None):
            result = scanner._run_trivy(["image", "nginx:latest"])
        assert "Results" in result
        assert result.get("ArtifactName") == "mock-image:latest"
        # All mock titles must carry the MOCK label
        for r in result.get("Results", []):
            for v in r.get("Vulnerabilities") or []:
                assert "MOCK" in v.get("Title", ""), (
                    f"Expected MOCK label in title: {v.get('Title')!r}"
                )

    def test_trivy_scan_engine_unavailable_no_fabrication(self, tmp_path):
        """TrivyScanEngine.queue_scan records unavailable — not fabricated vulns."""
        from core.trivy_scan_engine import TrivyScanEngine
        engine = TrivyScanEngine(db_path=str(tmp_path / "test.db"))
        with patch("shutil.which", return_value=None):
            queued = engine.queue_scan(image="nginx:latest")

        scan_id = queued["scan_id"]
        record = engine.get_scan(scan_id)
        assert record is not None
        assert record["status"] == "unavailable"
        # severity_counts should all be zero (no fabricated data)
        total = sum(record["severity_counts"].values())
        assert total == 0, f"Expected 0 total vulns on unavailable, got {total}"
        assert record["vulnerabilities"] == []

    def test_trivy_scan_engine_use_mock_opt_in(self, tmp_path):
        """TrivyScanEngine(_use_mock=True) exercises mock path explicitly."""
        from core.trivy_scan_engine import TrivyScanEngine
        engine = TrivyScanEngine(db_path=str(tmp_path / "test_mock.db"), _use_mock=True)
        with patch("shutil.which", return_value=None):
            queued = engine.queue_scan(image="mock-image:latest")

        scan_id = queued["scan_id"]
        record = engine.get_scan(scan_id)
        assert record is not None
        # Mock data has 3 vulns (HIGH/MEDIUM/LOW)
        assert record["status"] == "completed"
        total = sum(record["severity_counts"].values())
        assert total == 3
        assert record["severity_counts"].get("HIGH", 0) == 1
        assert record["severity_counts"].get("MEDIUM", 0) == 1
        assert record["severity_counts"].get("LOW", 0) == 1

    def test_semgrep_file_not_found_raises_unavailable(self):
        """FileNotFoundError during subprocess raises SemgrepUnavailableError."""
        from core.semgrep_integration import SemgrepScanner, SemgrepUnavailableError
        scanner = SemgrepScanner()
        with patch("shutil.which", return_value="/usr/bin/semgrep"), \
             patch("subprocess.run", side_effect=FileNotFoundError):
            with pytest.raises(SemgrepUnavailableError, match="disappeared mid-run"):
                scanner._run_semgrep(["--config", "p/python", "/tmp"])

    def test_trivy_file_not_found_raises_unavailable(self):
        """FileNotFoundError during subprocess raises TrivyUnavailableError."""
        from core.trivy_integration import TrivyScanner, TrivyUnavailableError
        scanner = TrivyScanner()
        with patch("shutil.which", return_value="/usr/bin/trivy"), \
             patch("subprocess.run", side_effect=FileNotFoundError):
            with pytest.raises(TrivyUnavailableError, match="disappeared mid-run"):
                scanner._run_trivy(["image", "nginx:latest"])
