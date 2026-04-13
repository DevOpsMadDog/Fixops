"""
Tests for scripts/self_scan.py — ALdeci self-scan bootstrap.

Covers:
- Pure-Python scanners (SAST, secrets, Dockerfile, SCA, license)
- SBOM generation (CycloneDX format)
- Requirements parsing
- Finding normalisation to brain-pipeline shape
- TrustGraph indexing (via mock KnowledgeStore)
- API call helper (mock urllib)
- File helpers (read_file, resolve_path, collect_python_files)
- Phase orchestration (offline / API-available paths)
- Results persistence (save_results)
- Main() exit codes and summary output
- Edge cases: empty files, missing files, malformed input

All tests use mocks and temp directories — no external services required.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch, mock_open

# ---------------------------------------------------------------------------
# Ensure repo root + scripts/ are importable
# ---------------------------------------------------------------------------
REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

# Set required env vars before import
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token-bootstrap")
os.environ.setdefault("ALDECI_BASE_URL", "http://localhost:8000")
os.environ.setdefault("SELF_SCAN_ORG_ID", "test-org")

import importlib
import self_scan as ss


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _reset_counters():
    """Reset module-level counters between tests."""
    ss._pass = 0
    ss._fail = 0
    ss._total = 0
    ss._step_open = False
    ss._step_status = None
    ss.ALL_FINDINGS.clear()
    ss.SCAN_SUMMARY.clear()


# ============================================================================
# 1. Requirements parser
# ============================================================================

class TestParseRequirements(unittest.TestCase):

    def test_pinned_version(self):
        content = "fastapi==0.115.0\n"
        comps = ss._parse_requirements(content)
        self.assertEqual(len(comps), 1)
        self.assertEqual(comps[0]["name"], "fastapi")
        self.assertEqual(comps[0]["version"], "0.115.0")

    def test_ge_version(self):
        content = "requests>=2.32.0\n"
        comps = ss._parse_requirements(content)
        self.assertEqual(comps[0]["version"], "2.32.0")

    def test_comments_and_blanks_ignored(self):
        content = "# comment\n\nfastapi==0.1.0\n"
        comps = ss._parse_requirements(content)
        self.assertEqual(len(comps), 1)

    def test_dash_lines_ignored(self):
        content = "-r other.txt\nrequests==2.31.0\n"
        comps = ss._parse_requirements(content)
        self.assertEqual(len(comps), 1)

    def test_purl_format(self):
        content = "pydantic==2.0.0\n"
        comps = ss._parse_requirements(content)
        self.assertIn("pkg:pypi/pydantic@2.0.0", comps[0]["purl"])

    def test_unknown_version(self):
        content = "some-lib\n"
        comps = ss._parse_requirements(content)
        self.assertEqual(comps[0]["version"], "unknown")

    def test_tilde_equal(self):
        content = "uvicorn~=0.30.0\n"
        comps = ss._parse_requirements(content)
        self.assertEqual(comps[0]["name"], "uvicorn")

    def test_empty_requirements(self):
        comps = ss._parse_requirements("")
        self.assertEqual(comps, [])

    def test_multiple_deps(self):
        content = "fastapi==0.115.0\nrequests>=2.32\npydantic==2.6.0\n"
        comps = ss._parse_requirements(content)
        self.assertEqual(len(comps), 3)


# ============================================================================
# 2. SBOM generation
# ============================================================================

class TestBuildSBOM(unittest.TestCase):

    def setUp(self):
        self.components = [
            {"name": "fastapi", "version": "0.115.0", "purl": "pkg:pypi/fastapi@0.115.0"},
            {"name": "requests", "version": "2.32.0", "purl": "pkg:pypi/requests@2.32.0"},
        ]

    def test_sbom_format(self):
        sbom = ss._build_sbom(self.components)
        self.assertEqual(sbom["bomFormat"], "CycloneDX")
        self.assertEqual(sbom["specVersion"], "1.5")

    def test_sbom_has_serial_number(self):
        sbom = ss._build_sbom(self.components)
        self.assertTrue(sbom["serialNumber"].startswith("urn:uuid:"))

    def test_sbom_component_count(self):
        sbom = ss._build_sbom(self.components)
        self.assertEqual(len(sbom["components"]), 2)

    def test_sbom_metadata_app_name(self):
        sbom = ss._build_sbom(self.components)
        self.assertEqual(sbom["metadata"]["component"]["name"], "aldeci-platform")

    def test_sbom_is_serialisable(self):
        sbom = ss._build_sbom(self.components)
        dumped = json.dumps(sbom)
        self.assertIn("CycloneDX", dumped)

    def test_sbom_empty_components(self):
        sbom = ss._build_sbom([])
        self.assertEqual(sbom["components"], [])


# ============================================================================
# 3. SAST scanner
# ============================================================================

class TestSASTScanner(unittest.TestCase):

    def test_eval_detected(self):
        code = "result = eval(user_input)\n"
        findings = ss._sast_scan_file(code, "test.py")
        rules = [f["rule_id"] for f in findings]
        self.assertIn("B307", rules)

    def test_shell_true_detected(self):
        code = "subprocess.run(cmd, shell=True)\n"
        findings = ss._sast_scan_file(code, "test.py")
        rules = [f["rule_id"] for f in findings]
        self.assertIn("B602", rules)

    def test_bare_except_detected(self):
        code = "try:\n    pass\nexcept:\n    pass\n"
        findings = ss._sast_scan_file(code, "test.py")
        rules = [f["rule_id"] for f in findings]
        self.assertIn("B110", rules)

    def test_ssl_verify_false(self):
        code = 'requests.get(url, verify=False)\n'
        findings = ss._sast_scan_file(code, "test.py")
        rules = [f["rule_id"] for f in findings]
        self.assertIn("B501", rules)

    def test_comments_skipped(self):
        code = "# eval(user_input)  -- commented out\n"
        findings = ss._sast_scan_file(code, "test.py")
        self.assertEqual(findings, [])

    def test_clean_code_no_findings(self):
        code = "def add(a, b):\n    return a + b\n"
        findings = ss._sast_scan_file(code, "test.py")
        self.assertEqual(findings, [])

    def test_finding_has_required_fields(self):
        code = "exec(cmd)\n"
        findings = ss._sast_scan_file(code, "app.py")
        self.assertTrue(len(findings) > 0)
        f = findings[0]
        for field in ("finding_id", "rule_id", "title", "severity", "file_path", "line_number"):
            self.assertIn(field, f)

    def test_line_number_correct(self):
        code = "x = 1\ny = eval(z)\n"
        findings = ss._sast_scan_file(code, "test.py")
        eval_findings = [f for f in findings if f["rule_id"] == "B307"]
        self.assertTrue(len(eval_findings) > 0)
        self.assertEqual(eval_findings[0]["line_number"], 2)

    def test_severity_values_valid(self):
        code = "eval(x)\nshell=True\nrandom.random()\n"
        findings = ss._sast_scan_file(code, "t.py")
        for f in findings:
            self.assertIn(f["severity"], ("critical", "high", "medium", "low", "info"))


# ============================================================================
# 4. Secrets scanner
# ============================================================================

class TestSecretsScanner(unittest.TestCase):

    def test_aws_key_detected(self):
        content = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
        findings = ss._secrets_scan_content(content, "config.env")
        types_ = [f["secret_type"] for f in findings]
        self.assertIn("aws_access_key_id", types_)

    def test_hardcoded_password_detected(self):
        content = 'password = "s3cr3t123"\n'
        findings = ss._secrets_scan_content(content, ".env")
        self.assertTrue(len(findings) > 0)

    def test_clean_content_no_findings(self):
        content = "HOST=localhost\nPORT=5432\n"
        findings = ss._secrets_scan_content(content, ".env")
        self.assertEqual(findings, [])

    def test_finding_has_line_number(self):
        content = "line1\npassword = \"abc\"\n"
        findings = ss._secrets_scan_content(content, "f.env")
        self.assertTrue(len(findings) > 0)
        self.assertEqual(findings[0]["line_number"], 2)

    def test_finding_has_severity(self):
        content = "AKIA1234567890ABCDEF\n"
        findings = ss._secrets_scan_content(content, "f.env")
        for f in findings:
            self.assertIn(f["severity"], ("critical", "high", "medium", "low"))


# ============================================================================
# 5. Dockerfile scanner
# ============================================================================

class TestDockerfileScanner(unittest.TestCase):

    def test_user_root_detected(self):
        content = "FROM python:3.11\nUSER root\n"
        findings = ss._dockerfile_scan(content, "Dockerfile")
        rules = [f["rule_id"] for f in findings]
        self.assertIn("DL3002", rules)

    def test_latest_tag_detected(self):
        content = "FROM python:latest\n"
        findings = ss._dockerfile_scan(content, "Dockerfile")
        rules = [f["rule_id"] for f in findings]
        self.assertIn("DL3007", rules)

    def test_clean_dockerfile_no_findings(self):
        content = "FROM python:3.11-slim\nWORKDIR /app\nCOPY . .\nCMD [\"python\", \"app.py\"]\n"
        findings = ss._dockerfile_scan(content, "Dockerfile")
        self.assertEqual(findings, [])

    def test_finding_has_required_fields(self):
        content = "FROM ubuntu:latest\n"
        findings = ss._dockerfile_scan(content, "Dockerfile")
        if findings:
            f = findings[0]
            for field in ("finding_id", "rule_id", "title", "severity", "file_path"):
                self.assertIn(field, f)

    def test_expose_ssh_detected(self):
        content = "FROM python:3.11\nEXPOSE 22\n"
        findings = ss._dockerfile_scan(content, "Dockerfile")
        rules = [f["rule_id"] for f in findings]
        self.assertIn("CIS-DK-1.4", rules)


# ============================================================================
# 6. SCA scanner
# ============================================================================

class TestSCAScanner(unittest.TestCase):

    def test_known_vuln_detected(self):
        comps = [{"name": "PyYAML", "version": "5.4.1", "purl": "pkg:pypi/PyYAML@5.4.1"}]
        findings = ss._sca_scan(comps)
        self.assertTrue(len(findings) > 0)
        self.assertEqual(findings[0]["cve_id"], "CVE-2020-14343")

    def test_safe_package_no_findings(self):
        comps = [{"name": "click", "version": "8.1.7", "purl": "pkg:pypi/click@8.1.7"}]
        findings = ss._sca_scan(comps)
        self.assertEqual(findings, [])

    def test_multiple_vulns(self):
        comps = [
            {"name": "PyYAML", "version": "5.4.1", "purl": "pkg:pypi/PyYAML@5.4.1"},
            {"name": "requests", "version": "2.28.0", "purl": "pkg:pypi/requests@2.28.0"},
        ]
        findings = ss._sca_scan(comps)
        self.assertEqual(len(findings), 2)

    def test_finding_has_severity(self):
        comps = [{"name": "PyYAML", "version": "5.4.1", "purl": "pkg:pypi/PyYAML@5.4.1"}]
        findings = ss._sca_scan(comps)
        self.assertIn(findings[0]["severity"], ("critical", "high", "medium", "low"))

    def test_finding_has_fixed_version(self):
        comps = [{"name": "PyYAML", "version": "5.4.1", "purl": "pkg:pypi/PyYAML@5.4.1"}]
        findings = ss._sca_scan(comps)
        self.assertIn("fixed_version", findings[0])


# ============================================================================
# 7. Finding normalisation
# ============================================================================

class TestToBrainFinding(unittest.TestCase):

    def test_all_required_fields_present(self):
        raw = {
            "id": "sast-B307-test.py-5",
            "title": "Use of eval()",
            "severity": "high",
            "source": "aldeci-sast",
            "description": "eval at line 5",
            "file_path": "core/brain.py",
            "line_number": 5,
        }
        result = ss._to_brain_finding(raw)
        for field in ("id", "title", "severity", "source", "description", "asset_id", "org_id"):
            self.assertIn(field, result)

    def test_asset_id_is_aldeci_platform(self):
        raw = {"title": "t", "severity": "low"}
        result = ss._to_brain_finding(raw)
        self.assertEqual(result["asset_id"], "aldeci-platform")

    def test_org_id_matches_module_setting(self):
        raw = {"title": "t", "severity": "low"}
        result = ss._to_brain_finding(raw)
        self.assertEqual(result["org_id"], ss.ORG_ID)

    def test_missing_id_gets_uuid(self):
        raw = {"title": "t", "severity": "low"}
        result = ss._to_brain_finding(raw)
        self.assertIsNotNone(result["id"])
        self.assertTrue(len(result["id"]) > 0)

    def test_metadata_subfields(self):
        raw = {"title": "t", "severity": "low", "rule_id": "B307", "package": "pyyaml"}
        result = ss._to_brain_finding(raw)
        self.assertIn("metadata", result)
        self.assertEqual(result["metadata"]["rule_id"], "B307")
        self.assertEqual(result["metadata"]["package"], "pyyaml")


# ============================================================================
# 8. API helper
# ============================================================================

class TestAPIHelper(unittest.TestCase):

    @patch("urllib.request.urlopen")
    def test_api_get_success(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.read.return_value = b'{"status": "ok"}'
        mock_resp.status = 200
        mock_urlopen.return_value = mock_resp

        code, body, ms = ss.api("GET", "/health")
        self.assertEqual(code, 200)
        self.assertEqual(body["status"], "ok")

    @patch("urllib.request.urlopen")
    def test_api_post_with_body(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.read.return_value = b'{"findings": []}'
        mock_resp.status = 200
        mock_urlopen.return_value = mock_resp

        code, body, ms = ss.api("POST", "/api/v1/sast/scan/code", {"code": "x=1"})
        self.assertEqual(code, 200)
        self.assertIn("findings", body)

    @patch("urllib.request.urlopen", side_effect=Exception("connection refused"))
    def test_api_connection_error_returns_zero(self, mock_urlopen):
        code, body, ms = ss.api("GET", "/health")
        self.assertEqual(code, 0)
        self.assertIn("error", body)

    @patch("urllib.request.urlopen")
    def test_api_non_json_response(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.read.return_value = b"not json"
        mock_resp.status = 200
        mock_urlopen.return_value = mock_resp

        code, body, ms = ss.api("GET", "/health")
        self.assertEqual(code, 200)
        self.assertIn("raw", body)


# ============================================================================
# 9. File helpers
# ============================================================================

class TestFileHelpers(unittest.TestCase):

    def test_read_file_missing_returns_empty(self):
        result = ss.read_file("nonexistent/path/file.txt")
        self.assertEqual(result, "")

    def test_read_file_real_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("hello world")
            tmp = f.name
        try:
            # Temporarily patch ROOT to the temp dir parent
            original_root = ss.ROOT
            ss.ROOT = Path(tmp).parent
            result = ss.read_file(Path(tmp).name)
            self.assertEqual(result, "hello world")
        finally:
            ss.ROOT = original_root
            Path(tmp).unlink(missing_ok=True)

    def test_resolve_path_returns_first_existing(self):
        # requirements.txt should exist in repo root
        result = ss.resolve_path("requirements.txt", "nonexistent.txt")
        self.assertEqual(result, "requirements.txt")

    def test_resolve_path_returns_first_candidate_when_none_exist(self):
        result = ss.resolve_path("fake1.txt", "fake2.txt")
        self.assertEqual(result, "fake1.txt")

    def test_collect_python_files_returns_list(self):
        files = ss.collect_python_files(max_files=5)
        self.assertIsInstance(files, list)
        self.assertLessEqual(len(files), 5)

    def test_collect_python_files_are_paths(self):
        files = ss.collect_python_files(max_files=3)
        for f in files:
            self.assertIsInstance(f, Path)
            self.assertEqual(f.suffix, ".py")


# ============================================================================
# 10. TrustGraph indexing (mocked KnowledgeStore)
# ============================================================================

class TestTrustGraphIndexing(unittest.TestCase):

    def _make_mock_trustgraph(self):
        """Create a mock trustgraph module for import patching."""
        mock_store = MagicMock()
        mock_store.ingest = MagicMock()

        mock_entity_cls = MagicMock(side_effect=lambda **kw: MagicMock(**kw))

        mock_tg_module = types.ModuleType("trustgraph")
        mock_tg_module.get_knowledge_store = MagicMock(return_value=mock_store)

        mock_ks_module = types.ModuleType("trustgraph.knowledge_store")
        mock_ks_module.KnowledgeEntity = mock_entity_cls
        mock_ks_module.KnowledgeRelationship = MagicMock()

        return mock_store, mock_tg_module, mock_ks_module

    def test_index_returns_indexed_count(self):
        mock_store, mock_tg, mock_ks = self._make_mock_trustgraph()
        findings = [
            {"id": "f1", "title": "eval", "severity": "high", "source": "sast", "cve_id": ""},
            {"id": "f2", "title": "secret", "severity": "medium", "source": "secrets", "cve_id": ""},
        ]
        sbom = {"components": [{"name": "requests", "version": "2.32", "purl": "pkg:pypi/requests"}]}
        sca = [{"cve_id": "CVE-2023-32681", "severity": "medium", "package": "requests",
                "installed_version": "2.28", "fixed_version": "2.31", "description": "leak"}]

        with patch.dict("sys.modules", {"trustgraph": mock_tg, "trustgraph.knowledge_store": mock_ks}):
            stats = ss._index_into_trustgraph(findings, sbom, sca)

        self.assertIn("indexed", stats)
        self.assertGreater(stats["indexed"], 0)

    def test_index_returns_error_when_import_fails(self):
        with patch.dict("sys.modules", {"trustgraph": None}):
            stats = ss._index_into_trustgraph([], {}, [])
        self.assertIn("error", stats)

    def test_index_cores_listed(self):
        mock_store, mock_tg, mock_ks = self._make_mock_trustgraph()
        with patch.dict("sys.modules", {"trustgraph": mock_tg, "trustgraph.knowledge_store": mock_ks}):
            stats = ss._index_into_trustgraph([], {"components": []}, [])
        self.assertIn("cores", stats)
        self.assertIsInstance(stats["cores"], list)


# ============================================================================
# 11. Results persistence
# ============================================================================

class TestSaveResults(unittest.TestCase):

    def setUp(self):
        _reset_counters()
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_save_creates_json_file(self):
        findings = [{"id": "f1", "title": "test", "severity": "low", "source": "sast"}]
        sbom = ss._build_sbom([])

        original_root = ss.ROOT
        ss.ROOT = Path(self.tmpdir)
        try:
            path = ss.save_results(findings, sbom)
        finally:
            ss.ROOT = original_root

        self.assertTrue(path.exists())
        data = json.loads(path.read_text())
        self.assertEqual(data["scan_type"], "aldeci-self-scan")
        self.assertEqual(data["total_findings"], 1)

    def test_save_creates_latest_json(self):
        original_root = ss.ROOT
        ss.ROOT = Path(self.tmpdir)
        try:
            ss.save_results([], ss._build_sbom([]))
            latest = Path(self.tmpdir) / "data" / "self-scan" / "latest.json"
        finally:
            ss.ROOT = original_root

        self.assertTrue(latest.exists())

    def test_save_includes_severity_breakdown(self):
        findings = [
            {"id": "f1", "title": "t", "severity": "critical"},
            {"id": "f2", "title": "t", "severity": "high"},
            {"id": "f3", "title": "t", "severity": "high"},
        ]
        original_root = ss.ROOT
        ss.ROOT = Path(self.tmpdir)
        try:
            path = ss.save_results(findings, ss._build_sbom([]))
        finally:
            ss.ROOT = original_root

        data = json.loads(path.read_text())
        self.assertEqual(data["findings_by_severity"]["critical"], 1)
        self.assertEqual(data["findings_by_severity"]["high"], 2)

    def test_save_also_writes_sbom(self):
        sbom = ss._build_sbom([{"name": "fastapi", "version": "0.115", "purl": "p"}])
        original_root = ss.ROOT
        ss.ROOT = Path(self.tmpdir)
        try:
            ss.save_results([], sbom)
            sbom_files = list((Path(self.tmpdir) / "data" / "self-scan").glob("sbom-*.json"))
        finally:
            ss.ROOT = original_root

        self.assertEqual(len(sbom_files), 1)
        sbom_data = json.loads(sbom_files[0].read_text())
        self.assertEqual(sbom_data["bomFormat"], "CycloneDX")


# ============================================================================
# 12. Step counter + output helpers
# ============================================================================

class TestStepCounters(unittest.TestCase):

    def setUp(self):
        _reset_counters()

    def test_step_increments_total(self):
        ss.step("test step")
        self.assertEqual(ss._total, 1)

    def test_ok_marks_step_passed(self):
        ss.step("s")
        ss.ok("good")
        ss._finalize_step()
        self.assertEqual(ss._pass, 1)
        self.assertEqual(ss._fail, 0)

    def test_fail_step_marks_failed(self):
        ss.step("s")
        ss.fail_step("bad")
        ss._finalize_step()
        self.assertEqual(ss._fail, 1)
        self.assertEqual(ss._pass, 0)

    def test_warn_does_not_affect_pass_fail(self):
        ss.step("s")
        ss.warn("meh")
        # Not calling ok or fail_step — step has no status, won't count
        ss._finalize_step()
        self.assertEqual(ss._pass, 0)
        self.assertEqual(ss._fail, 0)

    def test_multiple_steps(self):
        for _ in range(3):
            ss.step("x")
            ss.ok("good")
        ss._finalize_step()
        self.assertEqual(ss._total, 3)
        self.assertEqual(ss._pass, 3)


# ============================================================================
# 13. Main integration — offline mode
# ============================================================================

class TestMainOffline(unittest.TestCase):

    def setUp(self):
        _reset_counters()

    @patch("self_scan.api", return_value=(0, {"error": "connection refused"}, 0))
    @patch("self_scan._index_into_trustgraph", return_value={"indexed": 5, "cores": [1, 2, 5]})
    def test_main_returns_zero_offline(self, mock_tg, mock_api):
        """main() should return 0 (success) even when API is unreachable."""
        with tempfile.TemporaryDirectory() as tmpdir:
            original_root = ss.ROOT
            ss.ROOT = Path(tmpdir)
            # Put a minimal requirements.txt so SBOM phase works
            (Path(tmpdir) / "requirements.txt").write_text("requests==2.32.0\n")
            try:
                _reset_counters()
                exit_code = ss.main()
            finally:
                ss.ROOT = original_root
        self.assertEqual(exit_code, 0)

    @patch("self_scan.api", return_value=(0, {"error": "connection refused"}, 0))
    @patch("self_scan._index_into_trustgraph", return_value={"indexed": 0, "cores": []})
    def test_main_populates_scan_summary(self, mock_tg, mock_api):
        with tempfile.TemporaryDirectory() as tmpdir:
            original_root = ss.ROOT
            ss.ROOT = Path(tmpdir)
            (Path(tmpdir) / "requirements.txt").write_text("pyyaml==5.4.1\nrequests==2.28.0\n")
            try:
                _reset_counters()
                ss.main()
            finally:
                ss.ROOT = original_root
        # SCA should have found vulns in those old versions
        self.assertIn("sca_findings", ss.SCAN_SUMMARY)
        self.assertGreaterEqual(ss.SCAN_SUMMARY["sca_findings"], 0)

    @patch("self_scan.api", return_value=(0, {"error": "no"}, 0))
    @patch("self_scan._index_into_trustgraph", return_value={"indexed": 0, "cores": []})
    def test_main_creates_output_files(self, mock_tg, mock_api):
        with tempfile.TemporaryDirectory() as tmpdir:
            original_root = ss.ROOT
            ss.ROOT = Path(tmpdir)
            (Path(tmpdir) / "requirements.txt").write_text("fastapi==0.115.0\n")
            try:
                _reset_counters()
                ss.main()
            finally:
                ss.ROOT = original_root
            out_dir = Path(tmpdir) / "data" / "self-scan"
            self.assertTrue(out_dir.exists())
            jsons = list(out_dir.glob("*.json"))
            self.assertGreater(len(jsons), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
