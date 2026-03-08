"""Comprehensive tests for FixOps Remediation Engine (SPRINT1-005).

Covers:
- CWEFixRegistry: all 5 CWE fix templates (79, 89, 502, 78, 22)
- CWEFixTemplate: data class serialization
- RemediationEngine: strategy determination, CWE remediation, metrics
- RemediationResult: serialization
- Input normalization: various CWE ID formats
- Fix quality: each fix actually transforms vulnerable code correctly
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict

import pytest

from automation.remediation import (
    CWEFixRegistry,
    CWEFixTemplate,
    RemediationEngine,
    RemediationResult,
    RemediationStatus,
    RemediationStrategy,
)


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def engine() -> RemediationEngine:
    """Create a fresh RemediationEngine with auto_fix enabled."""
    return RemediationEngine({"auto_fix_enabled": True})


@pytest.fixture
def engine_manual() -> RemediationEngine:
    """Create a RemediationEngine with auto_fix disabled."""
    return RemediationEngine({"auto_fix_enabled": False})


@pytest.fixture
def finding_xss() -> Dict[str, Any]:
    return {
        "id": "FIND-XSS-001",
        "title": "Reflected XSS in user profile page",
        "severity": "high",
        "cwe_id": "CWE-79",
        "file_path": "web/profile.py",
        "language": "python",
        "code_snippet": (
            'from flask import request\n'
            'name = request.args.get("name")\n'
            'html = f"<div>{name}</div>"\n'
        ),
    }


@pytest.fixture
def finding_sqli() -> Dict[str, Any]:
    return {
        "id": "FIND-SQLI-001",
        "title": "SQL Injection in user login",
        "severity": "critical",
        "cwe_id": "CWE-89",
        "file_path": "auth/login.py",
        "language": "python",
        "code_snippet": (
            'import sqlite3\n'
            'conn = sqlite3.connect("app.db")\n'
            'user = request.form["username"]\n'
            'conn.execute(f"SELECT * FROM users WHERE name = {user}")\n'
        ),
    }


@pytest.fixture
def finding_deser() -> Dict[str, Any]:
    return {
        "id": "FIND-DESER-001",
        "title": "Insecure deserialization of user session",
        "severity": "critical",
        "cwe_id": "CWE-502",
        "file_path": "session/handler.py",
        "language": "python",
        "code_snippet": (
            'import pickle\n'
            'data = pickle.loads(session_cookie)\n'
        ),
    }


@pytest.fixture
def finding_cmdi() -> Dict[str, Any]:
    return {
        "id": "FIND-CMDI-001",
        "title": "Command injection via hostname parameter",
        "severity": "critical",
        "cwe_id": "CWE-78",
        "file_path": "util/network.py",
        "language": "python",
        "code_snippet": (
            'import os\n'
            'host = request.args.get("host")\n'
            'os.system(f"ping {host}")\n'
        ),
    }


@pytest.fixture
def finding_path() -> Dict[str, Any]:
    return {
        "id": "FIND-PATH-001",
        "title": "Path traversal in file download",
        "severity": "high",
        "cwe_id": "CWE-22",
        "file_path": "api/download.py",
        "language": "python",
        "code_snippet": (
            'filename = request.args.get("file")\n'
            'data = open(filename).read()\n'
        ),
    }


# ============================================================================
# CWEFixRegistry — supported CWEs
# ============================================================================


class TestCWEFixRegistrySupport:
    """Test CWE support detection."""

    def test_supported_cwes_returns_five(self):
        cwes = CWEFixRegistry.supported_cwes()
        assert len(cwes) == 5
        assert "CWE-22" in cwes
        assert "CWE-78" in cwes
        assert "CWE-79" in cwes
        assert "CWE-89" in cwes
        assert "CWE-502" in cwes

    def test_supported_cwes_sorted(self):
        cwes = CWEFixRegistry.supported_cwes()
        assert cwes == sorted(cwes)

    @pytest.mark.parametrize(
        "cwe_id",
        ["CWE-79", "CWE-89", "CWE-502", "CWE-78", "CWE-22"],
    )
    def test_can_fix_supported(self, cwe_id):
        assert CWEFixRegistry.can_fix(cwe_id) is True

    @pytest.mark.parametrize(
        "cwe_id",
        ["CWE-999", "CWE-0", "CWE-200", "not-a-cwe"],
    )
    def test_cannot_fix_unsupported(self, cwe_id):
        assert CWEFixRegistry.can_fix(cwe_id) is False


# ============================================================================
# CWEFixRegistry — normalization
# ============================================================================


class TestCWENormalization:
    """Test CWE ID normalization accepts various formats."""

    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("CWE-79", "CWE-79"),
            ("cwe-79", "CWE-79"),
            ("79", "CWE-79"),
            ("CWE79", "CWE-79"),
            ("cwe79", "CWE-79"),
            ("CWE-089", "CWE-89"),
            ("  CWE-79  ", "CWE-79"),
        ],
    )
    def test_normalize_variants(self, raw, expected):
        assert CWEFixRegistry._normalize_cwe(raw) == expected

    def test_can_fix_with_different_formats(self):
        """All format variants should be recognized."""
        for fmt in ("CWE-79", "cwe-79", "79", "CWE79", "cwe79"):
            assert CWEFixRegistry.can_fix(fmt) is True


# ============================================================================
# CWE-79: XSS Fix
# ============================================================================


class TestCWE79Fix:
    """Validate CWE-79 (XSS) fix template."""

    def test_generates_fix(self, finding_xss):
        fix = CWEFixRegistry.generate_fix("CWE-79", finding_xss, finding_xss["code_snippet"])
        assert isinstance(fix, CWEFixTemplate)
        assert fix.cwe_id == "CWE-79"
        assert fix.cwe_name == "Cross-Site Scripting (XSS)"

    def test_fix_adds_html_escape_import(self, finding_xss):
        fix = CWEFixRegistry.generate_fix("CWE-79", finding_xss, finding_xss["code_snippet"])
        assert "markupsafe" in fix.fix_code.lower() or "_html_escape" in fix.fix_code

    def test_fix_adds_csp_header(self, finding_xss):
        fix = CWEFixRegistry.generate_fix("CWE-79", finding_xss, finding_xss["code_snippet"])
        assert "Content-Security-Policy" in fix.fix_code

    def test_fix_wraps_interpolated_vars(self, finding_xss):
        fix = CWEFixRegistry.generate_fix("CWE-79", finding_xss, finding_xss["code_snippet"])
        # The {name} in f-string should be wrapped with _html_escape
        assert "_html_escape" in fix.fix_code

    def test_fix_has_test_code(self, finding_xss):
        fix = CWEFixRegistry.generate_fix("CWE-79", finding_xss, finding_xss["code_snippet"])
        assert "class TestCWE79Fix" in fix.test_code
        assert "XSS_PAYLOADS" in fix.test_code

    def test_fix_has_pr_metadata(self, finding_xss):
        fix = CWEFixRegistry.generate_fix("CWE-79", finding_xss, finding_xss["code_snippet"])
        assert "CWE-79" in fix.pr_title
        assert fix.pr_description
        assert "XSS" in fix.pr_title or "xss" in fix.pr_title.lower()

    def test_fix_confidence_high(self, finding_xss):
        fix = CWEFixRegistry.generate_fix("CWE-79", finding_xss, finding_xss["code_snippet"])
        assert fix.confidence >= 0.85

    def test_fix_has_compliance_refs(self, finding_xss):
        fix = CWEFixRegistry.generate_fix("CWE-79", finding_xss, finding_xss["code_snippet"])
        assert "CWE-79" in fix.compliance_refs
        assert any("OWASP" in r for r in fix.compliance_refs)

    def test_fix_files_modified(self, finding_xss):
        fix = CWEFixRegistry.generate_fix("CWE-79", finding_xss, finding_xss["code_snippet"])
        assert finding_xss["file_path"] in fix.files_modified

    def test_js_xss_fix(self):
        """Test JavaScript XSS fix generates DOMPurify import."""
        finding = {"file_path": "app.tsx", "language": "javascript", "severity": "high"}
        source = 'element.innerHTML = userInput;'
        fix = CWEFixRegistry.generate_fix("CWE-79", finding, source)
        assert "DOMPurify" in fix.fix_code


# ============================================================================
# CWE-89: SQL Injection Fix
# ============================================================================


class TestCWE89Fix:
    """Validate CWE-89 (SQL Injection) fix template."""

    def test_generates_fix(self, finding_sqli):
        fix = CWEFixRegistry.generate_fix("CWE-89", finding_sqli, finding_sqli["code_snippet"])
        assert isinstance(fix, CWEFixTemplate)
        assert fix.cwe_id == "CWE-89"

    def test_replaces_fstring_sql(self, finding_sqli):
        fix = CWEFixRegistry.generate_fix("CWE-89", finding_sqli, finding_sqli["code_snippet"])
        # Should not contain f-string SQL
        assert 'f"SELECT' not in fix.fix_code
        # Should contain parameterized marker
        assert "?" in fix.fix_code or "%s" in fix.fix_code

    def test_adds_parameterized_comment(self, finding_sqli):
        fix = CWEFixRegistry.generate_fix("CWE-89", finding_sqli, finding_sqli["code_snippet"])
        assert "FIXOPS" in fix.fix_code
        assert "CWE-89" in fix.fix_code

    def test_fix_has_test_code(self, finding_sqli):
        fix = CWEFixRegistry.generate_fix("CWE-89", finding_sqli, finding_sqli["code_snippet"])
        assert "class TestCWE89Fix" in fix.test_code
        assert "SQL_INJECTION_PAYLOADS" in fix.test_code

    def test_fix_pr_title(self, finding_sqli):
        fix = CWEFixRegistry.generate_fix("CWE-89", finding_sqli, finding_sqli["code_snippet"])
        assert "CWE-89" in fix.pr_title
        assert "SQL" in fix.pr_title.upper() or "injection" in fix.pr_title.lower()

    def test_fix_confidence_very_high(self, finding_sqli):
        fix = CWEFixRegistry.generate_fix("CWE-89", finding_sqli, finding_sqli["code_snippet"])
        # SQL injection parameterization is a well-understood fix
        assert fix.confidence >= 0.90

    def test_percent_format_sql_replaced(self):
        """Test that %-formatted SQL is also fixed."""
        finding = {"file_path": "old_db.py", "severity": "critical", "language": "python"}
        source = 'cursor.execute("SELECT * FROM t WHERE id = %s" % user_id)'
        fix = CWEFixRegistry.generate_fix("CWE-89", finding, source)
        # The %-format should be replaced with parameterized query
        assert "FIXOPS" in fix.fix_code

    def test_concat_sql_replaced(self):
        """Test that string concatenation SQL is fixed."""
        finding = {"file_path": "legacy.py", "severity": "critical", "language": "python"}
        source = 'cursor.execute("SELECT * FROM users WHERE name = " + name + "")'
        fix = CWEFixRegistry.generate_fix("CWE-89", finding, source)
        assert "FIXOPS" in fix.fix_code


# ============================================================================
# CWE-502: Insecure Deserialization Fix
# ============================================================================


class TestCWE502Fix:
    """Validate CWE-502 (Deserialization) fix template."""

    def test_generates_fix(self, finding_deser):
        fix = CWEFixRegistry.generate_fix("CWE-502", finding_deser, finding_deser["code_snippet"])
        assert isinstance(fix, CWEFixTemplate)
        assert fix.cwe_id == "CWE-502"

    def test_replaces_pickle_with_json(self, finding_deser):
        fix = CWEFixRegistry.generate_fix("CWE-502", finding_deser, finding_deser["code_snippet"])
        assert "json.loads" in fix.fix_code
        # pickle.loads should be replaced
        assert "pickle.loads" not in fix.fix_code

    def test_adds_json_import(self, finding_deser):
        fix = CWEFixRegistry.generate_fix("CWE-502", finding_deser, finding_deser["code_snippet"])
        assert "import json" in fix.fix_code

    def test_yaml_unsafe_replaced(self):
        """Test that yaml.load is replaced with yaml.safe_load."""
        finding = {"file_path": "config.py", "severity": "high", "language": "python"}
        source = 'import yaml\ndata = yaml.load(user_data, Loader=yaml.FullLoader)'
        fix = CWEFixRegistry.generate_fix("CWE-502", finding, source)
        assert "safe_load" in fix.fix_code
        assert "yaml.load(" not in fix.fix_code

    def test_fix_has_test_code(self, finding_deser):
        fix = CWEFixRegistry.generate_fix("CWE-502", finding_deser, finding_deser["code_snippet"])
        assert "class TestCWE502Fix" in fix.test_code

    def test_fix_confidence_high(self, finding_deser):
        fix = CWEFixRegistry.generate_fix("CWE-502", finding_deser, finding_deser["code_snippet"])
        assert fix.confidence >= 0.90


# ============================================================================
# CWE-78: OS Command Injection Fix
# ============================================================================


class TestCWE78Fix:
    """Validate CWE-78 (Command Injection) fix template."""

    def test_generates_fix(self, finding_cmdi):
        fix = CWEFixRegistry.generate_fix("CWE-78", finding_cmdi, finding_cmdi["code_snippet"])
        assert isinstance(fix, CWEFixTemplate)
        assert fix.cwe_id == "CWE-78"

    def test_replaces_os_system(self, finding_cmdi):
        fix = CWEFixRegistry.generate_fix("CWE-78", finding_cmdi, finding_cmdi["code_snippet"])
        assert "os.system(" not in fix.fix_code
        assert "subprocess" in fix.fix_code

    def test_adds_subprocess_import(self, finding_cmdi):
        fix = CWEFixRegistry.generate_fix("CWE-78", finding_cmdi, finding_cmdi["code_snippet"])
        assert "import subprocess" in fix.fix_code

    def test_adds_shlex_import(self, finding_cmdi):
        fix = CWEFixRegistry.generate_fix("CWE-78", finding_cmdi, finding_cmdi["code_snippet"])
        assert "import shlex" in fix.fix_code

    def test_no_shell_true(self, finding_cmdi):
        fix = CWEFixRegistry.generate_fix("CWE-78", finding_cmdi, finding_cmdi["code_snippet"])
        assert "shell=True" not in fix.fix_code

    def test_os_popen_replaced(self):
        """Test os.popen replacement."""
        finding = {"file_path": "util.py", "severity": "critical", "language": "python"}
        source = 'result = os.popen(cmd).read()'
        fix = CWEFixRegistry.generate_fix("CWE-78", finding, source)
        assert "os.popen(" not in fix.fix_code
        assert "subprocess" in fix.fix_code

    def test_shell_true_disabled(self):
        """Test shell=True is converted to shell=False in code (not comments)."""
        finding = {"file_path": "run.py", "severity": "critical", "language": "python"}
        source = 'subprocess.run(cmd, shell=True)'
        fix = CWEFixRegistry.generate_fix("CWE-78", finding, source)
        # Check non-comment lines only
        code_lines = [ln for ln in fix.fix_code.splitlines() if not ln.strip().startswith("#")]
        code_only = "\n".join(code_lines)
        assert "shell=True" not in code_only
        assert "shell=False" in code_only

    def test_fix_has_test_code(self, finding_cmdi):
        fix = CWEFixRegistry.generate_fix("CWE-78", finding_cmdi, finding_cmdi["code_snippet"])
        assert "class TestCWE78Fix" in fix.test_code
        assert "INJECTION_PAYLOADS" in fix.test_code


# ============================================================================
# CWE-22: Path Traversal Fix
# ============================================================================


class TestCWE22Fix:
    """Validate CWE-22 (Path Traversal) fix template."""

    def test_generates_fix(self, finding_path):
        fix = CWEFixRegistry.generate_fix("CWE-22", finding_path, finding_path["code_snippet"])
        assert isinstance(fix, CWEFixTemplate)
        assert fix.cwe_id == "CWE-22"

    def test_adds_path_canonicalization(self, finding_path):
        fix = CWEFixRegistry.generate_fix("CWE-22", finding_path, finding_path["code_snippet"])
        assert "realpath" in fix.fix_code

    def test_adds_safe_path_function(self, finding_path):
        fix = CWEFixRegistry.generate_fix("CWE-22", finding_path, finding_path["code_snippet"])
        assert "_fixops_safe_path" in fix.fix_code

    def test_adds_traversal_guard(self, finding_path):
        fix = CWEFixRegistry.generate_fix("CWE-22", finding_path, finding_path["code_snippet"])
        assert ".." in fix.fix_code  # Checks for '..' traversal
        assert "ValueError" in fix.fix_code

    def test_wraps_open_calls(self, finding_path):
        fix = CWEFixRegistry.generate_fix("CWE-22", finding_path, finding_path["code_snippet"])
        # open(filename) should be wrapped with safe path
        assert "_fixops_safe_path" in fix.fix_code

    def test_os_path_join_replaced(self):
        """Test os.path.join is replaced with safe variant."""
        finding = {"file_path": "files.py", "severity": "high", "language": "python"}
        source = 'import os\npath = os.path.join(base_dir, user_file)\ndata = open(path).read()'
        fix = CWEFixRegistry.generate_fix("CWE-22", finding, source)
        assert "_fixops_safe_path" in fix.fix_code

    def test_fix_has_test_code(self, finding_path):
        fix = CWEFixRegistry.generate_fix("CWE-22", finding_path, finding_path["code_snippet"])
        assert "class TestCWE22Fix" in fix.test_code
        assert "TRAVERSAL_PAYLOADS" in fix.test_code

    def test_fix_confidence_high(self, finding_path):
        fix = CWEFixRegistry.generate_fix("CWE-22", finding_path, finding_path["code_snippet"])
        assert fix.confidence >= 0.90


# ============================================================================
# CWEFixTemplate data class
# ============================================================================


class TestCWEFixTemplate:
    """Test CWEFixTemplate data structure."""

    def test_to_dict(self, finding_xss):
        fix = CWEFixRegistry.generate_fix("CWE-79", finding_xss, finding_xss["code_snippet"])
        d = fix.to_dict()
        assert d["cwe_id"] == "CWE-79"
        assert d["cwe_name"] == "Cross-Site Scripting (XSS)"
        assert isinstance(d["fix_code"], str)
        assert isinstance(d["test_code"], str)
        assert isinstance(d["pr_title"], str)
        assert isinstance(d["pr_description"], str)
        assert isinstance(d["files_modified"], list)
        assert isinstance(d["confidence"], float)
        assert isinstance(d["mitre_techniques"], list)
        assert isinstance(d["compliance_refs"], list)

    def test_to_dict_serializable(self, finding_xss):
        """Verify to_dict output is JSON-serializable."""
        fix = CWEFixRegistry.generate_fix("CWE-79", finding_xss, finding_xss["code_snippet"])
        d = fix.to_dict()
        serialized = json.dumps(d)
        assert isinstance(serialized, str)
        deserialized = json.loads(serialized)
        assert deserialized["cwe_id"] == "CWE-79"


# ============================================================================
# RemediationResult
# ============================================================================


class TestRemediationResult:
    """Test RemediationResult serialization."""

    def test_default_values(self):
        r = RemediationResult(finding_id="test-001")
        assert r.status == RemediationStatus.PENDING
        assert r.strategy == RemediationStrategy.GUIDED
        assert r.pillar == "V7"
        assert r.cwe_fix is None

    def test_to_dict_without_cwe_fix(self):
        r = RemediationResult(finding_id="test-001")
        d = r.to_dict()
        assert d["finding_id"] == "test-001"
        assert d["status"] == "pending"
        assert d["strategy"] == "guided"
        assert d["pillar"] == "V7"
        assert "cwe_fix" not in d

    def test_to_dict_with_cwe_fix(self, finding_xss):
        fix = CWEFixRegistry.generate_fix("CWE-79", finding_xss, finding_xss["code_snippet"])
        r = RemediationResult(
            finding_id="test-xss",
            status=RemediationStatus.FIX_GENERATED,
            cwe_fix=fix,
        )
        d = r.to_dict()
        assert "cwe_fix" in d
        assert d["cwe_fix"]["cwe_id"] == "CWE-79"

    def test_to_dict_json_serializable(self, finding_xss):
        fix = CWEFixRegistry.generate_fix("CWE-79", finding_xss, finding_xss["code_snippet"])
        r = RemediationResult(
            finding_id="test-xss",
            status=RemediationStatus.FIX_GENERATED,
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
            cwe_fix=fix,
        )
        serialized = json.dumps(r.to_dict())
        assert isinstance(serialized, str)


# ============================================================================
# RemediationEngine — strategy determination
# ============================================================================


class TestRemediationStrategy:
    """Test strategy determination logic."""

    def test_cwe_finding_gets_auto_fix(self, engine, finding_xss):
        strategy = engine.determine_strategy(finding_xss)
        assert strategy == RemediationStrategy.AUTO_FIX

    def test_critical_with_fix_gets_auto_fix(self, engine):
        finding = {"severity": "critical", "fix_available": True}
        assert engine.determine_strategy(finding) == RemediationStrategy.AUTO_FIX

    def test_high_with_fix_gets_auto_fix(self, engine):
        finding = {"severity": "high", "fix_available": True}
        assert engine.determine_strategy(finding) == RemediationStrategy.AUTO_FIX

    def test_medium_with_fix_gets_guided(self, engine):
        finding = {"severity": "medium", "fix_available": True}
        assert engine.determine_strategy(finding) == RemediationStrategy.GUIDED

    def test_low_no_fix_gets_manual(self, engine):
        finding = {"severity": "low", "fix_available": False}
        assert engine.determine_strategy(finding) == RemediationStrategy.MANUAL

    def test_disabled_auto_fix_always_manual(self, engine_manual):
        finding = {"severity": "critical", "fix_available": True, "cwe_id": "CWE-79"}
        assert engine_manual.determine_strategy(finding) == RemediationStrategy.MANUAL


# ============================================================================
# RemediationEngine — CWE remediation
# ============================================================================


class TestRemediationEngineCWE:
    """Test the remediate_cwe method."""

    @pytest.mark.parametrize("cwe_id", ["CWE-79", "CWE-89", "CWE-502", "CWE-78", "CWE-22"])
    def test_remediate_all_supported_cwes(self, engine, cwe_id):
        finding = {
            "file_path": "test.py",
            "severity": "high",
            "language": "python",
            "code_snippet": "# vulnerable code",
        }
        result = engine.remediate_cwe(f"finding-{cwe_id}", cwe_id, finding)
        assert result.status == RemediationStatus.FIX_GENERATED
        assert result.cwe_fix is not None
        assert result.cwe_fix.cwe_id == cwe_id

    def test_remediate_unsupported_cwe(self, engine):
        finding = {"file_path": "test.py", "severity": "high"}
        result = engine.remediate_cwe("finding-999", "CWE-999", finding)
        assert result.status == RemediationStatus.FAILED
        assert "No fix template" in result.error

    def test_remediate_stores_result(self, engine, finding_xss):
        engine.remediate_cwe("xss-1", "CWE-79", finding_xss, finding_xss["code_snippet"])
        stored = engine.get_result("xss-1")
        assert stored is not None
        assert stored.status == RemediationStatus.FIX_GENERATED

    def test_remediate_sets_timestamps(self, engine, finding_xss):
        result = engine.remediate_cwe("xss-2", "CWE-79", finding_xss)
        assert result.started_at is not None
        assert result.completed_at is not None
        assert result.completed_at >= result.started_at

    def test_remediate_sets_files_modified(self, engine, finding_xss):
        result = engine.remediate_cwe("xss-3", "CWE-79", finding_xss)
        assert len(result.files_modified) > 0
        assert finding_xss["file_path"] in result.files_modified

    def test_remediate_with_source_code(self, engine, finding_sqli):
        vulnerable_code = 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")'
        result = engine.remediate_cwe(
            "sqli-1", "CWE-89", finding_sqli, source_code=vulnerable_code
        )
        assert result.status == RemediationStatus.FIX_GENERATED
        assert result.cwe_fix is not None
        # Fix should have transformed the code
        assert result.cwe_fix.fix_code != vulnerable_code


# ============================================================================
# RemediationEngine — full remediate() with CWE integration
# ============================================================================


class TestRemediationEngineFullFlow:
    """Test the main remediate() method integrating CWE templates."""

    def test_auto_remediate_uses_cwe_template(self, engine, finding_xss):
        """When finding has a supported cwe_id, auto_fix uses CWE template."""
        result = engine.remediate(
            "full-xss-1",
            finding_xss,
            strategy=RemediationStrategy.AUTO_FIX,
        )
        assert result.status == RemediationStatus.FIX_GENERATED
        assert result.cwe_fix is not None

    def test_guided_remediate_uses_cwe_template(self, engine, finding_sqli):
        """Guided mode also uses CWE templates when available."""
        result = engine.remediate(
            "full-sqli-1",
            finding_sqli,
            strategy=RemediationStrategy.GUIDED,
        )
        assert result.status == RemediationStatus.FIX_GENERATED
        assert result.cwe_fix is not None

    def test_accept_risk_skips(self, engine, finding_xss):
        result = engine.remediate(
            "skip-1",
            finding_xss,
            strategy=RemediationStrategy.ACCEPT_RISK,
        )
        assert result.status == RemediationStatus.SKIPPED
        assert result.cwe_fix is None

    def test_manual_strategy(self, engine):
        finding = {"severity": "low", "title": "Info disclosure"}
        result = engine.remediate("manual-1", finding, strategy=RemediationStrategy.MANUAL)
        assert result.status == RemediationStatus.PENDING

    def test_auto_strategy_detection_with_cwe(self, engine, finding_cmdi):
        """When strategy is None, engine auto-detects based on CWE."""
        result = engine.remediate("auto-cmdi-1", finding_cmdi)
        # Should auto-detect AUTO_FIX because CWE-78 is supported
        assert result.strategy == RemediationStrategy.AUTO_FIX
        assert result.cwe_fix is not None


# ============================================================================
# RemediationEngine — metrics
# ============================================================================


class TestRemediationMetrics:
    """Test metrics collection."""

    def test_empty_metrics(self, engine):
        m = engine.get_metrics()
        assert m["total"] == 0
        assert m["success_rate"] == 0.0
        assert "CWE-79" in m["supported_cwes"]

    def test_metrics_after_remediation(self, engine, finding_xss, finding_sqli):
        engine.remediate_cwe("m-1", "CWE-79", finding_xss)
        engine.remediate_cwe("m-2", "CWE-89", finding_sqli)
        m = engine.get_metrics()
        assert m["total"] == 2
        assert m["cwe_fixes"] == 2
        assert m["success_rate"] == 1.0
        assert m["by_status"]["fix_generated"] == 2

    def test_metrics_include_failures(self, engine):
        engine.remediate_cwe("m-fail", "CWE-999", {"file_path": "x.py"})
        m = engine.get_metrics()
        assert m["total"] == 1
        assert m["success_rate"] == 0.0
        assert m["by_status"]["failed"] == 1
        assert m["cwe_fixes"] == 0

    def test_get_all_results(self, engine, finding_xss):
        engine.remediate_cwe("r1", "CWE-79", finding_xss)
        engine.remediate_cwe("r2", "CWE-79", finding_xss)
        all_results = engine.get_all_results()
        assert len(all_results) == 2
        assert "r1" in all_results
        assert "r2" in all_results


# ============================================================================
# Error handling
# ============================================================================


class TestErrorHandling:
    """Test error handling and edge cases."""

    def test_unsupported_cwe_raises_valueerror(self):
        with pytest.raises(ValueError, match="Unsupported CWE"):
            CWEFixRegistry.generate_fix("CWE-999", {"file_path": "x.py"})

    def test_empty_source_code(self, finding_xss):
        """Fix should work even with empty source code."""
        fix = CWEFixRegistry.generate_fix("CWE-79", finding_xss, "")
        assert fix.fix_code  # Should still produce something
        assert fix.test_code

    def test_none_source_code(self, finding_xss):
        """Fix should work with None source code."""
        fix = CWEFixRegistry.generate_fix("CWE-79", finding_xss, None)
        assert fix.fix_code
        assert fix.test_code

    def test_minimal_finding(self):
        """Fix should work with minimal finding dict."""
        fix = CWEFixRegistry.generate_fix("CWE-89", {})
        assert fix.cwe_id == "CWE-89"
        assert fix.fix_code is not None

    def test_remediate_exception_handling(self, engine):
        """Engine should catch exceptions and return FAILED status."""
        # This should not raise
        result = engine.remediate_cwe("err-1", "CWE-999", {})
        assert result.status == RemediationStatus.FAILED
        assert result.error is not None


# ============================================================================
# Fix quality — verify transforms are correct
# ============================================================================


class TestFixQuality:
    """Verify the generated fixes actually transform code correctly."""

    def test_cwe79_escapes_xss_payload(self):
        """The XSS fix should escape HTML in f-string context."""
        vulnerable = 'html = f"<h1>{user_name}</h1>"'
        finding = {"file_path": "page.py", "severity": "high", "language": "python"}
        fix = CWEFixRegistry.generate_fix("CWE-79", finding, vulnerable)
        # user_name should be wrapped with _html_escape
        assert "_html_escape(user_name)" in fix.fix_code

    def test_cwe89_parameterizes_fstring_query(self):
        """The SQL fix should parameterize f-string queries."""
        vulnerable = 'cursor.execute(f"SELECT * FROM users WHERE id = {uid}")'
        finding = {"file_path": "q.py", "severity": "critical", "language": "python"}
        fix = CWEFixRegistry.generate_fix("CWE-89", finding, vulnerable)
        assert "?" in fix.fix_code
        assert "uid" in fix.fix_code
        assert 'f"SELECT' not in fix.fix_code

    def test_cwe502_replaces_pickle(self):
        """The deserialization fix should remove pickle.loads."""
        vulnerable = 'import pickle\nobj = pickle.loads(raw_data)'
        finding = {"file_path": "deser.py", "severity": "critical", "language": "python"}
        fix = CWEFixRegistry.generate_fix("CWE-502", finding, vulnerable)
        assert "pickle.loads" not in fix.fix_code
        assert "json.loads" in fix.fix_code

    def test_cwe78_removes_os_system(self):
        """The command injection fix should remove os.system."""
        vulnerable = 'import os\nos.system(f"nmap {target}")'
        finding = {"file_path": "scan.py", "severity": "critical", "language": "python"}
        fix = CWEFixRegistry.generate_fix("CWE-78", finding, vulnerable)
        assert "os.system(" not in fix.fix_code
        assert "subprocess" in fix.fix_code

    def test_cwe22_adds_path_guard(self):
        """The path traversal fix should add realpath validation."""
        vulnerable = 'path = os.path.join(uploads, filename)\nopen(path)'
        finding = {"file_path": "dl.py", "severity": "high", "language": "python"}
        fix = CWEFixRegistry.generate_fix("CWE-22", finding, vulnerable)
        assert "_fixops_safe_path" in fix.fix_code
        assert "realpath" in fix.fix_code


# ============================================================================
# PR description format
# ============================================================================


class TestPRDescription:
    """Test PR description generation."""

    @pytest.mark.parametrize("cwe_id", ["CWE-79", "CWE-89", "CWE-502", "CWE-78", "CWE-22"])
    def test_pr_description_has_required_sections(self, cwe_id):
        finding = {"file_path": "test.py", "severity": "critical", "language": "python"}
        fix = CWEFixRegistry.generate_fix(cwe_id, finding, "# vulnerable")
        desc = fix.pr_description
        assert "## Security Fix" in desc
        assert "Severity" in desc
        assert "File" in desc
        assert "CWE" in desc
        assert "What changed" in desc
        assert "Testing" in desc
        assert "Rollback" in desc
        assert "FixOps" in desc

    @pytest.mark.parametrize("cwe_id", ["CWE-79", "CWE-89", "CWE-502", "CWE-78", "CWE-22"])
    def test_pr_title_format(self, cwe_id):
        finding = {"file_path": "src/app.py", "severity": "high", "language": "python"}
        fix = CWEFixRegistry.generate_fix(cwe_id, finding)
        assert fix.pr_title.startswith("fix(security):")
        assert cwe_id in fix.pr_title
