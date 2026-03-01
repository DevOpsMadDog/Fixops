"""
Comprehensive unit tests for suite-core/automation/remediation.py.

Covers:
  - RemediationStatus and RemediationStrategy enums
  - CWEFixTemplate: construction, to_dict
  - RemediationResult: construction, to_dict, optional cwe_fix
  - CWEFixRegistry: supported_cwes, can_fix, _normalize_cwe, generate_fix
  - CWE-79 (XSS): Python fix, JS fix, test code generation
  - CWE-89 (SQL Injection): Python parameterized queries
  - CWE-502 (Insecure Deserialization): pickle/yaml/marshal replacement
  - CWE-78 (OS Command Injection): os.system/os.popen replacement
  - CWE-22 (Path Traversal): path canonicalization
  - _build_cwe_pr_description: formatting, diff inclusion
  - RemediationEngine: init, determine_strategy, remediate, remediate_cwe,
    auto_fix_enabled, manual fallback, error handling
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from automation.remediation import (
    RemediationStatus,
    RemediationStrategy,
    CWEFixTemplate,
    RemediationResult,
    CWEFixRegistry,
    RemediationEngine,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def xss_finding():
    return {
        "file_path": "app.py",
        "title": "XSS in user profile",
        "severity": "high",
        "language": "python",
        "code_snippet": 'from flask import request\nreturn f"<h1>{name}</h1>"',
    }


@pytest.fixture
def sqli_finding():
    return {
        "file_path": "db.py",
        "title": "SQL Injection in search",
        "severity": "critical",
        "language": "python",
        "code_snippet": 'cursor.execute(f"SELECT * FROM users WHERE name = \'{user_input}\'")',
    }


@pytest.fixture
def deserialization_finding():
    return {
        "file_path": "serializer.py",
        "title": "Insecure Deserialization",
        "severity": "critical",
        "language": "python",
        "code_snippet": "import pickle\ndata = pickle.loads(user_data)",
    }


@pytest.fixture
def command_injection_finding():
    return {
        "file_path": "executor.py",
        "title": "OS Command Injection",
        "severity": "critical",
        "language": "python",
        "code_snippet": 'os.system(f"ping {host}")',
    }


@pytest.fixture
def path_traversal_finding():
    return {
        "file_path": "file_handler.py",
        "title": "Path Traversal",
        "severity": "high",
        "language": "python",
        "code_snippet": 'content = open(user_path).read()',
    }


@pytest.fixture
def engine():
    return RemediationEngine()


# ===========================================================================
# Enums
# ===========================================================================


class TestEnums:
    def test_remediation_status_values(self):
        assert RemediationStatus.PENDING.value == "pending"
        assert RemediationStatus.FIX_GENERATED.value == "fix_generated"
        assert RemediationStatus.PR_CREATED.value == "pr_created"
        assert RemediationStatus.VERIFIED.value == "verified"
        assert RemediationStatus.FAILED.value == "failed"

    def test_remediation_strategy_values(self):
        assert RemediationStrategy.AUTO_FIX.value == "auto_fix"
        assert RemediationStrategy.GUIDED.value == "guided"
        assert RemediationStrategy.MANUAL.value == "manual"
        assert RemediationStrategy.ACCEPT_RISK.value == "accept_risk"
        assert RemediationStrategy.COMPENSATING.value == "compensating"


# ===========================================================================
# CWEFixTemplate
# ===========================================================================


class TestCWEFixTemplate:
    def test_construction_defaults(self):
        tpl = CWEFixTemplate(
            cwe_id="CWE-79",
            cwe_name="XSS",
            fix_code="safe code",
            test_code="test code",
            pr_title="Fix XSS",
            pr_description="Description",
        )
        assert tpl.language == "python"
        assert tpl.effort_minutes == 15
        assert tpl.confidence == 0.90
        assert tpl.files_modified == []

    def test_to_dict(self):
        tpl = CWEFixTemplate(
            cwe_id="CWE-89",
            cwe_name="SQL Injection",
            fix_code="safe_sql",
            test_code="test_sql",
            pr_title="Fix SQLi",
            pr_description="Desc",
            files_modified=["db.py"],
            mitre_techniques=["T1190"],
            compliance_refs=["OWASP A03"],
        )
        d = tpl.to_dict()
        assert d["cwe_id"] == "CWE-89"
        assert d["files_modified"] == ["db.py"]
        assert d["mitre_techniques"] == ["T1190"]
        assert d["confidence"] == 0.90


# ===========================================================================
# RemediationResult
# ===========================================================================


class TestRemediationResult:
    def test_default_values(self):
        result = RemediationResult(finding_id="F-001")
        assert result.status == RemediationStatus.PENDING
        assert result.strategy == RemediationStrategy.GUIDED
        assert result.pillar == "V7"

    def test_to_dict_without_cwe_fix(self):
        result = RemediationResult(
            finding_id="F-001",
            status=RemediationStatus.FIX_GENERATED,
            strategy=RemediationStrategy.AUTO_FIX,
            fix_description="Applied XSS fix",
            files_modified=["app.py"],
        )
        d = result.to_dict()
        assert d["finding_id"] == "F-001"
        assert d["status"] == "fix_generated"
        assert d["strategy"] == "auto_fix"
        assert "cwe_fix" not in d

    def test_to_dict_with_cwe_fix(self):
        tpl = CWEFixTemplate(
            cwe_id="CWE-79",
            cwe_name="XSS",
            fix_code="safe",
            test_code="test",
            pr_title="Fix",
            pr_description="Desc",
        )
        result = RemediationResult(finding_id="F-002", cwe_fix=tpl)
        d = result.to_dict()
        assert "cwe_fix" in d
        assert d["cwe_fix"]["cwe_id"] == "CWE-79"

    def test_to_dict_with_timestamps(self):
        now = datetime.now(timezone.utc)
        result = RemediationResult(
            finding_id="F-003",
            started_at=now,
            completed_at=now,
        )
        d = result.to_dict()
        assert d["started_at"] is not None
        assert d["completed_at"] is not None

    def test_to_dict_none_timestamps(self):
        result = RemediationResult(finding_id="F-004")
        d = result.to_dict()
        assert d["started_at"] is None
        assert d["completed_at"] is None


# ===========================================================================
# CWEFixRegistry: normalization
# ===========================================================================


class TestCWENormalization:
    def test_standard_format(self):
        assert CWEFixRegistry._normalize_cwe("CWE-79") == "CWE-79"

    def test_lowercase(self):
        assert CWEFixRegistry._normalize_cwe("cwe-89") == "CWE-89"

    def test_digits_only(self):
        assert CWEFixRegistry._normalize_cwe("79") == "CWE-79"

    def test_no_dash(self):
        assert CWEFixRegistry._normalize_cwe("CWE79") == "CWE-79"

    def test_lowercase_no_dash(self):
        assert CWEFixRegistry._normalize_cwe("cwe502") == "CWE-502"

    def test_no_digits(self):
        result = CWEFixRegistry._normalize_cwe("XYZ")
        assert result == "XYZ"  # Falls through, no digits extracted

    def test_leading_trailing_spaces(self):
        assert CWEFixRegistry._normalize_cwe("  CWE-22  ") == "CWE-22"


# ===========================================================================
# CWEFixRegistry: supported_cwes / can_fix
# ===========================================================================


class TestCWEFixRegistryMeta:
    def test_supported_cwes(self):
        cwes = CWEFixRegistry.supported_cwes()
        assert "CWE-22" in cwes
        assert "CWE-78" in cwes
        assert "CWE-79" in cwes
        assert "CWE-89" in cwes
        assert "CWE-502" in cwes
        assert len(cwes) == 5

    def test_can_fix_supported(self):
        assert CWEFixRegistry.can_fix("CWE-79") is True
        assert CWEFixRegistry.can_fix("89") is True
        assert CWEFixRegistry.can_fix("cwe-502") is True

    def test_can_fix_unsupported(self):
        assert CWEFixRegistry.can_fix("CWE-400") is False
        assert CWEFixRegistry.can_fix("CWE-999") is False

    def test_generate_fix_unsupported_raises(self):
        with pytest.raises(ValueError, match="Unsupported CWE"):
            CWEFixRegistry.generate_fix("CWE-999", {})


# ===========================================================================
# CWE-79 XSS Fix
# ===========================================================================


class TestCWE79Fix:
    def test_generate_fix_python(self, xss_finding):
        tpl = CWEFixRegistry.generate_fix("CWE-79", xss_finding)
        assert tpl.cwe_id == "CWE-79"
        assert tpl.cwe_name == "Cross-Site Scripting (XSS)"
        assert "markupsafe" in tpl.fix_code.lower() or "_html_escape" in tpl.fix_code
        assert "Content-Security-Policy" in tpl.fix_code
        assert tpl.language == "python"
        assert tpl.confidence > 0.8
        assert "CWE-79" in tpl.compliance_refs

    def test_generate_fix_javascript(self):
        finding = {
            "file_path": "app.js",
            "language": "javascript",
            "severity": "high",
            "code_snippet": 'element.innerHTML = userInput;',
        }
        tpl = CWEFixRegistry.generate_fix("CWE-79", finding)
        assert "DOMPurify" in tpl.fix_code

    def test_pr_title_format(self, xss_finding):
        tpl = CWEFixRegistry.generate_fix("CWE-79", xss_finding)
        assert "CWE-79" in tpl.pr_title
        assert "XSS" in tpl.pr_title

    def test_test_code_generated(self, xss_finding):
        tpl = CWEFixRegistry.generate_fix("CWE-79", xss_finding)
        assert "TestCWE79Fix" in tpl.test_code
        assert "XSS_PAYLOADS" in tpl.test_code

    def test_fix_code_with_empty_source(self):
        finding = {"file_path": "app.py", "language": "python", "severity": "high"}
        tpl = CWEFixRegistry.generate_fix("CWE-79", finding)
        assert "Content-Security-Policy" in tpl.fix_code

    def test_files_modified(self, xss_finding):
        tpl = CWEFixRegistry.generate_fix("CWE-79", xss_finding)
        assert xss_finding["file_path"] in tpl.files_modified

    def test_mitre_techniques(self, xss_finding):
        tpl = CWEFixRegistry.generate_fix("CWE-79", xss_finding)
        assert len(tpl.mitre_techniques) > 0


# ===========================================================================
# CWE-89 SQL Injection Fix
# ===========================================================================


class TestCWE89Fix:
    def test_generate_fix(self, sqli_finding):
        tpl = CWEFixRegistry.generate_fix("CWE-89", sqli_finding)
        assert tpl.cwe_id == "CWE-89"
        assert tpl.cwe_name == "SQL Injection"
        assert tpl.confidence >= 0.90
        assert "CWE-89" in tpl.compliance_refs

    def test_parameterized_query_in_fix(self, sqli_finding):
        tpl = CWEFixRegistry.generate_fix("CWE-89", sqli_finding)
        # Fix should contain parameterized query markers
        assert "?" in tpl.fix_code or "execute(" in tpl.fix_code

    def test_pr_description_mentions_sql(self, sqli_finding):
        tpl = CWEFixRegistry.generate_fix("CWE-89", sqli_finding)
        assert "SQL" in tpl.pr_description or "sql" in tpl.pr_description.lower()

    def test_test_code_has_injection_payloads(self, sqli_finding):
        tpl = CWEFixRegistry.generate_fix("CWE-89", sqli_finding)
        assert "SQL_INJECTION_PAYLOADS" in tpl.test_code
        assert "DROP TABLE" in tpl.test_code

    def test_fstring_pattern_replacement(self):
        source = 'cursor.execute(f"SELECT * FROM users WHERE id = {uid}")'
        finding = {"file_path": "db.py", "language": "python", "code_snippet": source}
        tpl = CWEFixRegistry.generate_fix("CWE-89", finding, source)
        # Should have replaced the f-string with parameterized
        assert "CWE-89 fix" in tpl.fix_code or "?" in tpl.fix_code


# ===========================================================================
# CWE-502 Deserialization Fix
# ===========================================================================


class TestCWE502Fix:
    def test_generate_fix(self, deserialization_finding):
        tpl = CWEFixRegistry.generate_fix("CWE-502", deserialization_finding)
        assert tpl.cwe_id == "CWE-502"
        assert "json" in tpl.fix_code.lower()

    def test_pickle_replaced(self, deserialization_finding):
        source = "import pickle\ndata = pickle.loads(user_data)"
        tpl = CWEFixRegistry.generate_fix("CWE-502", deserialization_finding, source)
        assert "json.loads" in tpl.fix_code

    def test_yaml_load_replaced(self):
        source = "import yaml\nconfig = yaml.load(content, Loader=yaml.FullLoader)"
        finding = {"file_path": "config_loader.py", "language": "python", "code_snippet": source}
        tpl = CWEFixRegistry.generate_fix("CWE-502", finding, source)
        assert "safe_load" in tpl.fix_code

    def test_marshal_replaced(self):
        source = "import marshal\nobj = marshal.loads(data)"
        finding = {"file_path": "loader.py", "language": "python", "code_snippet": source}
        tpl = CWEFixRegistry.generate_fix("CWE-502", finding, source)
        assert "json.loads" in tpl.fix_code

    def test_test_code_has_deserialization_tests(self, deserialization_finding):
        tpl = CWEFixRegistry.generate_fix("CWE-502", deserialization_finding)
        assert "TestCWE502Fix" in tpl.test_code

    def test_effort_minutes(self, deserialization_finding):
        tpl = CWEFixRegistry.generate_fix("CWE-502", deserialization_finding)
        assert tpl.effort_minutes == 25


# ===========================================================================
# CWE-78 Command Injection Fix
# ===========================================================================


class TestCWE78Fix:
    def test_generate_fix(self, command_injection_finding):
        tpl = CWEFixRegistry.generate_fix("CWE-78", command_injection_finding)
        assert tpl.cwe_id == "CWE-78"
        assert "subprocess" in tpl.fix_code or "shell=False" in tpl.fix_code

    def test_os_system_replaced(self, command_injection_finding):
        source = 'os.system(f"ping {host}")'
        tpl = CWEFixRegistry.generate_fix("CWE-78", command_injection_finding, source)
        assert "os.system" not in tpl.fix_code or "subprocess" in tpl.fix_code

    def test_os_popen_replaced(self):
        source = 'output = os.popen(f"ls {directory}").read()'
        finding = {"file_path": "utils.py", "language": "python", "code_snippet": source}
        tpl = CWEFixRegistry.generate_fix("CWE-78", finding, source)
        assert "subprocess" in tpl.fix_code

    def test_shell_true_replaced(self):
        source = 'subprocess.run(cmd, shell=True)'
        finding = {"file_path": "runner.py", "language": "python", "code_snippet": source}
        tpl = CWEFixRegistry.generate_fix("CWE-78", finding, source)
        assert "shell=False" in tpl.fix_code

    def test_test_code_has_injection_payloads(self, command_injection_finding):
        tpl = CWEFixRegistry.generate_fix("CWE-78", command_injection_finding)
        assert "INJECTION_PAYLOADS" in tpl.test_code
        assert "rm -rf" in tpl.test_code

    def test_confidence(self, command_injection_finding):
        tpl = CWEFixRegistry.generate_fix("CWE-78", command_injection_finding)
        assert tpl.confidence >= 0.90


# ===========================================================================
# CWE-22 Path Traversal Fix
# ===========================================================================


class TestCWE22Fix:
    def test_generate_fix(self, path_traversal_finding):
        tpl = CWEFixRegistry.generate_fix("CWE-22", path_traversal_finding)
        assert tpl.cwe_id == "CWE-22"
        assert "realpath" in tpl.fix_code or "resolve" in tpl.fix_code

    def test_safe_path_function_added(self, path_traversal_finding):
        source = 'content = open(user_path).read()'
        tpl = CWEFixRegistry.generate_fix("CWE-22", path_traversal_finding, source)
        assert "fixops_safe_path" in tpl.fix_code or "realpath" in tpl.fix_code

    def test_os_path_join_replaced(self):
        source = 'full_path = os.path.join(base_dir, user_input)'
        finding = {"file_path": "handler.py", "language": "python", "code_snippet": source}
        tpl = CWEFixRegistry.generate_fix("CWE-22", finding, source)
        assert "fixops_safe_path" in tpl.fix_code or "realpath" in tpl.fix_code

    def test_test_code_has_traversal_payloads(self, path_traversal_finding):
        tpl = CWEFixRegistry.generate_fix("CWE-22", path_traversal_finding)
        assert "TRAVERSAL_PAYLOADS" in tpl.test_code
        assert "../../../etc/passwd" in tpl.test_code

    def test_compliance_refs(self, path_traversal_finding):
        tpl = CWEFixRegistry.generate_fix("CWE-22", path_traversal_finding)
        assert "CWE-22" in tpl.compliance_refs


# ===========================================================================
# _build_cwe_pr_description
# ===========================================================================


class TestBuildPRDescription:
    def test_basic_description(self):
        desc = CWEFixRegistry._build_cwe_pr_description(
            cwe_id="CWE-79",
            cwe_name="XSS",
            severity="high",
            file_path="app.py",
            description="Fixed XSS",
        )
        assert "CWE-79" in desc
        assert "XSS" in desc
        assert "HIGH" in desc
        assert "`app.py`" in desc

    def test_description_with_diff(self):
        desc = CWEFixRegistry._build_cwe_pr_description(
            cwe_id="CWE-89",
            cwe_name="SQL Injection",
            severity="critical",
            file_path="db.py",
            description="Parameterized",
            diff="--- a/db.py\n+++ b/db.py\n-old\n+new",
        )
        assert "```diff" in desc
        assert "Diff" in desc

    def test_description_without_diff(self):
        desc = CWEFixRegistry._build_cwe_pr_description(
            cwe_id="CWE-502",
            cwe_name="Deserialization",
            severity="critical",
            file_path="s.py",
            description="Safe deserialization",
        )
        assert "```diff" not in desc

    def test_footer_present(self):
        desc = CWEFixRegistry._build_cwe_pr_description(
            cwe_id="CWE-78",
            cwe_name="Command Injection",
            severity="critical",
            file_path="x.py",
            description="Fixed",
        )
        assert "Pillar V7" in desc


# ===========================================================================
# _make_unified_diff
# ===========================================================================


class TestMakeUnifiedDiff:
    def test_produces_diff(self):
        diff = CWEFixRegistry._make_unified_diff(
            "app.py",
            "old code\n",
            "new code\n",
        )
        assert "---" in diff
        assert "+++" in diff

    def test_identical_code_no_diff(self):
        diff = CWEFixRegistry._make_unified_diff(
            "app.py",
            "same code\n",
            "same code\n",
        )
        assert diff == ""


# ===========================================================================
# RemediationEngine
# ===========================================================================


class TestRemediationEngine:
    def test_init_defaults(self, engine):
        assert engine.auto_fix_enabled is True
        assert engine.max_concurrent == 5

    def test_init_custom_config(self):
        eng = RemediationEngine({"auto_fix_enabled": False, "max_concurrent": 10})
        assert eng.auto_fix_enabled is False
        assert eng.max_concurrent == 10

    def test_determine_strategy_auto_fix_disabled(self):
        eng = RemediationEngine({"auto_fix_enabled": False})
        finding = {"severity": "critical", "fix_available": True}
        assert eng.determine_strategy(finding) == RemediationStrategy.MANUAL

    def test_determine_strategy_cwe_template_available(self, engine):
        finding = {"severity": "medium", "cwe_id": "CWE-79"}
        assert engine.determine_strategy(finding) == RemediationStrategy.AUTO_FIX

    def test_determine_strategy_critical_with_fix(self, engine):
        finding = {"severity": "critical", "fix_available": True}
        assert engine.determine_strategy(finding) == RemediationStrategy.AUTO_FIX

    def test_determine_strategy_high_with_fix(self, engine):
        finding = {"severity": "high", "fix_available": True}
        assert engine.determine_strategy(finding) == RemediationStrategy.AUTO_FIX

    def test_determine_strategy_medium_with_fix(self, engine):
        finding = {"severity": "medium", "fix_available": True}
        assert engine.determine_strategy(finding) == RemediationStrategy.GUIDED

    def test_determine_strategy_medium_no_fix(self, engine):
        finding = {"severity": "medium", "fix_available": False}
        assert engine.determine_strategy(finding) == RemediationStrategy.MANUAL

    def test_determine_strategy_low(self, engine):
        finding = {"severity": "low"}
        assert engine.determine_strategy(finding) == RemediationStrategy.MANUAL

    def test_remediate_accept_risk(self, engine):
        result = engine.remediate(
            "F-001", {"severity": "low"}, strategy=RemediationStrategy.ACCEPT_RISK
        )
        assert result.status == RemediationStatus.SKIPPED
        assert "accepted" in result.fix_description.lower()

    def test_remediate_manual(self, engine):
        result = engine.remediate(
            "F-002", {"severity": "low"}, strategy=RemediationStrategy.MANUAL
        )
        assert result.status == RemediationStatus.PENDING
        assert "manual" in result.fix_description.lower()

    def test_remediate_stores_result(self, engine):
        result = engine.remediate(
            "F-003", {"severity": "low"}, strategy=RemediationStrategy.MANUAL
        )
        assert "F-003" in engine._results

    def test_remediate_completed_at_set(self, engine):
        result = engine.remediate(
            "F-004", {"severity": "low"}, strategy=RemediationStrategy.MANUAL
        )
        assert result.completed_at is not None

    def test_remediate_cwe_success(self, engine, xss_finding):
        result = engine.remediate_cwe("F-100", "CWE-79", xss_finding)
        assert result.status == RemediationStatus.FIX_GENERATED
        assert result.cwe_fix is not None
        assert result.cwe_fix.cwe_id == "CWE-79"
        assert len(result.files_modified) > 0

    def test_remediate_cwe_unsupported(self, engine):
        result = engine.remediate_cwe("F-101", "CWE-999", {})
        assert result.status == RemediationStatus.FAILED
        assert "No fix template" in result.error

    def test_remediate_cwe_with_source_code(self, engine):
        finding = {"file_path": "db.py", "language": "python", "severity": "critical"}
        source = 'cursor.execute(f"SELECT * FROM users WHERE id = {uid}")'
        result = engine.remediate_cwe("F-102", "CWE-89", finding, source)
        assert result.status == RemediationStatus.FIX_GENERATED
        assert result.cwe_fix is not None

    def test_remediate_cwe_all_five(self, engine):
        """Test all 5 supported CWEs generate fixes."""
        cwe_ids = ["CWE-79", "CWE-89", "CWE-502", "CWE-78", "CWE-22"]
        for cwe_id in cwe_ids:
            finding = {"file_path": "test.py", "language": "python", "severity": "high"}
            result = engine.remediate_cwe(f"F-{cwe_id}", cwe_id, finding)
            assert result.status == RemediationStatus.FIX_GENERATED, f"Failed for {cwe_id}"
            assert result.cwe_fix is not None, f"No fix for {cwe_id}"
            assert result.cwe_fix.cwe_id == cwe_id


# ===========================================================================
# Helper functions
# ===========================================================================


class TestHelpers:
    def test_file_path_helper(self):
        assert CWEFixRegistry._file_path({}, "default.py") == "default.py"
        assert CWEFixRegistry._file_path({"file_path": "app.py"}) == "app.py"

    def test_language_helper(self):
        assert CWEFixRegistry._language({}, "python") == "python"
        assert CWEFixRegistry._language({"language": "JavaScript"}) == "javascript"
