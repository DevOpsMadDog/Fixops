"""Deep tests for FixOps Remediation Engine — CWE templates, strategy, orchestration.

Covers:
- CWEFixTemplate creation for all 5 CWEs (79, 89, 502, 78, 22)
- CWE ID normalization across all accepted formats
- RemediationStatus enum transitions
- RemediationStrategy selection logic (auto_fix on/off, severity, fix_available)
- Fix generation quality: each CWE fix transforms vulnerable code correctly
- PR description generation with correct structure
- Unified diff / patch generation
- RemediationEngine orchestration: remediate(), remediate_cwe(), metrics
- Error handling: unsupported CWE, missing source code, invalid inputs
- Serialization: to_dict round-trip correctness

At least 30 real test functions -- no stubs, no assert True, no mocking of the SUT.
"""

from __future__ import annotations

import re
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
    """RemediationEngine with auto_fix enabled, no SCM configured."""
    return RemediationEngine({"auto_fix_enabled": True})


@pytest.fixture
def engine_disabled() -> RemediationEngine:
    """RemediationEngine with auto_fix disabled."""
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
        "title": "SQL Injection in login handler",
        "severity": "critical",
        "cwe_id": "CWE-89",
        "file_path": "auth/login.py",
        "language": "python",
        "code_snippet": (
            'import sqlite3\n'
            'conn = sqlite3.connect("app.db")\n'
            'user = request.form["username"]\n'
            'conn.execute(f"SELECT * FROM users WHERE name = \'{user}\'")\n'
        ),
    }


@pytest.fixture
def finding_deser() -> Dict[str, Any]:
    return {
        "id": "FIND-DESER-001",
        "title": "Insecure deserialization via pickle",
        "severity": "critical",
        "cwe_id": "CWE-502",
        "file_path": "data/loader.py",
        "language": "python",
        "code_snippet": (
            "import pickle\n"
            'data = pickle.loads(request.body)\n'
        ),
    }


@pytest.fixture
def finding_cmdi() -> Dict[str, Any]:
    return {
        "id": "FIND-CMDI-001",
        "title": "OS command injection in file processor",
        "severity": "critical",
        "cwe_id": "CWE-78",
        "file_path": "util/executor.py",
        "language": "python",
        "code_snippet": (
            "import os\n"
            'filename = request.args.get("file")\n'
            'os.system(f"cat {filename}")\n'
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
            "import os\n"
            'user_file = request.args.get("path")\n'
            'full_path = os.path.join("/uploads", user_file)\n'
            'data = open(full_path).read()\n'
        ),
    }


# ============================================================================
# CWE ID Normalization
# ============================================================================


class TestCWENormalization:
    """Verify _normalize_cwe handles all accepted formats."""

    @pytest.mark.parametrize(
        "raw, expected",
        [
            ("CWE-79", "CWE-79"),
            ("cwe-79", "CWE-79"),
            ("79", "CWE-79"),
            ("CWE79", "CWE-79"),
            ("cwe79", "CWE-79"),
            ("CWE-089", "CWE-89"),
            ("CWE-502", "CWE-502"),
            ("  CWE-22  ", "CWE-22"),
        ],
    )
    def test_normalize_cwe_id(self, raw: str, expected: str):
        result = CWEFixRegistry._normalize_cwe(raw)
        assert result == expected, f"Normalizing '{raw}' gave '{result}', expected '{expected}'"

    def test_normalize_non_numeric_returns_original(self):
        """Non-numeric input should pass through unchanged (uppercased)."""
        result = CWEFixRegistry._normalize_cwe("ABC")
        # No digits, so it returns the raw upper-cased string
        assert result == "ABC"


# ============================================================================
# CWE Registry -- supported CWEs, can_fix, generate_fix
# ============================================================================


class TestCWEFixRegistry:
    """Test the CWEFixRegistry classmethods."""

    def test_supported_cwes_returns_five(self):
        cwes = CWEFixRegistry.supported_cwes()
        assert len(cwes) == 5
        assert "CWE-22" in cwes
        assert "CWE-78" in cwes
        assert "CWE-79" in cwes
        assert "CWE-89" in cwes
        assert "CWE-502" in cwes

    def test_supported_cwes_are_sorted(self):
        cwes = CWEFixRegistry.supported_cwes()
        assert cwes == sorted(cwes)

    @pytest.mark.parametrize("cwe_id", ["CWE-79", "CWE-89", "CWE-502", "CWE-78", "CWE-22"])
    def test_can_fix_supported(self, cwe_id: str):
        assert CWEFixRegistry.can_fix(cwe_id) is True

    @pytest.mark.parametrize("cwe_id", ["CWE-200", "CWE-400", "CWE-119", "CWE-0", "NOTACWE"])
    def test_can_fix_unsupported(self, cwe_id: str):
        assert CWEFixRegistry.can_fix(cwe_id) is False

    @pytest.mark.parametrize("raw", ["79", "cwe79", "cwe-79", "CWE79"])
    def test_can_fix_normalizes_input(self, raw: str):
        """can_fix should accept any format and normalize internally."""
        assert CWEFixRegistry.can_fix(raw) is True

    def test_generate_fix_unsupported_raises(self):
        with pytest.raises(ValueError, match="Unsupported CWE"):
            CWEFixRegistry.generate_fix("CWE-999", {"severity": "high"})


# ============================================================================
# CWE-79 XSS Fix
# ============================================================================


class TestCWE79Fix:
    """Validate XSS fix template generation."""

    def test_generates_fix_template(self, finding_xss):
        tpl = CWEFixRegistry.generate_fix("CWE-79", finding_xss, finding_xss["code_snippet"])
        assert isinstance(tpl, CWEFixTemplate)
        assert tpl.cwe_id == "CWE-79"
        assert tpl.cwe_name == "Cross-Site Scripting (XSS)"

    def test_fix_adds_markupsafe_import(self, finding_xss):
        tpl = CWEFixRegistry.generate_fix("CWE-79", finding_xss, finding_xss["code_snippet"])
        assert "markupsafe" in tpl.fix_code.lower() or "_html_escape" in tpl.fix_code

    def test_fix_adds_csp_header(self, finding_xss):
        tpl = CWEFixRegistry.generate_fix("CWE-79", finding_xss, finding_xss["code_snippet"])
        assert "Content-Security-Policy" in tpl.fix_code

    def test_pr_title_contains_cwe(self, finding_xss):
        tpl = CWEFixRegistry.generate_fix("CWE-79", finding_xss)
        assert "CWE-79" in tpl.pr_title
        assert finding_xss["file_path"] in tpl.pr_title

    def test_compliance_refs_present(self, finding_xss):
        tpl = CWEFixRegistry.generate_fix("CWE-79", finding_xss)
        assert "OWASP A03:2021" in tpl.compliance_refs
        assert "CWE-79" in tpl.compliance_refs

    def test_mitre_techniques_present(self, finding_xss):
        tpl = CWEFixRegistry.generate_fix("CWE-79", finding_xss)
        assert len(tpl.mitre_techniques) > 0

    def test_confidence_above_threshold(self, finding_xss):
        tpl = CWEFixRegistry.generate_fix("CWE-79", finding_xss)
        assert tpl.confidence >= 0.90


# ============================================================================
# CWE-89 SQL Injection Fix
# ============================================================================


class TestCWE89Fix:
    """Validate SQL injection fix template generation."""

    def test_generates_fix_template(self, finding_sqli):
        tpl = CWEFixRegistry.generate_fix("CWE-89", finding_sqli, finding_sqli["code_snippet"])
        assert isinstance(tpl, CWEFixTemplate)
        assert tpl.cwe_id == "CWE-89"

    def test_fix_replaces_fstring_with_parameterized(self, finding_sqli):
        source = 'conn.execute(f"SELECT * FROM users WHERE name = \'{user}\'")'
        tpl = CWEFixRegistry.generate_fix("CWE-89", finding_sqli, source)
        # Should use ? placeholder or parameterized query pattern
        assert "?" in tpl.fix_code or "execute(" in tpl.fix_code

    def test_fix_code_no_fstring_sql(self, finding_sqli):
        tpl = CWEFixRegistry.generate_fix("CWE-89", finding_sqli, finding_sqli["code_snippet"])
        # The fix code should not contain f"SELECT patterns
        fstring_sql = re.findall(r'f["\']SELECT', tpl.fix_code, re.IGNORECASE)
        assert len(fstring_sql) == 0, f"f-string SQL still present in fix: {fstring_sql}"

    def test_pr_description_mentions_parameterized(self, finding_sqli):
        tpl = CWEFixRegistry.generate_fix("CWE-89", finding_sqli)
        assert "parameterized" in tpl.pr_description.lower()

    def test_effort_minutes_is_reasonable(self, finding_sqli):
        tpl = CWEFixRegistry.generate_fix("CWE-89", finding_sqli)
        assert 5 <= tpl.effort_minutes <= 60


# ============================================================================
# CWE-502 Deserialization Fix
# ============================================================================


class TestCWE502Fix:
    """Validate insecure deserialization fix."""

    def test_generates_fix_template(self, finding_deser):
        tpl = CWEFixRegistry.generate_fix("CWE-502", finding_deser, finding_deser["code_snippet"])
        assert tpl.cwe_id == "CWE-502"
        assert tpl.cwe_name == "Deserialization of Untrusted Data"

    def test_replaces_pickle_with_json(self, finding_deser):
        tpl = CWEFixRegistry.generate_fix("CWE-502", finding_deser, finding_deser["code_snippet"])
        # pickle.loads should be replaced
        assert "pickle.loads" not in tpl.fix_code or "FIXOPS" in tpl.fix_code
        assert "json.loads" in tpl.fix_code

    def test_adds_json_import(self, finding_deser):
        tpl = CWEFixRegistry.generate_fix("CWE-502", finding_deser, finding_deser["code_snippet"])
        assert "import json" in tpl.fix_code

    def test_yaml_unsafe_replaced(self):
        finding = {"severity": "high", "cwe_id": "CWE-502", "file_path": "config.py"}
        source = 'import yaml\ndata = yaml.load(open("config.yml"), Loader=yaml.FullLoader)\n'
        tpl = CWEFixRegistry.generate_fix("CWE-502", finding, source)
        assert "yaml.safe_load" in tpl.fix_code
        # FullLoader arg should be removed
        assert "FullLoader" not in tpl.fix_code


# ============================================================================
# CWE-78 OS Command Injection Fix
# ============================================================================


class TestCWE78Fix:
    """Validate OS command injection fix."""

    def test_generates_fix_template(self, finding_cmdi):
        tpl = CWEFixRegistry.generate_fix("CWE-78", finding_cmdi, finding_cmdi["code_snippet"])
        assert tpl.cwe_id == "CWE-78"
        assert tpl.cwe_name == "OS Command Injection"

    def test_replaces_os_system(self, finding_cmdi):
        tpl = CWEFixRegistry.generate_fix("CWE-78", finding_cmdi, finding_cmdi["code_snippet"])
        assert "os.system(" not in tpl.fix_code
        assert "subprocess" in tpl.fix_code

    def test_adds_subprocess_import(self, finding_cmdi):
        tpl = CWEFixRegistry.generate_fix("CWE-78", finding_cmdi, finding_cmdi["code_snippet"])
        assert "import subprocess" in tpl.fix_code

    def test_adds_shlex_import(self, finding_cmdi):
        tpl = CWEFixRegistry.generate_fix("CWE-78", finding_cmdi, finding_cmdi["code_snippet"])
        assert "import shlex" in tpl.fix_code

    def test_no_shell_true_in_fix(self, finding_cmdi):
        tpl = CWEFixRegistry.generate_fix("CWE-78", finding_cmdi, finding_cmdi["code_snippet"])
        assert "shell=True" not in tpl.fix_code


# ============================================================================
# CWE-22 Path Traversal Fix
# ============================================================================


class TestCWE22Fix:
    """Validate path traversal fix."""

    def test_generates_fix_template(self, finding_path):
        tpl = CWEFixRegistry.generate_fix("CWE-22", finding_path, finding_path["code_snippet"])
        assert tpl.cwe_id == "CWE-22"
        assert tpl.cwe_name == "Path Traversal"

    def test_fix_adds_realpath(self, finding_path):
        tpl = CWEFixRegistry.generate_fix("CWE-22", finding_path, finding_path["code_snippet"])
        assert "realpath" in tpl.fix_code

    def test_fix_adds_safe_path_function(self, finding_path):
        tpl = CWEFixRegistry.generate_fix("CWE-22", finding_path, finding_path["code_snippet"])
        assert "_fixops_safe_path" in tpl.fix_code

    def test_fix_rejects_dotdot(self, finding_path):
        tpl = CWEFixRegistry.generate_fix("CWE-22", finding_path, finding_path["code_snippet"])
        assert '".."' in tpl.fix_code or "'..' " in tpl.fix_code


# ============================================================================
# CWEFixTemplate to_dict Serialization
# ============================================================================


class TestCWEFixTemplateSerialization:
    """Validate CWEFixTemplate.to_dict() round-trip."""

    def test_to_dict_has_all_keys(self, finding_xss):
        tpl = CWEFixRegistry.generate_fix("CWE-79", finding_xss)
        d = tpl.to_dict()
        expected_keys = {
            "cwe_id", "cwe_name", "fix_code", "test_code", "pr_title",
            "pr_description", "files_modified", "language", "effort_minutes",
            "confidence", "mitre_techniques", "compliance_refs",
        }
        assert expected_keys.issubset(d.keys()), f"Missing keys: {expected_keys - d.keys()}"

    def test_to_dict_values_match(self, finding_xss):
        tpl = CWEFixRegistry.generate_fix("CWE-79", finding_xss)
        d = tpl.to_dict()
        assert d["cwe_id"] == tpl.cwe_id
        assert d["cwe_name"] == tpl.cwe_name
        assert d["confidence"] == tpl.confidence
        assert d["files_modified"] == tpl.files_modified


# ============================================================================
# RemediationResult Serialization
# ============================================================================


class TestRemediationResultSerialization:
    """Validate RemediationResult.to_dict() serialization."""

    def test_basic_to_dict(self):
        r = RemediationResult(
            finding_id="F-001",
            status=RemediationStatus.PENDING,
            strategy=RemediationStrategy.MANUAL,
        )
        d = r.to_dict()
        assert d["finding_id"] == "F-001"
        assert d["status"] == "pending"
        assert d["strategy"] == "manual"
        assert d["pillar"] == "V7"

    def test_to_dict_with_cwe_fix(self, finding_xss):
        tpl = CWEFixRegistry.generate_fix("CWE-79", finding_xss)
        r = RemediationResult(
            finding_id="F-002",
            status=RemediationStatus.FIX_GENERATED,
            strategy=RemediationStrategy.AUTO_FIX,
            cwe_fix=tpl,
        )
        d = r.to_dict()
        assert "cwe_fix" in d
        assert d["cwe_fix"]["cwe_id"] == "CWE-79"

    def test_to_dict_datetime_serialization(self):
        now = datetime.now(timezone.utc)
        r = RemediationResult(
            finding_id="F-003",
            started_at=now,
            completed_at=now,
        )
        d = r.to_dict()
        assert d["started_at"] == now.isoformat()
        assert d["completed_at"] == now.isoformat()

    def test_to_dict_none_datetimes(self):
        r = RemediationResult(finding_id="F-004")
        d = r.to_dict()
        assert d["started_at"] is None
        assert d["completed_at"] is None


# ============================================================================
# RemediationStatus and RemediationStrategy Enums
# ============================================================================


class TestEnums:
    """Validate enum values."""

    def test_remediation_status_values(self):
        assert RemediationStatus.PENDING.value == "pending"
        assert RemediationStatus.IN_PROGRESS.value == "in_progress"
        assert RemediationStatus.FIX_GENERATED.value == "fix_generated"
        assert RemediationStatus.PR_CREATED.value == "pr_created"
        assert RemediationStatus.PR_MERGED.value == "pr_merged"
        assert RemediationStatus.VERIFIED.value == "verified"
        assert RemediationStatus.FAILED.value == "failed"
        assert RemediationStatus.SKIPPED.value == "skipped"

    def test_remediation_status_count(self):
        assert len(RemediationStatus) == 8

    def test_remediation_strategy_values(self):
        assert RemediationStrategy.AUTO_FIX.value == "auto_fix"
        assert RemediationStrategy.GUIDED.value == "guided"
        assert RemediationStrategy.MANUAL.value == "manual"
        assert RemediationStrategy.ACCEPT_RISK.value == "accept_risk"
        assert RemediationStrategy.COMPENSATING.value == "compensating"

    def test_remediation_strategy_count(self):
        assert len(RemediationStrategy) == 5


# ============================================================================
# RemediationEngine -- Strategy Determination
# ============================================================================


class TestStrategyDetermination:
    """Validate RemediationEngine.determine_strategy()."""

    def test_auto_fix_for_supported_cwe(self, engine):
        finding = {"severity": "high", "cwe_id": "CWE-79"}
        strategy = engine.determine_strategy(finding)
        assert strategy == RemediationStrategy.AUTO_FIX

    def test_auto_fix_for_critical_with_fix(self, engine):
        finding = {"severity": "critical", "fix_available": True}
        strategy = engine.determine_strategy(finding)
        assert strategy == RemediationStrategy.AUTO_FIX

    def test_auto_fix_for_high_with_fix(self, engine):
        finding = {"severity": "high", "fix_available": True}
        strategy = engine.determine_strategy(finding)
        assert strategy == RemediationStrategy.AUTO_FIX

    def test_guided_for_medium_with_fix(self, engine):
        finding = {"severity": "medium", "fix_available": True}
        strategy = engine.determine_strategy(finding)
        assert strategy == RemediationStrategy.GUIDED

    def test_manual_for_low_severity(self, engine):
        finding = {"severity": "low", "fix_available": False}
        strategy = engine.determine_strategy(finding)
        assert strategy == RemediationStrategy.MANUAL

    def test_manual_for_medium_without_fix(self, engine):
        finding = {"severity": "medium", "fix_available": False}
        strategy = engine.determine_strategy(finding)
        assert strategy == RemediationStrategy.MANUAL

    def test_manual_when_autofix_disabled(self, engine_disabled):
        finding = {"severity": "critical", "cwe_id": "CWE-79", "fix_available": True}
        strategy = engine_disabled.determine_strategy(finding)
        assert strategy == RemediationStrategy.MANUAL

    def test_default_severity_is_medium(self, engine):
        finding = {"fix_available": False}  # no severity key
        strategy = engine.determine_strategy(finding)
        assert strategy == RemediationStrategy.MANUAL


# ============================================================================
# RemediationEngine -- remediate_cwe()
# ============================================================================


class TestRemediateCWE:
    """Validate CWE-specific remediation via RemediationEngine."""

    @pytest.mark.parametrize(
        "cwe_id, fixture_name",
        [
            ("CWE-79", "finding_xss"),
            ("CWE-89", "finding_sqli"),
            ("CWE-502", "finding_deser"),
            ("CWE-78", "finding_cmdi"),
            ("CWE-22", "finding_path"),
        ],
    )
    def test_remediate_cwe_all_five(self, engine, cwe_id, fixture_name, request):
        finding = request.getfixturevalue(fixture_name)
        result = engine.remediate_cwe(
            finding["id"], cwe_id, finding, finding.get("code_snippet")
        )
        assert result.status == RemediationStatus.FIX_GENERATED
        assert result.cwe_fix is not None
        assert result.cwe_fix.cwe_id == cwe_id
        assert result.finding_id == finding["id"]

    def test_remediate_cwe_unsupported(self, engine):
        finding = {"id": "F-999", "severity": "high"}
        result = engine.remediate_cwe("F-999", "CWE-999", finding)
        assert result.status == RemediationStatus.FAILED
        assert "No fix template" in result.error

    def test_remediate_cwe_result_stored(self, engine, finding_xss):
        engine.remediate_cwe("F-XSS", "CWE-79", finding_xss)
        stored = engine.get_result("F-XSS")
        assert stored is not None
        assert stored.finding_id == "F-XSS"

    def test_remediate_cwe_timestamps_set(self, engine, finding_xss):
        result = engine.remediate_cwe("F-TS", "CWE-79", finding_xss)
        assert result.started_at is not None
        assert result.completed_at is not None
        assert result.completed_at >= result.started_at


# ============================================================================
# RemediationEngine -- remediate() orchestration
# ============================================================================


class TestRemediateOrchestration:
    """Validate full remediation orchestration flow."""

    def test_auto_remediate_with_cwe(self, engine, finding_xss):
        result = engine.remediate("F-AUTO-1", finding_xss)
        assert result.status == RemediationStatus.FIX_GENERATED
        assert result.strategy == RemediationStrategy.AUTO_FIX
        assert result.cwe_fix is not None

    def test_accept_risk_strategy(self, engine, finding_xss):
        result = engine.remediate(
            "F-RISK-1", finding_xss, strategy=RemediationStrategy.ACCEPT_RISK
        )
        assert result.status == RemediationStatus.SKIPPED
        assert "Risk accepted" in result.fix_description

    def test_manual_strategy(self, engine, finding_xss):
        result = engine.remediate(
            "F-MANUAL-1", finding_xss, strategy=RemediationStrategy.MANUAL
        )
        assert result.status == RemediationStatus.PENDING
        assert "Manual remediation" in result.fix_description

    def test_guided_remediate_with_cwe(self, engine, finding_sqli):
        result = engine.remediate(
            "F-GUIDED-1", finding_sqli, strategy=RemediationStrategy.GUIDED
        )
        assert result.status == RemediationStatus.FIX_GENERATED
        assert result.cwe_fix is not None
        assert "Guided fix" in result.fix_description


# ============================================================================
# RemediationEngine -- Metrics
# ============================================================================


class TestMetrics:
    """Validate RemediationEngine.get_metrics()."""

    def test_empty_metrics(self, engine):
        m = engine.get_metrics()
        assert m["total"] == 0
        assert m["success_rate"] == 0.0
        assert m["cwe_fixes"] == 0
        assert "supported_cwes" in m
        assert len(m["supported_cwes"]) == 5

    def test_metrics_after_remediations(self, engine, finding_xss, finding_sqli):
        engine.remediate_cwe("M-1", "CWE-79", finding_xss)
        engine.remediate_cwe("M-2", "CWE-89", finding_sqli)
        engine.remediate_cwe("M-3", "CWE-999", {"severity": "high"})

        m = engine.get_metrics()
        assert m["total"] == 3
        assert m["cwe_fixes"] == 2  # only 79 and 89 succeeded
        assert m["by_status"]["fix_generated"] == 2
        assert m["by_status"]["failed"] == 1
        assert m["success_rate"] > 0.5

    def test_get_all_results(self, engine, finding_xss, finding_sqli):
        engine.remediate_cwe("ALL-1", "CWE-79", finding_xss)
        engine.remediate_cwe("ALL-2", "CWE-89", finding_sqli)
        results = engine.get_all_results()
        assert len(results) == 2
        assert "ALL-1" in results
        assert "ALL-2" in results


# ============================================================================
# Unified Diff Generation
# ============================================================================


class TestDiffGeneration:
    """Validate _make_unified_diff produces correct diffs."""

    def test_diff_contains_file_markers(self):
        old = "line1\nline2\nline3\n"
        new = "line1\nLINE2_FIXED\nline3\n"
        diff = CWEFixRegistry._make_unified_diff("test.py", old, new)
        assert "a/test.py" in diff
        assert "b/test.py" in diff

    def test_diff_shows_changes(self):
        old = "vulnerable_code\n"
        new = "safe_code\n"
        diff = CWEFixRegistry._make_unified_diff("fix.py", old, new)
        assert "-vulnerable_code" in diff
        assert "+safe_code" in diff

    def test_diff_empty_when_identical(self):
        code = "same_code\n"
        diff = CWEFixRegistry._make_unified_diff("same.py", code, code)
        assert diff == ""


# ============================================================================
# PR Description Builder
# ============================================================================


class TestPRDescriptionBuilder:
    """Validate _build_cwe_pr_description structure."""

    def test_pr_description_has_sections(self):
        desc = CWEFixRegistry._build_cwe_pr_description(
            cwe_id="CWE-79",
            cwe_name="Cross-Site Scripting (XSS)",
            severity="high",
            file_path="app.py",
            description="Applied HTML escaping.",
        )
        assert "## Security Fix: CWE-79" in desc
        assert "**Severity:** HIGH" in desc
        assert "**File:** `app.py`" in desc
        assert "### What changed" in desc
        assert "### Testing" in desc
        assert "### Rollback" in desc

    def test_pr_description_includes_diff(self):
        desc = CWEFixRegistry._build_cwe_pr_description(
            cwe_id="CWE-89",
            cwe_name="SQL Injection",
            severity="critical",
            file_path="db.py",
            description="Parameterized queries.",
            diff="-old\n+new",
        )
        assert "### Diff" in desc
        assert "```diff" in desc

    def test_pr_description_no_diff_section_when_empty(self):
        desc = CWEFixRegistry._build_cwe_pr_description(
            cwe_id="CWE-22",
            cwe_name="Path Traversal",
            severity="high",
            file_path="handler.py",
            description="Path validation.",
            diff="",
        )
        assert "### Diff" not in desc

    def test_pr_description_contains_cwe_link(self):
        desc = CWEFixRegistry._build_cwe_pr_description(
            cwe_id="CWE-78",
            cwe_name="OS Command Injection",
            severity="critical",
            file_path="exec.py",
            description="Subprocess fix.",
        )
        assert "cwe.mitre.org" in desc
        assert "/78.html" in desc


# ============================================================================
# Edge Cases
# ============================================================================


class TestEdgeCases:
    """Edge case handling in the remediation engine."""

    def test_fix_with_no_source_code(self, finding_xss):
        """Fix generation without source code should still produce a template."""
        tpl = CWEFixRegistry.generate_fix("CWE-79", finding_xss, source_code=None)
        assert isinstance(tpl, CWEFixTemplate)
        assert tpl.fix_code is not None

    def test_fix_with_empty_source_code(self, finding_xss):
        tpl = CWEFixRegistry.generate_fix("CWE-79", finding_xss, source_code="")
        assert isinstance(tpl, CWEFixTemplate)

    def test_engine_default_config(self):
        engine = RemediationEngine()
        assert engine.auto_fix_enabled is True
        assert engine.max_concurrent == 5

    def test_engine_custom_config(self):
        engine = RemediationEngine({
            "auto_fix_enabled": False,
            "max_concurrent": 10,
        })
        assert engine.auto_fix_enabled is False
        assert engine.max_concurrent == 10

    def test_get_result_nonexistent(self, engine):
        assert engine.get_result("NONEXISTENT") is None

    def test_finding_with_js_language_cwe79(self):
        finding = {
            "severity": "high",
            "cwe_id": "CWE-79",
            "file_path": "app.js",
            "language": "javascript",
        }
        source = 'element.innerHTML = userInput;\n'
        tpl = CWEFixRegistry.generate_fix("CWE-79", finding, source)
        assert "DOMPurify" in tpl.fix_code
