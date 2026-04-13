"""Tests for ErrorHandlingAuditor — 15+ tests covering detection, categorization, reporting.

Uses tmp_path with synthetic Python files containing known-bad patterns.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Ensure suite-core is importable
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "suite-core"))

from core.error_handling_auditor import (
    CRITICAL,
    HIGH,
    MEDIUM,
    ErrorHandlingAuditor,
    _scan_file,
)


# ---------------------------------------------------------------------------
# Helper: write a temporary Python file
# ---------------------------------------------------------------------------


def _write(tmp_path: Path, name: str, source: str) -> Path:
    p = tmp_path / name
    p.write_text(source, encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# _scan_file unit tests
# ---------------------------------------------------------------------------


class TestScanFileBareExcept:
    def test_bare_except_detected_as_critical(self, tmp_path):
        p = _write(tmp_path, "bad.py", "try:\n    pass\nexcept:\n    pass\n")
        findings = _scan_file(str(p))
        assert len(findings) == 1
        assert findings[0]["severity"] == CRITICAL
        assert findings[0]["pattern"] == "bare_except"
        assert findings[0]["line"] == 3

    def test_bare_except_snippet_captured(self, tmp_path):
        p = _write(tmp_path, "bad.py", "try:\n    x = 1\nexcept:\n    pass\n")
        findings = _scan_file(str(p))
        assert findings[0]["snippet"] == "except:"

    def test_multiple_bare_excepts_all_detected(self, tmp_path):
        source = (
            "try:\n    a()\nexcept:\n    pass\n"
            "try:\n    b()\nexcept:\n    pass\n"
        )
        p = _write(tmp_path, "multi.py", source)
        findings = _scan_file(str(p))
        criticals = [f for f in findings if f["severity"] == CRITICAL]
        assert len(criticals) == 2


class TestScanFileExceptExceptionPass:
    def test_except_exception_pass_detected_as_high(self, tmp_path):
        source = "try:\n    risky()\nexcept Exception:\n    pass\n"
        p = _write(tmp_path, "swallow.py", source)
        findings = _scan_file(str(p))
        assert len(findings) == 1
        assert findings[0]["severity"] == HIGH
        assert findings[0]["pattern"] == "except_exception_pass"

    def test_except_exception_with_body_not_flagged_as_pass(self, tmp_path):
        source = (
            "import logging\n"
            "log = logging.getLogger(__name__)\n"
            "try:\n    risky()\n"
            "except Exception as e:\n    log.error('err', exc_info=True)\n    raise\n"
        )
        p = _write(tmp_path, "ok.py", source)
        findings = _scan_file(str(p))
        # has raise → not medium; not pass; not print → no HIGH or MEDIUM findings
        highs = [f for f in findings if f["severity"] == HIGH]
        assert len(highs) == 0


class TestScanFilePrintException:
    def test_except_exception_print_detected_as_high(self, tmp_path):
        source = "try:\n    risky()\nexcept Exception as e:\n    print(e)\n"
        p = _write(tmp_path, "printbad.py", source)
        findings = _scan_file(str(p))
        assert len(findings) == 1
        assert findings[0]["severity"] == HIGH
        assert findings[0]["pattern"] == "except_exception_print"


class TestScanFileLogNoReraise:
    def test_log_without_reraise_detected_as_medium(self, tmp_path):
        source = (
            "import logging\n"
            "_log = logging.getLogger(__name__)\n"
            "try:\n    risky()\n"
            "except Exception as e:\n    _log.error('failed: %s', e)\n"
        )
        p = _write(tmp_path, "logonly.py", source)
        findings = _scan_file(str(p))
        assert len(findings) == 1
        assert findings[0]["severity"] == MEDIUM
        assert findings[0]["pattern"] == "except_exception_log_no_reraise"

    def test_log_with_reraise_not_flagged(self, tmp_path):
        source = (
            "import logging\n"
            "_log = logging.getLogger(__name__)\n"
            "try:\n    risky()\n"
            "except Exception as e:\n    _log.error('failed: %s', e)\n    raise\n"
        )
        p = _write(tmp_path, "lograise.py", source)
        findings = _scan_file(str(p))
        mediums = [f for f in findings if f["severity"] == MEDIUM]
        assert len(mediums) == 0


class TestScanFileCleanCode:
    def test_specific_exception_type_not_flagged(self, tmp_path):
        source = "try:\n    open('x')\nexcept FileNotFoundError:\n    pass\n"
        p = _write(tmp_path, "clean.py", source)
        findings = _scan_file(str(p))
        assert findings == []

    def test_no_try_blocks_not_flagged(self, tmp_path):
        source = "def add(a, b):\n    return a + b\n"
        p = _write(tmp_path, "noexcept.py", source)
        findings = _scan_file(str(p))
        assert findings == []

    def test_syntax_error_file_skipped_gracefully(self, tmp_path):
        source = "def broken(\n"
        p = _write(tmp_path, "broken.py", source)
        findings = _scan_file(str(p))
        assert findings == []


# ---------------------------------------------------------------------------
# ErrorHandlingAuditor integration tests
# ---------------------------------------------------------------------------


class TestAuditorScanDirectory:
    def test_scan_directory_returns_list(self, tmp_path):
        _write(tmp_path, "a.py", "try:\n    x()\nexcept:\n    pass\n")
        auditor = ErrorHandlingAuditor(root_dir=str(tmp_path))
        results = auditor.scan_directory()
        assert isinstance(results, list)
        assert len(results) >= 1

    def test_scan_directory_ignores_pycache(self, tmp_path):
        pycache = tmp_path / "__pycache__"
        pycache.mkdir()
        _write(pycache, "cached.py", "try:\n    x()\nexcept:\n    pass\n")
        _write(tmp_path, "real.py", "x = 1\n")
        auditor = ErrorHandlingAuditor(root_dir=str(tmp_path))
        results = auditor.scan_directory()
        # No findings from __pycache__
        for r in results:
            assert "__pycache__" not in r["file"]

    def test_scan_directory_with_explicit_path(self, tmp_path):
        sub = tmp_path / "sub"
        sub.mkdir()
        _write(sub, "bad.py", "try:\n    x()\nexcept:\n    pass\n")
        auditor = ErrorHandlingAuditor(root_dir=str(tmp_path))
        results = auditor.scan_directory(path=str(sub))
        assert len(results) >= 1


class TestCategorizefindings:
    def test_categorize_groups_by_severity(self, tmp_path):
        _write(tmp_path, "a.py", "try:\n    x()\nexcept:\n    pass\n")
        source_high = "try:\n    x()\nexcept Exception:\n    pass\n"
        _write(tmp_path, "b.py", source_high)
        auditor = ErrorHandlingAuditor(root_dir=str(tmp_path))
        findings = auditor.scan_directory()
        cat = auditor.categorize_findings(findings)
        assert "by_severity" in cat
        assert "by_file" in cat
        assert CRITICAL in cat["by_severity"]
        assert HIGH in cat["by_severity"]

    def test_categorize_groups_by_file(self, tmp_path):
        _write(tmp_path, "x.py", "try:\n    x()\nexcept:\n    pass\n")
        _write(tmp_path, "y.py", "try:\n    y()\nexcept:\n    pass\n")
        auditor = ErrorHandlingAuditor(root_dir=str(tmp_path))
        findings = auditor.scan_directory()
        cat = auditor.categorize_findings(findings)
        assert len(cat["by_file"]) >= 2

    def test_empty_findings_returns_empty_categories(self):
        auditor = ErrorHandlingAuditor(root_dir=".")
        cat = auditor.categorize_findings([])
        assert cat["by_severity"][CRITICAL] == []
        assert cat["by_severity"][HIGH] == []
        assert cat["by_severity"][MEDIUM] == []
        assert cat["by_file"] == {}


class TestGenerateReport:
    def test_report_has_expected_keys(self, tmp_path):
        _write(tmp_path, "bad.py", "try:\n    x()\nexcept:\n    pass\n")
        auditor = ErrorHandlingAuditor(root_dir=str(tmp_path))
        report = auditor.generate_report()
        assert "summary" in report
        assert "top_offenders" in report
        assert "categorized" in report
        assert "recommendations" in report
        assert "findings" in report

    def test_report_summary_counts_correct(self, tmp_path):
        _write(tmp_path, "crit.py", "try:\n    x()\nexcept:\n    pass\n")
        source_high = "try:\n    x()\nexcept Exception:\n    pass\n"
        _write(tmp_path, "high.py", source_high)
        auditor = ErrorHandlingAuditor(root_dir=str(tmp_path))
        report = auditor.generate_report()
        assert report["summary"]["critical"] >= 1
        assert report["summary"]["high"] >= 1
        assert report["summary"]["total"] >= 2

    def test_report_top_offenders_sorted_descending(self, tmp_path):
        # File with 3 bare excepts should rank above file with 1
        source_many = "".join(
            f"try:\n    f{i}()\nexcept:\n    pass\n" for i in range(3)
        )
        _write(tmp_path, "many.py", source_many)
        _write(tmp_path, "one.py", "try:\n    g()\nexcept:\n    pass\n")
        auditor = ErrorHandlingAuditor(root_dir=str(tmp_path))
        report = auditor.generate_report()
        counts = [o["count"] for o in report["top_offenders"]]
        assert counts == sorted(counts, reverse=True)

    def test_report_recommendations_present_when_issues_exist(self, tmp_path):
        _write(tmp_path, "bad.py", "try:\n    x()\nexcept:\n    pass\n")
        auditor = ErrorHandlingAuditor(root_dir=str(tmp_path))
        report = auditor.generate_report()
        assert len(report["recommendations"]) >= 1


class TestGetCriticalFiles:
    def test_file_with_5_bare_excepts_is_critical(self, tmp_path):
        source = "".join(
            f"try:\n    f{i}()\nexcept:\n    pass\n" for i in range(5)
        )
        p = _write(tmp_path, "many_bare.py", source)
        auditor = ErrorHandlingAuditor(root_dir=str(tmp_path))
        auditor.scan_directory()
        critical = auditor.get_critical_files()
        assert str(p) in critical

    def test_file_with_fewer_than_5_not_in_critical(self, tmp_path):
        source = "".join(
            f"try:\n    f{i}()\nexcept:\n    pass\n" for i in range(3)
        )
        p = _write(tmp_path, "few_bare.py", source)
        auditor = ErrorHandlingAuditor(root_dir=str(tmp_path))
        auditor.scan_directory()
        critical = auditor.get_critical_files()
        assert str(p) not in critical
