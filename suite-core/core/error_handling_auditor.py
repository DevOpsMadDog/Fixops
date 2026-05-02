"""Error Handling Auditor — ALDECI static analysis tool.

Scans the codebase for poor error handling patterns and reports findings
grouped by severity:

  - critical : bare ``except:`` with no exception type
  - high     : ``except Exception: pass`` (silently swallowed) or print(e)
  - medium   : ``except Exception:`` that only logs but never re-raises

Usage::

    from core.error_handling_auditor import ErrorHandlingAuditor

    auditor = ErrorHandlingAuditor(".")
    report  = auditor.generate_report()
    print(report["summary"])
"""

from __future__ import annotations

import ast
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

import structlog

_logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Severity constants
# ---------------------------------------------------------------------------

CRITICAL = "critical"
HIGH = "high"
MEDIUM = "medium"


# ---------------------------------------------------------------------------
# Pattern helpers (line-level, used as a fast pre-filter before AST)
# ---------------------------------------------------------------------------

_BARE_EXCEPT_RE = re.compile(r"^\s*except\s*:\s*$")
_EXCEPT_EXCEPTION_RE = re.compile(r"^\s*except\s+Exception\b")
_PRINT_EXCEPT_RE = re.compile(r"^\s*print\s*\(")


# ---------------------------------------------------------------------------
# AST-based body classifiers
# ---------------------------------------------------------------------------


def _body_is_pass_only(handler: ast.ExceptHandler) -> bool:
    """True when the handler body contains only ``pass`` (and possibly docstring)."""
    [
        n for n in handler.body
        if not isinstance(n, (ast.Pass, ast.Expr))
        or (isinstance(n, ast.Expr) and not isinstance(n.value, ast.Constant))
    ]
    trivial_pass = all(isinstance(n, ast.Pass) for n in handler.body)
    return trivial_pass or (
        len(handler.body) == 1 and isinstance(handler.body[0], ast.Pass)
    )


def _body_has_print(handler: ast.ExceptHandler) -> bool:
    """True when the handler calls print() anywhere in its body."""
    for node in ast.walk(ast.Module(body=handler.body, type_ignores=[])):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "print"
        ):
            return True
    return False


def _body_has_raise(handler: ast.ExceptHandler) -> bool:
    """True when the handler re-raises (bare ``raise`` or ``raise e``)."""
    for node in ast.walk(ast.Module(body=handler.body, type_ignores=[])):
        if isinstance(node, ast.Raise):
            return True
    return False


def _body_has_logger_call(handler: ast.ExceptHandler) -> bool:
    """True when the handler calls a logging/logger method."""
    for node in ast.walk(ast.Module(body=handler.body, type_ignores=[])):
        if isinstance(node, ast.Call):
            func = node.func
            # logger.error(...) / _logger.warning(...) / log.exception(...)
            if isinstance(func, ast.Attribute) and func.attr in {
                "debug", "info", "warning", "error", "critical", "exception",
                "warn", "msg",
            }:
                return True
    return False


# ---------------------------------------------------------------------------
# Core scanner
# ---------------------------------------------------------------------------


def _scan_file(file_path: str) -> list[dict[str, Any]]:
    """Return a list of findings for *file_path*.

    Each finding is::

        {
            "file":     str,
            "line":     int,
            "pattern":  str,
            "severity": "critical" | "high" | "medium",
            "snippet":  str,
        }
    """
    findings: list[dict[str, Any]] = []

    try:
        source = Path(file_path).read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        _logger.warning("error_handling_auditor: cannot read file", file=file_path, error=str(e))
        return findings

    try:
        tree = ast.parse(source, filename=file_path)
    except SyntaxError:
        # Not a valid Python file — skip silently
        return findings

    lines = source.splitlines()

    for node in ast.walk(tree):
        if not isinstance(node, ast.ExceptHandler):
            continue

        lineno = node.lineno
        snippet = lines[lineno - 1].strip() if lineno <= len(lines) else ""

        # 1. Bare except: (no type at all) → critical
        if node.type is None:
            findings.append({
                "file": file_path,
                "line": lineno,
                "pattern": "bare_except",
                "severity": CRITICAL,
                "snippet": snippet,
            })
            continue

        # From here, type is not None — check if it's "Exception"
        is_exception_type = (
            isinstance(node.type, ast.Name) and node.type.id == "Exception"
        )

        if not is_exception_type:
            continue

        # 2. except Exception: pass → high (silently swallowed)
        if _body_is_pass_only(node):
            findings.append({
                "file": file_path,
                "line": lineno,
                "pattern": "except_exception_pass",
                "severity": HIGH,
                "snippet": snippet,
            })
            continue

        # 3. except Exception as e: print(e) → high
        if _body_has_print(node):
            findings.append({
                "file": file_path,
                "line": lineno,
                "pattern": "except_exception_print",
                "severity": HIGH,
                "snippet": snippet,
            })
            continue

        # 4. except Exception: logs only, no re-raise → medium
        if _body_has_logger_call(node) and not _body_has_raise(node):
            findings.append({
                "file": file_path,
                "line": lineno,
                "pattern": "except_exception_log_no_reraise",
                "severity": MEDIUM,
                "snippet": snippet,
            })

    return findings


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


class ErrorHandlingAuditor:
    """Static analysis tool that finds poor exception handling patterns."""

    def __init__(self, root_dir: str = ".") -> None:
        self.root_dir = str(Path(root_dir).resolve())
        self._findings: list[dict[str, Any]] | None = None

    # ------------------------------------------------------------------
    # Scanning
    # ------------------------------------------------------------------

    def scan_directory(self, path: str | None = None) -> list[dict[str, Any]]:
        """Walk *path* (default: root_dir) and return all findings.

        Returns a list of dicts::

            {"file": str, "line": int, "pattern": str, "severity": str, "snippet": str}
        """
        scan_root = Path(path) if path else Path(self.root_dir)
        findings: list[dict[str, Any]] = []

        for py_file in sorted(scan_root.rglob("*.py")):
            # Skip __pycache__ and hidden directories
            parts = py_file.parts
            if any(p.startswith("__pycache__") or p.startswith(".") for p in parts):
                continue
            findings.extend(_scan_file(str(py_file)))

        self._findings = findings
        return findings

    # ------------------------------------------------------------------
    # Categorization
    # ------------------------------------------------------------------

    def categorize_findings(self, findings: list[dict[str, Any]]) -> dict[str, Any]:
        """Group findings by severity and by file.

        Returns::

            {
                "by_severity": {"critical": [...], "high": [...], "medium": [...]},
                "by_file":     {"path/to/file.py": [...]},
            }
        """
        by_severity: dict[str, list] = {CRITICAL: [], HIGH: [], MEDIUM: []}
        by_file: dict[str, list] = defaultdict(list)

        for finding in findings:
            sev = finding.get("severity", MEDIUM)
            by_severity.setdefault(sev, []).append(finding)
            by_file[finding["file"]].append(finding)

        return {
            "by_severity": by_severity,
            "by_file": dict(by_file),
        }

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------

    def generate_report(self) -> dict[str, Any]:
        """Run a full scan and return a structured audit report.

        The report includes::

            {
                "summary": {"total": int, "critical": int, "high": int, "medium": int},
                "top_offenders": [{"file": str, "count": int}, ...],  # top 10
                "categorized": {by_severity, by_file},
                "recommendations": [...],
                "findings": [...],
            }
        """
        findings = self.scan_directory()
        categorized = self.categorize_findings(findings)

        total = len(findings)
        n_critical = len(categorized["by_severity"].get(CRITICAL, []))
        n_high = len(categorized["by_severity"].get(HIGH, []))
        n_medium = len(categorized["by_severity"].get(MEDIUM, []))

        # Top offenders by file
        file_counts = {
            f: len(items)
            for f, items in categorized["by_file"].items()
        }
        top_offenders = [
            {"file": f, "count": c}
            for f, c in sorted(file_counts.items(), key=lambda x: -x[1])[:10]
        ]

        recommendations = []
        if n_critical:
            recommendations.append(
                f"Fix {n_critical} bare `except:` clauses — they catch KeyboardInterrupt "
                "and SystemExit and hide all errors."
            )
        if n_high:
            recommendations.append(
                f"Address {n_high} silently-swallowed exceptions (pass or print). "
                "At minimum log with _logger.warning(..., exc_info=True)."
            )
        if n_medium:
            recommendations.append(
                f"Review {n_medium} handlers that log but never re-raise — "
                "consider whether callers need to know about the failure."
            )

        return {
            "summary": {
                "total": total,
                "critical": n_critical,
                "high": n_high,
                "medium": n_medium,
            },
            "top_offenders": top_offenders,
            "categorized": categorized,
            "recommendations": recommendations,
            "findings": findings,
        }

    # ------------------------------------------------------------------
    # Convenience
    # ------------------------------------------------------------------

    def get_critical_files(self) -> list[str]:
        """Return file paths that have 5 or more bare exception handlers."""
        if self._findings is None:
            self.scan_directory()

        assert self._findings is not None  # satisfied by scan above
        file_counts: dict[str, int] = defaultdict(int)
        for f in self._findings:
            if f["severity"] == CRITICAL:
                file_counts[f["file"]] += 1

        return [
            fpath
            for fpath, count in sorted(file_counts.items(), key=lambda x: -x[1])
            if count >= 5
        ]
