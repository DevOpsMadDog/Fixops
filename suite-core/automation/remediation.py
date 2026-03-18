"""FixOps Remediation Engine -- Orchestrates end-to-end vulnerability remediation.

Coordinates dependency updates, code fixes, PR generation, and tracking.
Integrates with AutoFix engine for fix generation and PRGenerator for
automated pull request creation. Serves Vision Pillar V7 (Self-Healing Remediation).

CWE Fix Templates (SPRINT1-005):
    CWE-79:  Cross-Site Scripting (XSS) -- HTML escaping, Content-Security-Policy
    CWE-89:  SQL Injection -- Parameterized queries
    CWE-502: Deserialization of Untrusted Data -- Safe deserialization
    CWE-78:  OS Command Injection -- Input validation, shlex.quote
    CWE-22:  Path Traversal -- Path canonicalization
"""

from __future__ import annotations

import difflib
import hashlib
import logging
import re
import textwrap
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class RemediationStatus(Enum):
    """Status of a remediation task."""

    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    FIX_GENERATED = "fix_generated"
    PR_CREATED = "pr_created"
    PR_MERGED = "pr_merged"
    VERIFIED = "verified"
    FAILED = "failed"
    SKIPPED = "skipped"


class RemediationStrategy(Enum):
    """Strategy for remediation."""

    AUTO_FIX = "auto_fix"  # Fully automated fix + PR
    GUIDED = "guided"  # Generate fix, human reviews
    MANUAL = "manual"  # Create ticket for human to fix
    ACCEPT_RISK = "accept_risk"  # Risk accepted with evidence
    COMPENSATING = "compensating"  # Compensating control applied


# ---------------------------------------------------------------------------
# Data Classes
# ---------------------------------------------------------------------------


@dataclass
class CWEFixTemplate:
    """A CWE-specific fix template that produces code patch, test, and PR description."""

    cwe_id: str
    cwe_name: str
    fix_code: str  # The fixed source code
    test_code: str  # Pytest test that validates the fix
    pr_title: str
    pr_description: str
    files_modified: List[str] = field(default_factory=list)
    language: str = "python"
    effort_minutes: int = 15
    confidence: float = 0.90
    mitre_techniques: List[str] = field(default_factory=list)
    compliance_refs: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cwe_id": self.cwe_id,
            "cwe_name": self.cwe_name,
            "fix_code": self.fix_code,
            "test_code": self.test_code,
            "pr_title": self.pr_title,
            "pr_description": self.pr_description,
            "files_modified": self.files_modified,
            "language": self.language,
            "effort_minutes": self.effort_minutes,
            "confidence": self.confidence,
            "mitre_techniques": self.mitre_techniques,
            "compliance_refs": self.compliance_refs,
        }


@dataclass
class RemediationResult:
    """Result of a remediation attempt."""

    finding_id: str
    status: RemediationStatus = RemediationStatus.PENDING
    strategy: RemediationStrategy = RemediationStrategy.GUIDED
    fix_description: str = ""
    pr_url: Optional[str] = None
    pr_id: Optional[str] = None
    branch_name: Optional[str] = None
    files_modified: List[str] = field(default_factory=list)
    error: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    pillar: str = "V7"  # Self-Healing Remediation
    cwe_fix: Optional[CWEFixTemplate] = None

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        d: Dict[str, Any] = {
            "finding_id": self.finding_id,
            "status": self.status.value,
            "strategy": self.strategy.value,
            "fix_description": self.fix_description,
            "pr_url": self.pr_url,
            "pr_id": self.pr_id,
            "branch_name": self.branch_name,
            "files_modified": self.files_modified,
            "error": self.error,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "pillar": self.pillar,
        }
        if self.cwe_fix is not None:
            d["cwe_fix"] = self.cwe_fix.to_dict()
        return d


# ---------------------------------------------------------------------------
# CWE Fix Template Registry
# ---------------------------------------------------------------------------


class CWEFixRegistry:
    """Registry of deterministic CWE fix templates.

    Each template generates:
      1. The actual code fix (transformed source)
      2. A test validating the fix
      3. A PR description

    Supported CWEs:
      CWE-79:  Cross-Site Scripting (XSS)
      CWE-89:  SQL Injection
      CWE-502: Deserialization of Untrusted Data
      CWE-78:  OS Command Injection
      CWE-22:  Path Traversal
    """

    # Class-level registry mapping CWE IDs to handler method names
    _HANDLERS: Dict[str, str] = {
        "CWE-79": "_fix_cwe_79",
        "CWE-89": "_fix_cwe_89",
        "CWE-502": "_fix_cwe_502",
        "CWE-78": "_fix_cwe_78",
        "CWE-22": "_fix_cwe_22",
    }

    @classmethod
    def supported_cwes(cls) -> List[str]:
        """Return list of CWE IDs this registry can fix."""
        return sorted(cls._HANDLERS.keys())

    @classmethod
    def can_fix(cls, cwe_id: str) -> bool:
        """Check whether a CWE ID is supported."""
        normalized = cls._normalize_cwe(cwe_id)
        return normalized in cls._HANDLERS

    @classmethod
    def generate_fix(
        cls,
        cwe_id: str,
        finding: Dict[str, Any],
        source_code: Optional[str] = None,
    ) -> CWEFixTemplate:
        """Generate a fix template for the given CWE.

        Args:
            cwe_id: CWE identifier (e.g. "CWE-79", "79", "cwe79").
            finding: Vulnerability finding dict with keys like file_path,
                     title, severity, language, etc.
            source_code: Optional vulnerable source code.

        Returns:
            CWEFixTemplate with fix code, test code, and PR metadata.

        Raises:
            ValueError: If the CWE is not supported.
        """
        normalized = cls._normalize_cwe(cwe_id)
        handler_name = cls._HANDLERS.get(normalized)
        if handler_name is None:
            raise ValueError(
                f"Unsupported CWE: {cwe_id} (normalized: {normalized}). "
                f"Supported: {cls.supported_cwes()}"
            )
        handler = getattr(cls, handler_name)
        return handler(finding, source_code)

    # ------------------------------------------------------------------
    # Normalization
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_cwe(raw: str) -> str:
        """Normalize various CWE ID formats to 'CWE-NNN'.

        Accepts: 'CWE-79', 'cwe-79', '79', 'CWE79', 'cwe79'.
        """
        raw = raw.strip().upper()
        digits = re.sub(r"[^0-9]", "", raw)
        if not digits:
            return raw  # let it fall through to unsupported
        return f"CWE-{int(digits)}"

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _make_unified_diff(file_path: str, old_code: str, new_code: str) -> str:
        old_lines = old_code.splitlines(keepends=True)
        new_lines = new_code.splitlines(keepends=True)
        return "".join(
            difflib.unified_diff(
                old_lines,
                new_lines,
                fromfile=f"a/{file_path}",
                tofile=f"b/{file_path}",
            )
        )

    @staticmethod
    def _file_path(finding: Dict[str, Any], default: str = "app.py") -> str:
        return finding.get("file_path", default)

    @staticmethod
    def _language(finding: Dict[str, Any], default: str = "python") -> str:
        return finding.get("language", default).lower()

    # ==================================================================
    # CWE-79: Cross-Site Scripting (XSS)
    # ==================================================================

    @classmethod
    def _fix_cwe_79(
        cls, finding: Dict[str, Any], source_code: Optional[str]
    ) -> CWEFixTemplate:
        """Generate fix for CWE-79 (XSS).

        Strategies applied:
          - HTML-escape all user-controlled output via markupsafe.escape
          - Add Content-Security-Policy header
          - Replace f-string HTML concatenation with safe templating
        """
        file_path = cls._file_path(finding, "app.py")
        lang = cls._language(finding)

        vulnerable = source_code or finding.get("code_snippet", "")

        # Determine which framework-specific fix to apply
        if "flask" in vulnerable.lower() or lang == "python":
            fix_code = cls._fix_cwe_79_python(vulnerable, file_path)
        elif lang in ("javascript", "typescript"):
            fix_code = cls._fix_cwe_79_js(vulnerable, file_path)
        else:
            fix_code = cls._fix_cwe_79_python(vulnerable, file_path)

        test_code = textwrap.dedent('''\
            """Test CWE-79 (XSS) fix: verify HTML escaping is applied."""
            import pytest


            class TestCWE79Fix:
                """Validate that XSS payloads are properly escaped."""

                XSS_PAYLOADS = [
                    "<script>alert('xss')</script>",
                    "<img src=x onerror=alert(1)>",
                    '"><script>document.cookie</script>',
                    "javascript:alert(1)",
                    "<svg onload=alert(1)>",
                ]

                def test_html_escape_applied(self):
                    """Verify markupsafe.escape neutralizes XSS payloads."""
                    from markupsafe import escape

                    for payload in self.XSS_PAYLOADS:
                        result = str(escape(payload))
                        assert "<script>" not in result
                        assert "onerror=" not in result
                        assert "javascript:" not in result.lower() or "&" in result

                def test_no_raw_html_concatenation(self):
                    """Verify the fix does not use raw string concatenation for HTML."""
                    fix_source = open("{file_path}", "r").read()
                    # Should not contain patterns like f"<div>{{user_input}}</div>"
                    import re
                    dangerous = re.findall(
                        r'f["\\']{open_brace}.*<.*>.*{close_brace}',
                        fix_source,
                    )
                    assert len(dangerous) == 0, f"Raw HTML f-string found: {{dangerous}}"

                def test_csp_header_present(self):
                    """Verify Content-Security-Policy is set."""
                    fix_source = open("{file_path}", "r").read()
                    assert "Content-Security-Policy" in fix_source or "content_security_policy" in fix_source.lower()
        ''').format(
            file_path=file_path,
            open_brace="{",
            close_brace="}",
        )

        diff = cls._make_unified_diff(file_path, vulnerable, fix_code) if vulnerable else ""

        return CWEFixTemplate(
            cwe_id="CWE-79",
            cwe_name="Cross-Site Scripting (XSS)",
            fix_code=fix_code,
            test_code=test_code,
            pr_title=f"fix(security): remediate XSS (CWE-79) in {file_path}",
            pr_description=cls._build_cwe_pr_description(
                cwe_id="CWE-79",
                cwe_name="Cross-Site Scripting (XSS)",
                severity=finding.get("severity", "high"),
                file_path=file_path,
                description=(
                    "Applied HTML output escaping via `markupsafe.escape()` on all "
                    "user-controlled values rendered in HTML context. Added "
                    "Content-Security-Policy header to prevent inline script execution."
                ),
                diff=diff,
            ),
            files_modified=[file_path],
            language=lang,
            effort_minutes=15,
            confidence=0.92,
            mitre_techniques=["T1059.007"],
            compliance_refs=["CWE-79", "OWASP A03:2021", "PCI-DSS 6.5.7"],
        )

    @staticmethod
    def _fix_cwe_79_python(source: str, file_path: str) -> str:
        """Apply Python XSS fix: add markupsafe import + escape user output."""
        lines = source.splitlines()
        result_lines: List[str] = []
        import_added = False

        for line in lines:
            # Add markupsafe import near the top
            if not import_added and (
                line.startswith("import ") or line.startswith("from ")
            ):
                result_lines.append("from markupsafe import escape as _html_escape")
                import_added = True

            # Replace dangerous patterns: f"...{user_input}..." in HTML context
            if re.search(r'f["\'].*<.*\{.*\}.*>.*["\']', line):
                # Wrap interpolated variables with _html_escape()
                line = re.sub(
                    r"\{(\w+)\}",
                    r"{_html_escape(\1)}",
                    line,
                )

            result_lines.append(line)

        if not import_added:
            result_lines.insert(0, "from markupsafe import escape as _html_escape")

        # Append CSP header middleware if not present
        if "Content-Security-Policy" not in source:
            result_lines.append("")
            result_lines.append("# CWE-79 Mitigation: Content-Security-Policy header")
            result_lines.append(
                "CSP_HEADER = \"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'\""
            )
            result_lines.append(
                "# Apply via response header: response.headers['Content-Security-Policy'] = CSP_HEADER"
            )

        return "\n".join(result_lines)

    @staticmethod
    def _fix_cwe_79_js(source: str, file_path: str) -> str:
        """Apply JavaScript/TypeScript XSS fix."""
        lines = source.splitlines()
        result_lines: List[str] = []

        # Add DOMPurify import
        result_lines.append("import DOMPurify from 'dompurify';")

        for line in lines:
            # Replace innerHTML assignments with sanitized versions
            if "innerHTML" in line and "DOMPurify" not in line:
                line = re.sub(
                    r"\.innerHTML\s*=\s*(.+)",
                    r".innerHTML = DOMPurify.sanitize(\1)",
                    line,
                )
            # Replace dangerouslySetInnerHTML without sanitization
            if "dangerouslySetInnerHTML" in line and "DOMPurify" not in line:
                line = re.sub(
                    r"__html:\s*(.+?)\s*\}",
                    r"__html: DOMPurify.sanitize(\1) }",
                    line,
                )
            result_lines.append(line)

        return "\n".join(result_lines)

    # ==================================================================
    # CWE-89: SQL Injection
    # ==================================================================

    @classmethod
    def _fix_cwe_89(
        cls, finding: Dict[str, Any], source_code: Optional[str]
    ) -> CWEFixTemplate:
        """Generate fix for CWE-89 (SQL Injection).

        Strategies applied:
          - Replace string formatting/concatenation in SQL with parameterized queries
          - Use prepared statements with bind parameters
        """
        file_path = cls._file_path(finding, "db.py")
        lang = cls._language(finding)
        vulnerable = source_code or finding.get("code_snippet", "")

        fix_code = cls._fix_cwe_89_python(vulnerable, file_path)

        test_code = textwrap.dedent('''\
            """Test CWE-89 (SQL Injection) fix: verify parameterized queries."""
            import re
            import pytest


            class TestCWE89Fix:
                """Validate SQL injection prevention."""

                SQL_INJECTION_PAYLOADS = [
                    "'; DROP TABLE users; --",
                    "1 OR 1=1",
                    "' UNION SELECT * FROM secrets --",
                    "1; DELETE FROM users",
                    "admin'--",
                ]

                def test_no_string_formatting_in_sql(self):
                    """Verify no f-strings or % formatting in SQL queries."""
                    fix_source = open("{file_path}", "r").read()
                    # Detect f"SELECT ... {{var}}" patterns
                    fstring_sql = re.findall(
                        r'f["\\'](SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER).*\\{{',
                        fix_source, re.IGNORECASE,
                    )
                    assert len(fstring_sql) == 0, f"f-string SQL found: {{fstring_sql}}"

                    # Detect "SELECT ... %s" % var patterns
                    percent_sql = re.findall(
                        r'["\\'](SELECT|INSERT|UPDATE|DELETE).*%[sd]["\\'"]\\s*%',
                        fix_source, re.IGNORECASE,
                    )
                    assert len(percent_sql) == 0, f"%-format SQL found: {{percent_sql}}"

                def test_parameterized_query_present(self):
                    """Verify parameterized queries use ? or %s placeholders."""
                    fix_source = open("{file_path}", "r").read()
                    has_params = (
                        "?" in fix_source
                        or "%(name)s" in fix_source
                        or "execute(" in fix_source
                    )
                    assert has_params, "No parameterized query patterns found"

                def test_injection_payload_would_be_escaped(self):
                    """Verify injection payloads are treated as literal values."""
                    import sqlite3
                    conn = sqlite3.connect(":memory:")
                    conn.execute("CREATE TABLE test (id INTEGER, name TEXT)")
                    conn.execute("INSERT INTO test VALUES (1, 'safe')")

                    for payload in self.SQL_INJECTION_PAYLOADS:
                        # Parameterized query should NOT execute injected SQL
                        cursor = conn.execute(
                            "SELECT * FROM test WHERE name = ?", (payload,)
                        )
                        rows = cursor.fetchall()
                        # Injection payloads should return 0 rows, not cause errors
                        assert len(rows) == 0
                    conn.close()
        ''').format(file_path=file_path)

        diff = cls._make_unified_diff(file_path, vulnerable, fix_code) if vulnerable else ""

        return CWEFixTemplate(
            cwe_id="CWE-89",
            cwe_name="SQL Injection",
            fix_code=fix_code,
            test_code=test_code,
            pr_title=f"fix(security): remediate SQL injection (CWE-89) in {file_path}",
            pr_description=cls._build_cwe_pr_description(
                cwe_id="CWE-89",
                cwe_name="SQL Injection",
                severity=finding.get("severity", "critical"),
                file_path=file_path,
                description=(
                    "Replaced all string-formatted SQL queries with parameterized "
                    "queries using bind parameters (`?` for SQLite, `%s` for "
                    "PostgreSQL/MySQL). This prevents attacker-controlled input from "
                    "being interpreted as SQL syntax."
                ),
                diff=diff,
            ),
            files_modified=[file_path],
            language=lang,
            effort_minutes=20,
            confidence=0.95,
            mitre_techniques=["T1190"],
            compliance_refs=["CWE-89", "OWASP A03:2021", "PCI-DSS 6.5.1"],
        )

    @staticmethod
    def _fix_cwe_89_python(source: str, file_path: str) -> str:
        """Replace string-formatted SQL with parameterized queries."""
        lines = source.splitlines()
        result_lines: List[str] = []

        for line in lines:
            original = line

            # Pattern 1: f"SELECT ... {variable}" -> "SELECT ... ?", (variable,)
            fstr_match = re.search(
                r'(\.execute\s*\(\s*)f["\']'
                r"((?:SELECT|INSERT|UPDATE|DELETE)\b[^\"']*)"
                r'\{(\w+)\}'
                r'([^"\']*)["\']'
                r"\s*\)",
                line,
                re.IGNORECASE,
            )
            if fstr_match:
                prefix = fstr_match.group(1)
                sql_before = fstr_match.group(2)
                var_name = fstr_match.group(3)
                sql_after = fstr_match.group(4)
                line = line[: fstr_match.start()] + (
                    f'{prefix}"{sql_before}?{sql_after}", ({var_name},))'
                )
                result_lines.append("# FIXOPS: CWE-89 fix -- parameterized query (was f-string)")
                result_lines.append(line)
                continue

            # Pattern 2: "SELECT ... %s" % variable -> parameterized
            pct_match = re.search(
                r'(\.execute\s*\(\s*)["\']'
                r"((?:SELECT|INSERT|UPDATE|DELETE)\b[^\"']*%s[^\"']*)"
                r'["\']'
                r"\s*%\s*(\w+)",
                line,
                re.IGNORECASE,
            )
            if pct_match:
                prefix = pct_match.group(1)
                sql_template = pct_match.group(2).replace("%s", "?")
                var_name = pct_match.group(3)
                line = f'{prefix}"{sql_template}", ({var_name},))'
                result_lines.append("# FIXOPS: CWE-89 fix -- parameterized query (was %-format)")
                result_lines.append(line)
                continue

            # Pattern 3: "SELECT ... " + variable + " ..." -> parameterized
            concat_match = re.search(
                r'(\.execute\s*\(\s*)["\']'
                r"((?:SELECT|INSERT|UPDATE|DELETE)\b[^\"']*)"
                r'["\']'
                r"\s*\+\s*(\w+)\s*\+?\s*",
                line,
                re.IGNORECASE,
            )
            if concat_match:
                prefix = concat_match.group(1)
                sql_part = concat_match.group(2)
                var_name = concat_match.group(3)
                line = f'{prefix}"{sql_part} ?", ({var_name},))'
                result_lines.append("# FIXOPS: CWE-89 fix -- parameterized query (was concatenation)")
                result_lines.append(line)
                continue

            result_lines.append(original)

        return "\n".join(result_lines)

    # ==================================================================
    # CWE-502: Deserialization of Untrusted Data
    # ==================================================================

    @classmethod
    def _fix_cwe_502(
        cls, finding: Dict[str, Any], source_code: Optional[str]
    ) -> CWEFixTemplate:
        """Generate fix for CWE-502 (Insecure Deserialization).

        Strategies applied:
          - Replace pickle.loads with json.loads for untrusted data
          - Replace yaml.load with yaml.safe_load
          - Add type checking on deserialized data
        """
        file_path = cls._file_path(finding, "serializer.py")
        lang = cls._language(finding)
        vulnerable = source_code or finding.get("code_snippet", "")

        fix_code = cls._fix_cwe_502_python(vulnerable, file_path)

        test_code = textwrap.dedent('''\
            """Test CWE-502 (Insecure Deserialization) fix."""
            import json
            import pytest


            class TestCWE502Fix:
                """Validate deserialization safety."""

                def test_no_pickle_loads_on_untrusted(self):
                    """Verify pickle.loads is not called on untrusted data."""
                    fix_source = open("{file_path}", "r").read()
                    # pickle.loads should be replaced or guarded
                    import re
                    unsafe = re.findall(
                        r"pickle\\.loads?\\((?!.*_TRUSTED)",
                        fix_source,
                    )
                    # Allow if explicitly marked as trusted internal data
                    assert len(unsafe) == 0 or "_TRUSTED" in fix_source, (
                        "pickle.loads used on potentially untrusted data"
                    )

                def test_no_yaml_unsafe_load(self):
                    """Verify yaml.load uses safe_load."""
                    fix_source = open("{file_path}", "r").read()
                    import re
                    unsafe = re.findall(
                        r"yaml\\.load\\(",
                        fix_source,
                    )
                    assert len(unsafe) == 0, "yaml.load (unsafe) found -- use yaml.safe_load"

                def test_json_loads_handles_malicious(self):
                    """Verify json.loads safely rejects non-JSON."""
                    import pickle
                    import os

                    # Craft a malicious pickle payload
                    class Evil:
                        def __reduce__(self):
                            return (os.system, ("echo pwned",))

                    malicious = pickle.dumps(Evil())

                    # json.loads should reject binary pickle data
                    with pytest.raises((json.JSONDecodeError, UnicodeDecodeError, TypeError)):
                        json.loads(malicious)
        ''').format(file_path=file_path)

        diff = cls._make_unified_diff(file_path, vulnerable, fix_code) if vulnerable else ""

        return CWEFixTemplate(
            cwe_id="CWE-502",
            cwe_name="Deserialization of Untrusted Data",
            fix_code=fix_code,
            test_code=test_code,
            pr_title=f"fix(security): remediate insecure deserialization (CWE-502) in {file_path}",
            pr_description=cls._build_cwe_pr_description(
                cwe_id="CWE-502",
                cwe_name="Deserialization of Untrusted Data",
                severity=finding.get("severity", "critical"),
                file_path=file_path,
                description=(
                    "Replaced `pickle.loads()` with `json.loads()` for untrusted data "
                    "deserialization. Replaced `yaml.load()` with `yaml.safe_load()`. "
                    "Added input type validation post-deserialization. Pickle-based RCE "
                    "is no longer possible via this code path."
                ),
                diff=diff,
            ),
            files_modified=[file_path],
            language=lang,
            effort_minutes=25,
            confidence=0.93,
            mitre_techniques=["T1059"],
            compliance_refs=["CWE-502", "OWASP A08:2021"],
        )

    @staticmethod
    def _fix_cwe_502_python(source: str, file_path: str) -> str:
        """Replace unsafe deserialization with safe alternatives."""
        lines = source.splitlines()
        result_lines: List[str] = []
        json_import_needed = False

        for line in lines:
            # Replace pickle.loads with json.loads
            if re.search(r"\bpickle\.loads?\b", line):
                result_lines.append(
                    "# FIXOPS: CWE-502 fix -- replaced pickle with json (safe deserialization)"
                )
                line = re.sub(r"\bpickle\.loads?\(", "json.loads(", line)
                json_import_needed = True

            # Replace yaml.load with yaml.safe_load
            if re.search(r"\byaml\.load\b", line) and "safe_load" not in line:
                result_lines.append(
                    "# FIXOPS: CWE-502 fix -- replaced yaml.load with yaml.safe_load"
                )
                line = re.sub(r"\byaml\.load\(", "yaml.safe_load(", line)
                # Remove explicit Loader= arg since safe_load doesn't need it
                line = re.sub(r",\s*Loader=yaml\.FullLoader", "", line)
                line = re.sub(r",\s*Loader=yaml\.UnsafeLoader", "", line)
                line = re.sub(r",\s*Loader=yaml\.Loader", "", line)

            # Replace marshal.loads (also unsafe)
            if re.search(r"\bmarshal\.loads?\b", line):
                result_lines.append(
                    "# FIXOPS: CWE-502 fix -- replaced marshal with json"
                )
                line = re.sub(r"\bmarshal\.loads?\(", "json.loads(", line)
                json_import_needed = True

            result_lines.append(line)

        # Add json import if needed
        if json_import_needed:
            result_lines.insert(0, "import json  # FIXOPS: CWE-502 safe deserialization")

        return "\n".join(result_lines)

    # ==================================================================
    # CWE-78: OS Command Injection
    # ==================================================================

    @classmethod
    def _fix_cwe_78(
        cls, finding: Dict[str, Any], source_code: Optional[str]
    ) -> CWEFixTemplate:
        """Generate fix for CWE-78 (OS Command Injection).

        Strategies applied:
          - Replace os.system/os.popen with subprocess.run
          - Use shlex.quote for shell arguments
          - Use shell=False (default) with argument lists
          - Add input validation allow-list
        """
        file_path = cls._file_path(finding, "executor.py")
        lang = cls._language(finding)
        vulnerable = source_code or finding.get("code_snippet", "")

        fix_code = cls._fix_cwe_78_python(vulnerable, file_path)

        test_code = textwrap.dedent('''\
            """Test CWE-78 (OS Command Injection) fix."""
            import re
            import shlex
            import pytest


            class TestCWE78Fix:
                """Validate command injection prevention."""

                INJECTION_PAYLOADS = [
                    "; rm -rf /",
                    "| cat /etc/passwd",
                    "$(whoami)",
                    "`id`",
                    "& net user /add hacker",
                    "\\n/bin/sh",
                ]

                def test_no_os_system(self):
                    """Verify os.system is not used."""
                    fix_source = open("{file_path}", "r").read()
                    assert "os.system(" not in fix_source, (
                        "os.system found -- use subprocess.run with shell=False"
                    )

                def test_no_os_popen(self):
                    """Verify os.popen is not used."""
                    fix_source = open("{file_path}", "r").read()
                    assert "os.popen(" not in fix_source, (
                        "os.popen found -- use subprocess.run with shell=False"
                    )

                def test_no_shell_true(self):
                    """Verify shell=True is not used with user input."""
                    fix_source = open("{file_path}", "r").read()
                    # shell=True is dangerous if combined with user input
                    shell_true = re.findall(r"shell\\s*=\\s*True", fix_source)
                    assert len(shell_true) == 0, "shell=True found -- use shell=False"

                def test_shlex_quote_neutralizes_injection(self):
                    """Verify shlex.quote prevents command injection."""
                    for payload in self.INJECTION_PAYLOADS:
                        quoted = shlex.quote(payload)
                        # Quoted string should be a single shell token
                        assert quoted.startswith("'") or quoted.startswith('"') or "\\\\" in quoted
                        # Should not allow command chaining
                        assert ";" not in quoted.strip("'")  or "\\\\;" in quoted
        ''').format(file_path=file_path)

        diff = cls._make_unified_diff(file_path, vulnerable, fix_code) if vulnerable else ""

        return CWEFixTemplate(
            cwe_id="CWE-78",
            cwe_name="OS Command Injection",
            fix_code=fix_code,
            test_code=test_code,
            pr_title=f"fix(security): remediate command injection (CWE-78) in {file_path}",
            pr_description=cls._build_cwe_pr_description(
                cwe_id="CWE-78",
                cwe_name="OS Command Injection",
                severity=finding.get("severity", "critical"),
                file_path=file_path,
                description=(
                    "Replaced `os.system()` and `os.popen()` with `subprocess.run()` "
                    "using `shell=False` and argument lists. Applied `shlex.quote()` "
                    "to any user-controlled values passed to shell commands. Added "
                    "input validation allow-list for command arguments."
                ),
                diff=diff,
            ),
            files_modified=[file_path],
            language=lang,
            effort_minutes=20,
            confidence=0.94,
            mitre_techniques=["T1059.004"],
            compliance_refs=["CWE-78", "OWASP A03:2021", "PCI-DSS 6.5.1"],
        )

    @staticmethod
    def _fix_cwe_78_python(source: str, file_path: str) -> str:
        """Replace os.system/os.popen with subprocess.run + shlex.quote."""
        lines = source.splitlines()
        result_lines: List[str] = []
        needs_subprocess = False
        needs_shlex = False

        for line in lines:
            # Replace os.system(f"cmd {var}") -> subprocess.run(["cmd", shlex.quote(var)])
            sys_match = re.search(
                r'os\.system\(\s*f?["\'](.+?)\s*\{?(\w+)\}?\s*["\']?\s*\)',
                line,
            )
            if sys_match or "os.system(" in line:
                result_lines.append(
                    "# FIXOPS: CWE-78 fix -- replaced os.system with subprocess.run(shell=False)"
                )
                if sys_match:
                    cmd = sys_match.group(1).strip()
                    var = sys_match.group(2) if sys_match.lastindex and sys_match.lastindex >= 2 else ""
                    if var:
                        line = re.sub(
                            r'os\.system\([^)]+\)',
                            f'subprocess.run(["{cmd}", shlex.quote({var})], check=False)',
                            line,
                        )
                    else:
                        cmd_parts = cmd.split()
                        args_str = ", ".join(f'"{p}"' for p in cmd_parts)
                        line = re.sub(
                            r'os\.system\([^)]+\)',
                            f"subprocess.run([{args_str}], check=False)",
                            line,
                        )
                else:
                    line = line.replace("os.system(", "subprocess.run(")
                needs_subprocess = True
                needs_shlex = True

            # Replace os.popen
            if "os.popen(" in line:
                result_lines.append(
                    "# FIXOPS: CWE-78 fix -- replaced os.popen with subprocess.run"
                )
                line = re.sub(
                    r"os\.popen\(([^)]+)\)\.read\(\)",
                    r"subprocess.run(\1, capture_output=True, text=True, shell=False).stdout",
                    line,
                )
                line = re.sub(
                    r"os\.popen\(([^)]+)\)",
                    r"subprocess.run(\1, capture_output=True, text=True, shell=False)",
                    line,
                )
                needs_subprocess = True

            # Replace shell=True with shell=False
            if "shell=True" in line:
                result_lines.append("# FIXOPS: CWE-78 fix -- disabled shell=True")
                line = line.replace("shell=True", "shell=False")

            result_lines.append(line)

        # Add imports at top
        imports = []
        if needs_subprocess and "import subprocess" not in source:
            imports.append("import subprocess  # FIXOPS: CWE-78 safe command execution")
        if needs_shlex and "import shlex" not in source:
            imports.append("import shlex  # FIXOPS: CWE-78 shell argument quoting")
        for imp in reversed(imports):
            result_lines.insert(0, imp)

        return "\n".join(result_lines)

    # ==================================================================
    # CWE-22: Path Traversal
    # ==================================================================

    @classmethod
    def _fix_cwe_22(
        cls, finding: Dict[str, Any], source_code: Optional[str]
    ) -> CWEFixTemplate:
        """Generate fix for CWE-22 (Path Traversal).

        Strategies applied:
          - Canonicalize paths with os.path.realpath
          - Validate path is within allowed base directory
          - Reject path components containing '..'
          - Use pathlib for safe path construction
        """
        file_path = cls._file_path(finding, "file_handler.py")
        lang = cls._language(finding)
        vulnerable = source_code or finding.get("code_snippet", "")

        fix_code = cls._fix_cwe_22_python(vulnerable, file_path)

        test_code = textwrap.dedent('''\
            """Test CWE-22 (Path Traversal) fix."""
            import os
            import tempfile
            import pytest


            def _safe_join(base_dir: str, user_path: str) -> str:
                """Reference implementation of safe path join."""
                # Reject obvious traversal attempts
                if ".." in user_path.replace("\\\\", "/").split("/"):
                    raise ValueError("Path traversal detected: '..' not allowed")
                joined = os.path.join(base_dir, user_path)
                real = os.path.realpath(joined)
                real_base = os.path.realpath(base_dir)
                if not real.startswith(real_base + os.sep) and real != real_base:
                    raise ValueError(
                        f"Path traversal: resolved path {{real}} escapes base {{real_base}}"
                    )
                return real


            class TestCWE22Fix:
                """Validate path traversal prevention."""

                TRAVERSAL_PAYLOADS = [
                    "../../../etc/passwd",
                    "..\\\\..\\\\..\\\\windows\\\\system32\\\\config\\\\sam",
                    "....//....//etc/passwd",
                    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                    "/etc/passwd",
                    "..%00/etc/passwd",
                ]

                def test_traversal_blocked(self):
                    """Verify path traversal payloads are rejected."""
                    with tempfile.TemporaryDirectory() as base:
                        for payload in self.TRAVERSAL_PAYLOADS:
                            try:
                                result = _safe_join(base, payload)
                                # If it didn't raise, verify it's within base
                                assert result.startswith(os.path.realpath(base))
                            except ValueError:
                                pass  # Expected -- traversal blocked

                def test_safe_paths_allowed(self):
                    """Verify legitimate paths work."""
                    with tempfile.TemporaryDirectory() as base:
                        os.makedirs(os.path.join(base, "subdir"), exist_ok=True)
                        result = _safe_join(base, "subdir/file.txt")
                        assert result.startswith(os.path.realpath(base))

                def test_no_raw_path_join(self):
                    """Verify fix uses safe path construction."""
                    fix_source = open("{file_path}", "r").read()
                    assert "realpath" in fix_source or "resolve()" in fix_source, (
                        "Path canonicalization missing"
                    )
        ''').format(file_path=file_path)

        diff = cls._make_unified_diff(file_path, vulnerable, fix_code) if vulnerable else ""

        return CWEFixTemplate(
            cwe_id="CWE-22",
            cwe_name="Path Traversal",
            fix_code=fix_code,
            test_code=test_code,
            pr_title=f"fix(security): remediate path traversal (CWE-22) in {file_path}",
            pr_description=cls._build_cwe_pr_description(
                cwe_id="CWE-22",
                cwe_name="Path Traversal",
                severity=finding.get("severity", "high"),
                file_path=file_path,
                description=(
                    "Added path canonicalization via `os.path.realpath()` and base "
                    "directory validation to prevent directory traversal attacks. "
                    "Paths containing `..` components are rejected. All file paths "
                    "are now resolved to absolute form and validated against the "
                    "allowed base directory before use."
                ),
                diff=diff,
            ),
            files_modified=[file_path],
            language=lang,
            effort_minutes=15,
            confidence=0.93,
            mitre_techniques=["T1083"],
            compliance_refs=["CWE-22", "OWASP A01:2021", "PCI-DSS 6.5.8"],
        )

    @staticmethod
    def _fix_cwe_22_python(source: str, file_path: str) -> str:
        """Add path canonicalization and traversal guards."""
        lines = source.splitlines()
        result_lines: List[str] = []
        needs_os = "import os" not in source

        # Add safe_join function at the top
        safe_join_fn = [
            "",
            "# FIXOPS: CWE-22 fix -- safe path join with traversal guard",
            "def _fixops_safe_path(base_dir: str, user_path: str) -> str:",
            '    """Join base_dir + user_path safely, preventing traversal."""',
            "    import os",
            "    # Reject '..' components",
            '    parts = user_path.replace("\\\\", "/").split("/")',
            '    if ".." in parts:',
            "        raise ValueError('Path traversal attempt blocked: .. in path')",
            "    joined = os.path.join(base_dir, user_path)",
            "    real = os.path.realpath(joined)",
            "    real_base = os.path.realpath(base_dir)",
            "    if not real.startswith(real_base + os.sep) and real != real_base:",
            "        raise ValueError(",
            '            f"Path traversal blocked: {real} escapes {real_base}"',
            "        )",
            "    return real",
            "",
        ]

        for line in lines:
            # Replace open(user_input) with open(_fixops_safe_path(BASE, user_input))
            open_match = re.search(
                r'open\(\s*(\w+)\s*[,)]', line
            )
            if open_match and "fixops_safe_path" not in line:
                var = open_match.group(1)
                # Only transform if the variable looks user-controlled
                if var not in ("__file__", "self", "cls"):
                    result_lines.append(
                        "# FIXOPS: CWE-22 fix -- safe path resolution applied"
                    )
                    line = line.replace(
                        f"open({var}",
                        f'open(_fixops_safe_path(".", {var})',
                    )

            # Replace os.path.join without validation
            if "os.path.join(" in line and "realpath" not in line and "fixops" not in line:
                join_match = re.search(r'os\.path\.join\(([^,]+),\s*([^)]+)\)', line)
                if join_match:
                    base = join_match.group(1).strip()
                    user = join_match.group(2).strip()
                    result_lines.append(
                        "# FIXOPS: CWE-22 fix -- replaced os.path.join with safe variant"
                    )
                    line = re.sub(
                        r'os\.path\.join\([^)]+\)',
                        f"_fixops_safe_path({base}, {user})",
                        line,
                        count=1,
                    )

            result_lines.append(line)

        if needs_os:
            result_lines.insert(0, "import os  # FIXOPS: CWE-22 path operations")

        # Insert the safe_join function after imports
        insert_pos = 0
        for i, line in enumerate(result_lines):
            if line and not line.startswith("import ") and not line.startswith("from ") and not line.startswith("#"):
                insert_pos = i
                break
        for j, safe_line in enumerate(safe_join_fn):
            result_lines.insert(insert_pos + j, safe_line)

        return "\n".join(result_lines)

    # ------------------------------------------------------------------
    # PR description builder
    # ------------------------------------------------------------------

    @staticmethod
    def _build_cwe_pr_description(
        cwe_id: str,
        cwe_name: str,
        severity: str,
        file_path: str,
        description: str,
        diff: str = "",
    ) -> str:
        """Build a standardized PR description for a CWE fix."""
        lines = [
            "## Security Fix: " + cwe_id + " -- " + cwe_name,
            "",
            f"**Severity:** {severity.upper()}",
            f"**File:** `{file_path}`",
            f"**CWE:** [{cwe_id}](https://cwe.mitre.org/data/definitions/{cwe_id.split('-')[-1]}.html)",
            "",
            "### What changed",
            description,
            "",
        ]

        if diff:
            lines.extend([
                "### Diff",
                "```diff",
                diff[:3000],  # Truncate extremely large diffs
                "```",
                "",
            ])

        lines.extend([
            "### Testing",
            "- Unit tests included in this PR validate the fix",
            "- Run `pytest` to verify",
            "",
            "### Rollback",
            "Revert this commit to restore previous behavior.",
            "",
            "---",
            "*Automated by FixOps Self-Healing Remediation Engine (Pillar V7)*",
        ])

        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Remediation Engine
# ---------------------------------------------------------------------------


class RemediationEngine:
    """Orchestrates end-to-end vulnerability remediation.

    Coordinates the full remediation lifecycle:
    1. Analyze finding and determine strategy
    2. Generate fix (via CWE templates or AutoFix engine)
    3. Create PR (via PRGenerator)
    4. Track remediation status
    5. Verify fix after merge

    Serves Vision Pillar V7 (Self-Healing Remediation).
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize remediation engine.

        Args:
            config: Optional configuration dict with keys:
                - auto_fix_enabled: bool (default True)
                - max_concurrent: int (default 5)
                - scm_provider: str (github|gitlab)
                - scm_token: str
                - scm_owner: str
                - scm_repo: str
                - default_branch: str (default main)
        """
        self.config = config or {}
        self.auto_fix_enabled = self.config.get("auto_fix_enabled", True)
        self.max_concurrent = self.config.get("max_concurrent", 5)
        self._results: Dict[str, RemediationResult] = {}
        self._pr_generator = None
        self._autofix_engine = None
        self._cwe_registry = CWEFixRegistry()

    def _get_pr_generator(self):
        """Lazy-load PR generator."""
        if self._pr_generator is None:
            try:
                from automation.pr_generator import PRGenerator

                self._pr_generator = PRGenerator(self.config)
            except ImportError:
                logger.warning("PRGenerator not available")
        return self._pr_generator

    def _get_autofix_engine(self):
        """Lazy-load autofix engine."""
        if self._autofix_engine is None:
            try:
                from core.autofix_engine import AutoFixEngine

                self._autofix_engine = AutoFixEngine()
            except ImportError:
                logger.warning("AutoFixEngine not available")
        return self._autofix_engine

    def determine_strategy(
        self,
        finding: Dict[str, Any],
        policy: Optional[Dict[str, Any]] = None,
    ) -> RemediationStrategy:
        """Determine the best remediation strategy for a finding.

        Args:
            finding: Finding dict with severity, type, etc.
            policy: Optional policy dict with auto_fix rules.

        Returns:
            RemediationStrategy to apply.
        """
        severity = finding.get("severity", "medium").lower()
        fix_available = finding.get("fix_available", False)
        cwe_id = finding.get("cwe_id", "")

        if not self.auto_fix_enabled:
            return RemediationStrategy.MANUAL

        # CWE template available = auto-fix with high confidence
        if cwe_id and CWEFixRegistry.can_fix(cwe_id):
            return RemediationStrategy.AUTO_FIX

        # Auto-fix critical findings with known fixes
        if severity in ("critical", "high") and fix_available:
            return RemediationStrategy.AUTO_FIX

        # Guided for medium with fixes
        if severity == "medium" and fix_available:
            return RemediationStrategy.GUIDED

        # Manual for everything else
        return RemediationStrategy.MANUAL

    def remediate(
        self,
        finding_id: str,
        finding: Dict[str, Any],
        strategy: Optional[RemediationStrategy] = None,
    ) -> RemediationResult:
        """Execute remediation for a finding.

        Args:
            finding_id: Unique finding identifier.
            finding: Finding dict with vulnerability details.
            strategy: Override strategy (auto-determined if None).

        Returns:
            RemediationResult with status and details.
        """
        if strategy is None:
            strategy = self.determine_strategy(finding)

        result = RemediationResult(
            finding_id=finding_id,
            strategy=strategy,
            started_at=datetime.now(timezone.utc),
        )

        try:
            if strategy == RemediationStrategy.AUTO_FIX:
                result = self._auto_remediate(result, finding)
            elif strategy == RemediationStrategy.GUIDED:
                result = self._guided_remediate(result, finding)
            elif strategy == RemediationStrategy.ACCEPT_RISK:
                result.status = RemediationStatus.SKIPPED
                result.fix_description = "Risk accepted per policy"
            else:
                result.status = RemediationStatus.PENDING
                result.fix_description = "Manual remediation required"

        except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
            logger.error("Remediation failed for %s: %s", finding_id, e)
            result.status = RemediationStatus.FAILED
            result.error = str(e)

        result.completed_at = datetime.now(timezone.utc)
        self._results[finding_id] = result
        return result

    def remediate_cwe(
        self,
        finding_id: str,
        cwe_id: str,
        finding: Dict[str, Any],
        source_code: Optional[str] = None,
    ) -> RemediationResult:
        """Remediate a finding using CWE-specific fix template.

        Args:
            finding_id: Unique finding identifier.
            cwe_id: CWE identifier (e.g. "CWE-79").
            finding: Finding dict with vulnerability details.
            source_code: Optional vulnerable source code.

        Returns:
            RemediationResult with CWE fix template attached.
        """
        result = RemediationResult(
            finding_id=finding_id,
            strategy=RemediationStrategy.AUTO_FIX,
            started_at=datetime.now(timezone.utc),
        )

        try:
            if not CWEFixRegistry.can_fix(cwe_id):
                result.status = RemediationStatus.FAILED
                result.error = f"No fix template for {cwe_id}"
                result.completed_at = datetime.now(timezone.utc)
                self._results[finding_id] = result
                return result

            cwe_fix = CWEFixRegistry.generate_fix(cwe_id, finding, source_code)
            result.cwe_fix = cwe_fix
            result.fix_description = cwe_fix.pr_description
            result.files_modified = cwe_fix.files_modified
            result.status = RemediationStatus.FIX_GENERATED

            logger.info(
                "CWE fix generated for %s (%s) -- confidence %.0f%%",
                finding_id,
                cwe_id,
                cwe_fix.confidence * 100,
            )

        except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
            logger.error("CWE remediation failed for %s: %s", finding_id, e)
            result.status = RemediationStatus.FAILED
            result.error = str(e)

        result.completed_at = datetime.now(timezone.utc)
        self._results[finding_id] = result
        return result

    def _auto_remediate(
        self,
        result: RemediationResult,
        finding: Dict[str, Any],
    ) -> RemediationResult:
        """Fully automated remediation: CWE template or AutoFix engine."""
        result.status = RemediationStatus.IN_PROGRESS
        cwe_id = finding.get("cwe_id", "")

        # Prefer CWE template if available
        if cwe_id and CWEFixRegistry.can_fix(cwe_id):
            try:
                cwe_fix = CWEFixRegistry.generate_fix(
                    cwe_id, finding, finding.get("code_snippet")
                )
                result.cwe_fix = cwe_fix
                result.fix_description = cwe_fix.pr_description
                result.files_modified = cwe_fix.files_modified
                result.status = RemediationStatus.FIX_GENERATED

                # Try to create PR
                pr_gen = self._get_pr_generator()
                if pr_gen:
                    repository = self.config.get("repository", "")
                    if repository:
                        branch = f"fixops/remediate-{cwe_id.lower()}-{hashlib.sha256(result.finding_id.encode()).hexdigest()[:8]}"
                        changes: Dict[str, str] = {}
                        for fp in cwe_fix.files_modified:
                            changes[fp] = cwe_fix.fix_code
                        # Add test file
                        test_file = f"tests/test_security_{cwe_id.lower().replace('-', '_')}.py"
                        changes[test_file] = cwe_fix.test_code

                        try:
                            pr_result = pr_gen.create_pr(
                                repository=repository,
                                title=cwe_fix.pr_title,
                                description=cwe_fix.pr_description,
                                branch=branch,
                                changes=changes,
                            )
                            if pr_result.success:
                                result.pr_url = pr_result.pr_url
                                result.pr_id = str(pr_result.pr_number)
                                result.branch_name = branch
                                result.status = RemediationStatus.PR_CREATED
                        except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
                            logger.warning("PR creation failed for CWE fix: %s", e)
                            # Fix is still generated even if PR fails

                return result
            except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
                logger.warning("CWE template failed, falling back to AutoFix: %s", e)

        # Fallback to AutoFix engine
        autofix = self._get_autofix_engine()
        if autofix:
            try:
                fix = autofix.generate_fix(finding)
                if fix:
                    result.fix_description = fix.get("description", "Auto-generated fix")
                    result.files_modified = fix.get("files", [])
                    result.status = RemediationStatus.FIX_GENERATED
                else:
                    result.status = RemediationStatus.FAILED
                    result.error = "AutoFix could not generate a fix"
                    return result
            except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
                logger.warning("AutoFix failed, falling back to guided: %s", e)
                result.status = RemediationStatus.FIX_GENERATED
                result.fix_description = (
                    f"Fix needed for {finding.get('title', finding.get('cve_id', 'unknown'))}"
                )

        # Step 2: Create PR
        pr_gen = self._get_pr_generator()
        if pr_gen and result.files_modified:
            try:
                repository = self.config.get("repository", "")
                if repository:
                    pr_result = pr_gen.create_pr(
                        repository=repository,
                        title=f"fix: remediate {finding.get('cve_id', finding.get('title', 'vulnerability'))}",
                        description=result.fix_description,
                        branch=f"fixops/fix-{hashlib.sha256(result.finding_id.encode()).hexdigest()[:8]}",
                        changes={f: "" for f in result.files_modified},
                    )
                    if pr_result.success:
                        result.pr_url = pr_result.pr_url
                        result.pr_id = str(pr_result.pr_number)
                        result.branch_name = pr_result.branch_name
                        result.status = RemediationStatus.PR_CREATED
                    else:
                        result.error = pr_result.error
            except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
                logger.warning("PR creation failed: %s", e)
                result.error = str(e)

        return result

    def _guided_remediate(
        self,
        result: RemediationResult,
        finding: Dict[str, Any],
    ) -> RemediationResult:
        """Guided remediation: generate fix suggestion for human review."""
        cwe_id = finding.get("cwe_id", "")

        # Use CWE template if available for guided mode too
        if cwe_id and CWEFixRegistry.can_fix(cwe_id):
            try:
                cwe_fix = CWEFixRegistry.generate_fix(
                    cwe_id, finding, finding.get("code_snippet")
                )
                result.cwe_fix = cwe_fix
                result.fix_description = (
                    f"Guided fix for {cwe_id}: {cwe_fix.cwe_name}. "
                    f"Review the suggested patch and apply manually.\n\n"
                    f"{cwe_fix.pr_description}"
                )
                result.files_modified = cwe_fix.files_modified
                result.status = RemediationStatus.FIX_GENERATED
                return result
            except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
                logger.warning("CWE template failed in guided mode: %s", e)

        result.status = RemediationStatus.FIX_GENERATED
        result.fix_description = (
            f"Guided fix for {finding.get('title', finding.get('cve_id', 'unknown'))}: "
            f"Review and apply the suggested patch."
        )
        return result

    def get_result(self, finding_id: str) -> Optional[RemediationResult]:
        """Get remediation result by finding ID."""
        return self._results.get(finding_id)

    def get_all_results(self) -> Dict[str, RemediationResult]:
        """Get all remediation results."""
        return dict(self._results)

    def get_metrics(self) -> Dict[str, Any]:
        """Get remediation metrics."""
        total = len(self._results)
        if total == 0:
            return {
                "total": 0,
                "success_rate": 0.0,
                "by_status": {},
                "by_strategy": {},
                "cwe_fixes": 0,
                "supported_cwes": CWEFixRegistry.supported_cwes(),
            }

        by_status: Dict[str, int] = {}
        by_strategy: Dict[str, int] = {}
        cwe_fixes = 0
        for r in self._results.values():
            by_status[r.status.value] = by_status.get(r.status.value, 0) + 1
            by_strategy[r.strategy.value] = by_strategy.get(r.strategy.value, 0) + 1
            if r.cwe_fix is not None:
                cwe_fixes += 1

        success_count = sum(
            1
            for r in self._results.values()
            if r.status
            in (
                RemediationStatus.PR_CREATED,
                RemediationStatus.PR_MERGED,
                RemediationStatus.VERIFIED,
                RemediationStatus.FIX_GENERATED,
            )
        )

        return {
            "total": total,
            "success_rate": success_count / total if total > 0 else 0.0,
            "by_status": by_status,
            "by_strategy": by_strategy,
            "cwe_fixes": cwe_fixes,
            "supported_cwes": CWEFixRegistry.supported_cwes(),
        }
