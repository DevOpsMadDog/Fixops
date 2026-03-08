"""
Hardening Tests — 2026-03-07 (Friday — Dependency Security & Info Disclosure)

Tests for:
1. WIQL injection prevention in Azure DevOps connector
2. CLI URL scheme validation for urllib.request.urlopen
3. str(exc) info disclosure prevention across security_connectors, connectors,
   llm_providers, cve_tester, scanner_ingest_router, middleware
4. pypdf CVE-2026-28804 fix verification

Backend Hardener — Pillar: V7 (MCP-Native), V3 (Decision Intelligence)
"""

from __future__ import annotations

import importlib
import re
import sys

import pytest


# ============================================================================
# 1. WIQL Injection Prevention (connectors.py)
# ============================================================================


class TestWIQLInjectionPrevention:
    """Verify Azure DevOps connector sanitizes WIQL inputs."""

    def _get_connector_class(self):
        """Import AzureDevOpsConnector."""
        from core.connectors import AzureDevOpsConnector
        return AzureDevOpsConnector

    def test_sanitize_wiql_value_escapes_single_quotes(self):
        """Single quotes in WIQL values must be escaped to prevent injection."""
        cls = self._get_connector_class()
        result = cls._sanitize_wiql_value("Bug'; DROP TABLE --")
        assert "''" in result  # Single quotes are doubled
        assert "DROP" in result  # Content preserved

    def test_sanitize_wiql_value_strips_control_chars(self):
        """Control characters (newlines, tabs) stripped from WIQL values."""
        cls = self._get_connector_class()
        result = cls._sanitize_wiql_value("Bug\nType\r\tTest\x00End")
        assert "\n" not in result
        assert "\r" not in result
        assert "\t" not in result
        assert "\x00" not in result
        assert "BugTypeTestEnd" == result

    def test_sanitize_wiql_value_limits_length(self):
        """WIQL values truncated to 256 chars to prevent abuse."""
        cls = self._get_connector_class()
        result = cls._sanitize_wiql_value("A" * 1000)
        assert len(result) == 256

    def test_sanitize_wiql_value_empty_string(self):
        """Empty string remains empty."""
        cls = self._get_connector_class()
        result = cls._sanitize_wiql_value("")
        assert result == ""

    def test_sanitize_wiql_value_normal_input(self):
        """Normal input passes through unchanged."""
        cls = self._get_connector_class()
        result = cls._sanitize_wiql_value("Bug")
        assert result == "Bug"

    def test_list_work_items_uses_sanitized_values(self):
        """list_work_items sanitizes work_item_type and state before interpolation."""
        cls = self._get_connector_class()
        # Use proper __init__ with required settings
        connector = cls({
            "organization": "test-org",
            "project": "test-project",
            "token": "fake-pat",
        })

        # Mock search_work_items to capture the WIQL
        captured_wiql = []
        def mock_search(wiql, max_results=50):
            captured_wiql.append(wiql)
            from core.connectors import ConnectorOutcome
            return ConnectorOutcome("fetched", {"work_items": [], "count": 0})

        connector.search_work_items = mock_search

        # Inject SQL-like payload
        connector.list_work_items(
            work_item_type="Bug'; SELECT * FROM secrets --",
            state="Active\nHacked"
        )

        assert len(captured_wiql) == 1
        wiql = captured_wiql[0]
        # Verify single quotes are escaped
        assert "Bug''; SELECT * FROM secrets --" in wiql
        # Verify newline is stripped
        assert "\n" not in wiql
        assert "ActiveHacked" in wiql


# ============================================================================
# 2. CLI URL Scheme Validation
# ============================================================================


class TestCLIURLSchemeValidation:
    """Verify _validate_api_url blocks non-http(s) schemes."""

    def _get_validator(self):
        from core.cli import _validate_api_url
        return _validate_api_url

    def test_http_scheme_allowed(self):
        validate = self._get_validator()
        result = validate("http://localhost:8000")
        assert result == "http://localhost:8000"

    def test_https_scheme_allowed(self):
        validate = self._get_validator()
        result = validate("https://api.example.com")
        assert result == "https://api.example.com"

    def test_file_scheme_blocked(self):
        validate = self._get_validator()
        with pytest.raises(ValueError, match="http or https"):
            validate("file:///etc/passwd")

    def test_ftp_scheme_blocked(self):
        validate = self._get_validator()
        with pytest.raises(ValueError, match="http or https"):
            validate("ftp://evil.com/payload")

    def test_custom_scheme_blocked(self):
        validate = self._get_validator()
        with pytest.raises(ValueError, match="http or https"):
            validate("gopher://evil.com")

    def test_empty_scheme_blocked(self):
        validate = self._get_validator()
        with pytest.raises(ValueError):
            validate("://no-scheme")

    def test_no_hostname_blocked(self):
        validate = self._get_validator()
        with pytest.raises(ValueError, match="hostname"):
            validate("http://")

    def test_trailing_slash_stripped(self):
        validate = self._get_validator()
        result = validate("http://localhost:8000///")
        assert not result.endswith("/")


# ============================================================================
# 3. Info Disclosure Prevention (str(exc) → type(exc).__name__)
# ============================================================================


class TestSecurityConnectorsInfoDisclosure:
    """Verify security_connectors.py returns type(exc).__name__ not str(exc)."""

    def test_no_str_exc_in_security_connectors(self):
        """security_connectors.py must not use str(exc) in ConnectorOutcome."""
        import inspect
        from core import security_connectors
        source = inspect.getsource(security_connectors)
        # Should use type(exc).__name__ instead of str(exc)
        matches = re.findall(r'"error":\s*str\(exc\)', source)
        assert len(matches) == 0, (
            f"Found {len(matches)} str(exc) patterns in security_connectors.py — "
            "these could leak auth tokens or internal URLs"
        )

    def test_uses_type_name_pattern(self):
        """security_connectors.py uses type(exc).__name__ for error reporting."""
        import inspect
        from core import security_connectors
        source = inspect.getsource(security_connectors)
        type_name_count = source.count("type(exc).__name__")
        assert type_name_count >= 20, (
            f"Expected at least 20 type(exc).__name__ patterns, found {type_name_count}"
        )


class TestConnectorsInfoDisclosure:
    """Verify connectors.py returns type(exc).__name__ not str(exc)."""

    def test_no_str_exc_in_connectors(self):
        """connectors.py must not use str(exc) in ConnectorOutcome error dicts."""
        import inspect
        from core import connectors
        source = inspect.getsource(connectors)
        matches = re.findall(r'"error":\s*str\(exc\)', source)
        assert len(matches) == 0, (
            f"Found {len(matches)} str(exc) patterns in connectors.py"
        )


class TestLLMProvidersInfoDisclosure:
    """Verify LLM providers don't leak API keys in error messages."""

    def test_no_str_exc_in_llm_providers(self):
        """llm_providers.py must not use str(exc) in metadata or reasoning."""
        import inspect
        from core import llm_providers
        source = inspect.getsource(llm_providers)
        # Check for str(exc) in error dicts
        str_exc_count = source.count("str(exc)")
        assert str_exc_count == 0, (
            f"Found {str_exc_count} str(exc) patterns in llm_providers.py — "
            "API keys could leak through exception messages"
        )

    def test_no_raw_exc_in_reasoning(self):
        """LLM reasoning field must not contain raw exception string."""
        import inspect
        from core import llm_providers
        source = inspect.getsource(llm_providers)
        # Should use type(exc).__name__ in fallback messages
        raw_exc_patterns = re.findall(r'fallback:\s*\{exc\}', source)
        assert len(raw_exc_patterns) == 0, (
            f"Found {len(raw_exc_patterns)} raw {{exc}} in reasoning strings"
        )


class TestCVETesterInfoDisclosure:
    """Verify cve_tester.py doesn't leak sensitive info in evidence."""

    def test_no_str_e_in_evidence(self):
        """cve_tester.py must not use str(e) in evidence dicts."""
        import inspect
        from core import cve_tester
        source = inspect.getsource(cve_tester)
        matches = re.findall(r'"error":\s*str\(e\)', source)
        assert len(matches) == 0, (
            f"Found {len(matches)} str(e) patterns in cve_tester.py — "
            "evidence dicts could leak file paths or connection strings"
        )


class TestScannerIngestInfoDisclosure:
    """Verify scanner_ingest_router.py doesn't leak in pipeline error responses."""

    def test_no_str_e_in_scanner_ingest(self):
        """scanner_ingest_router.py must not use str(e) in pipeline_result."""
        import inspect
        from apps.api import scanner_ingest_router
        source = inspect.getsource(scanner_ingest_router)
        matches = re.findall(r'"error":\s*str\(e\)', source)
        assert len(matches) == 0, (
            f"Found {len(matches)} str(e) patterns in scanner_ingest_router.py"
        )


class TestMiddlewareInfoDisclosure:
    """Verify middleware.py doesn't expose raw exceptions in logs."""

    def test_no_str_exc_in_middleware_logs(self):
        """middleware.py must not use str(exc) in log extra dicts."""
        import inspect
        from apps.api import middleware
        source = inspect.getsource(middleware)
        # Check for str(exc) in extra dict
        matches = re.findall(r'"error":\s*str\(exc\)', source)
        assert len(matches) == 0, (
            f"Found {len(matches)} str(exc) patterns in middleware.py log extras"
        )


class TestMPTEAdvancedInfoDisclosure:
    """Verify mpte_advanced.py doesn't leak LLM errors."""

    def test_no_str_error_in_metadata(self):
        """mpte_advanced.py must not use str(last_error) or str(e) in dicts."""
        import inspect
        from core import mpte_advanced
        source = inspect.getsource(mpte_advanced)
        str_last = re.findall(r'str\(last_error\)', source)
        str_e = re.findall(r'"error":\s*str\(e\)', source)
        total = len(str_last) + len(str_e)
        assert total == 0, (
            f"Found {len(str_last)} str(last_error) and {len(str_e)} str(e) "
            "patterns in mpte_advanced.py"
        )


# ============================================================================
# 4. pypdf CVE-2026-28804 Fix
# ============================================================================


class TestPypdfCVEFix:
    """Verify pypdf is updated past the vulnerable version."""

    def test_pypdf_version_not_vulnerable(self):
        """pypdf must be >= 6.7.5 (CVE-2026-28804 fix)."""
        try:
            import pypdf
            version = pypdf.__version__
            major, minor, patch = (int(x) for x in version.split(".")[:3])
            assert (major, minor, patch) >= (6, 7, 5), (
                f"pypdf {version} is vulnerable to CVE-2026-28804. "
                "Upgrade to >= 6.7.5"
            )
        except ImportError:
            pytest.skip("pypdf not installed")


# ============================================================================
# 5. f-string Logging Audit (High-Risk Files Only)
# ============================================================================


class TestFStringLoggingAudit:
    """Check that security-critical files don't use f-string logging with
    exception data that could leak secrets."""

    @pytest.mark.parametrize("module_path,module_name", [
        ("core.secrets_scanner", "secrets_scanner"),
        ("core.autofix_engine", "autofix_engine"),
        ("core.brain_pipeline", "brain_pipeline"),
    ])
    def test_no_fstring_logging_with_exception(self, module_path, module_name):
        """Security-critical engines must not log exceptions via f-strings.

        Pattern: logger.error(f"... {e}") or logger.error(f"... {exc}")
        These are pre-evaluated regardless of log level and could contain secrets.
        """
        mod = importlib.import_module(module_path)
        import inspect
        source = inspect.getsource(mod)
        # Look for f-string logging that includes exception variables
        # Pattern: logger.LEVEL(f"...{e}...") or logger.LEVEL(f"...{exc}...")
        dangerous_patterns = re.findall(
            r'logger\.\w+\(f"[^"]*\{(?:e|exc|err)\b[^}]*\}',
            source
        )
        assert len(dangerous_patterns) == 0, (
            f"Found {len(dangerous_patterns)} f-string logging with exception "
            f"variables in {module_name}: {dangerous_patterns[:3]}"
        )


# ============================================================================
# 6. Bandit Verification
# ============================================================================


class TestBanditClean:
    """Verify zero HIGH severity bandit findings."""

    def test_no_high_severity_bandit_findings(self):
        """Bandit scan must show 0 HIGH severity findings."""
        import subprocess
        result = subprocess.run(
            [
                sys.executable, "-m", "bandit",
                "-r", "suite-core/", "suite-api/", "suite-attack/",
                "--severity-level", "high",
                "-f", "txt",
                "--quiet",
            ],
            capture_output=True, text=True, timeout=120
        )
        # bandit returns 0 when no issues found at the given severity
        if result.stdout:
            lines = [ln for ln in result.stdout.strip().split("\n")
                     if ln.strip() and "No issues" not in ln and "Run started" not in ln
                     and "Code scanned" not in ln and "Total lines" not in ln
                     and "Run metrics" not in ln and "Total issues" not in ln
                     and "Total potential" not in ln and "Files skipped" not in ln]
            high_findings = [ln for ln in lines if "High" in ln and "Severity" in ln]
            assert len(high_findings) == 0, (
                "Found HIGH severity bandit findings:\n" +
                "\n".join(high_findings[:5])
            )
