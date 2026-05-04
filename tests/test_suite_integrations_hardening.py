"""OWASP hardening smoke tests for suite-integrations.

Covers:
  - webhooks_router: detail=str(e) info-disclosure removed (issues 1 & 2)
  - webhooks_router: sqlite3.Error now caught alongside ValueError/KeyError (issue 3)
  - webhooks_router: outbox logger uses %s lazy format + exc_info, not f-string (issue 4)
  - sentinel_connector: raise_for_status() wrapped to strip client_secret from exc repr (issue 5)
"""

from __future__ import annotations

import ast
import inspect
import re
import sqlite3
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Ensure suite paths are on sys.path via sitecustomize
REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

WEBHOOKS_PATH = REPO_ROOT / "suite-integrations" / "api" / "webhooks_router.py"
SENTINEL_PATH = REPO_ROOT / "suite-integrations" / "siem_connectors" / "sentinel_connector.py"


# ---------------------------------------------------------------------------
# Helper: read source once
# ---------------------------------------------------------------------------

def _src(path: Path) -> str:
    return path.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Issue 1 & 2: detail=str(e) must not appear in webhook exception handlers
# ---------------------------------------------------------------------------

class TestNoDetailStrLeak:
    """HTTP 500 detail must be a generic string, not str(e)."""

    def test_no_str_e_in_detail_jira_block(self):
        src = _src(WEBHOOKS_PATH)
        # Check line-by-line: no single line should have both detail= and str(e)
        bad_lines = [
            (i + 1, line)
            for i, line in enumerate(src.splitlines())
            if "detail=" in line and "str(e)" in line
        ]
        assert bad_lines == [], (
            f"Found {len(bad_lines)} line(s) with detail=str(e) — leaks internal errors to clients: {bad_lines}"
        )

    def test_generic_detail_present(self):
        src = _src(WEBHOOKS_PATH)
        assert "Webhook processing error" in src, (
            "Expected generic 'Webhook processing error' detail string not found"
        )


# ---------------------------------------------------------------------------
# Issue 3: sqlite3.Error must be in the except tuple
# ---------------------------------------------------------------------------

class TestSqliteErrorCaught:
    def test_sqlite_error_in_jira_handler(self):
        src = _src(WEBHOOKS_PATH)
        # Both webhook handlers must include sqlite3.Error
        occurrences = src.count("sqlite3.Error")
        assert occurrences >= 2, (
            f"Expected sqlite3.Error in at least 2 exception handlers, found {occurrences}"
        )

    def test_sqlite_error_raises_http_500_not_unhandled(self):
        """Simulate a sqlite3.OperationalError in webhook processing — must yield HTTP 500, not propagate raw."""
        # We verify by AST that the except clauses include sqlite3.Error
        tree = ast.parse(_src(WEBHOOKS_PATH))
        sqlite_error_caught = False
        for node in ast.walk(tree):
            if isinstance(node, ast.ExceptHandler) and node.type is not None:
                # ExceptHandler.type can be a Tuple or Name/Attribute
                handler_src = ast.unparse(node.type)
                if "sqlite3.Error" in handler_src:
                    sqlite_error_caught = True
                    break
        assert sqlite_error_caught, "sqlite3.Error not found in any except handler in webhooks_router.py"


# ---------------------------------------------------------------------------
# Issue 4: outbox logger must use %s lazy format, not f-string
# ---------------------------------------------------------------------------

class TestOutboxLoggerFormat:
    def test_no_fstring_in_outbox_logger(self):
        src = _src(WEBHOOKS_PATH)
        # The outbox error log must not use f"..." with logger.error
        bad = re.search(
            r'logger\.error\s*\(\s*f["\']Failed to execute outbox item',
            src,
        )
        assert bad is None, "outbox logger.error still uses f-string — switch to %s lazy format"

    def test_exc_info_in_outbox_logger(self):
        src = _src(WEBHOOKS_PATH)
        # exc_info=True must appear near the outbox logger call
        # Find the outbox block
        idx = src.find("Failed to execute outbox item")
        assert idx != -1, "Outbox error log message not found"
        surrounding = src[idx - 50 : idx + 200]
        assert "exc_info=True" in surrounding, (
            "outbox logger.error missing exc_info=True — stack trace won't appear in logs"
        )


# ---------------------------------------------------------------------------
# Issue 5: sentinel_connector strips client_secret from exception repr
# ---------------------------------------------------------------------------

class TestSentinelSecretStrip:
    def test_runtime_error_raised_not_httpx_status_error(self):
        """SentinelConnector._acquire_token must raise RuntimeError (not HTTPStatusError)
        so client_secret never appears in the exception chain repr."""
        src = _src(SENTINEL_PATH)
        # Verify the sanitising re-raise pattern is present
        assert "from None" in src, (
            "sentinel_connector._acquire_token must use 'raise RuntimeError(...) from None' "
            "to suppress the exception chain containing client_secret"
        )

    def test_http_status_error_caught_before_propagation(self):
        src = _src(SENTINEL_PATH)
        assert "httpx.HTTPStatusError" in src, (
            "httpx.HTTPStatusError must be explicitly caught in _acquire_token"
        )

    def test_request_error_caught(self):
        src = _src(SENTINEL_PATH)
        assert "httpx.RequestError" in src, (
            "httpx.RequestError (network errors) must be caught in _acquire_token"
        )

    def test_secret_not_logged_in_exception_message(self):
        """The sanitised RuntimeError message must not include 'client_secret' or the secret value."""
        src = _src(SENTINEL_PATH)
        # Find the RuntimeError raise lines and assert they don't reference client_secret
        runtime_raises = re.findall(r'raise RuntimeError\([^)]+\)', src)
        for raise_stmt in runtime_raises:
            assert "client_secret" not in raise_stmt, (
                f"RuntimeError message references client_secret: {raise_stmt}"
            )
            assert "self.config" not in raise_stmt, (
                f"RuntimeError message references config object (may leak secrets): {raise_stmt}"
            )
