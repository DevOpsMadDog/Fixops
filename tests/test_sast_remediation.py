"""Regression tests for SAST remediation — 2026-04-27.

Covers:
  1. SHA1 -> SHA256 fix in wave_a_code_intel_router.py
  2. SQL injection fix in llm_loop_metrics_router.py (_safe_count / _last_created)
  3. PGP "key" in secrets_manager.py is a detection regex, not a real key
"""
from __future__ import annotations

import ast
import inspect
import re
import sqlite3
import textwrap
from pathlib import Path
from typing import Optional

import pytest

ROOT = Path(__file__).parent.parent

# ---------------------------------------------------------------------------
# 1. SHA1 fix — wave_a_code_intel_router.py
# ---------------------------------------------------------------------------

class TestSha1Remediation:
    """Bandit B324 — SHA1 must not be used for any hashing in wave_a router."""

    def _load_source(self) -> str:
        return (ROOT / "suite-api/apps/api/wave_a_code_intel_router.py").read_text()

    def test_no_sha1_call(self):
        """hashlib.sha1 must not appear anywhere in the module source."""
        src = self._load_source()
        # Allow the string only inside comments / nosec annotations — reject bare calls.
        for lineno, line in enumerate(src.splitlines(), 1):
            stripped = line.strip()
            if "hashlib.sha1" in stripped and not stripped.startswith("#"):
                # It could be in a string literal that is a doc/comment — check AST
                # For safety we fail if sha1( appears in non-comment code.
                pytest.fail(
                    f"hashlib.sha1 found at line {lineno} in wave_a_code_intel_router.py: {line!r}"
                )

    def test_sha256_present(self):
        """hashlib.sha256 must be used as the replacement."""
        src = self._load_source()
        assert "hashlib.sha256" in src, (
            "Expected hashlib.sha256 dedup hash in wave_a_code_intel_router.py"
        )


# ---------------------------------------------------------------------------
# 2. SQL injection fix — llm_loop_metrics_router.py
# ---------------------------------------------------------------------------

class TestSqlInjectionRemediation:
    """Semgrep sqlalchemy-execute-raw-query — table name must be validated."""

    def _load_source(self) -> str:
        return (ROOT / "suite-api/apps/api/llm_loop_metrics_router.py").read_text()

    def test_allowed_tables_defined_in_source(self):
        """Source must define _ALLOWED_TABLES with the two known tables."""
        src = self._load_source()
        assert "_ALLOWED_TABLES" in src, "_ALLOWED_TABLES allowlist not found in source"
        assert "council_verdicts" in src
        assert "feedback_pairs" in src

    def test_validate_table_function_present(self):
        """_validate_table guard function must exist in source."""
        src = self._load_source()
        assert "def _validate_table(" in src, "_validate_table function not found"

    def test_validate_table_raises_on_disallowed(self):
        """_validate_table must raise ValueError for unknown tables."""
        # Extract and exec only the guard function (no FastAPI dependency)
        src = self._load_source()
        # Build a minimal namespace with _ALLOWED_TABLES and _validate_table
        ns: dict = {}
        # Parse out the allowlist line and the function
        lines = src.splitlines()
        code_lines = []
        in_func = False
        for line in lines:
            if "_ALLOWED_TABLES = frozenset" in line:
                code_lines.append(line)
            elif line.startswith("def _validate_table("):
                in_func = True
                code_lines.append(line)
            elif in_func:
                if line and not line[0].isspace() and not line.startswith(" "):
                    break
                code_lines.append(line)
        exec("\n".join(code_lines), ns)  # noqa: S102 — controlled test exec of extracted pure function
        _validate_table = ns["_validate_table"]

        with pytest.raises(ValueError, match="disallowed"):
            _validate_table("users; DROP TABLE users--")

        with pytest.raises(ValueError, match="disallowed"):
            _validate_table("../../etc/passwd")

        # Valid tables must pass through
        assert _validate_table("council_verdicts") == "council_verdicts"
        assert _validate_table("feedback_pairs") == "feedback_pairs"

    def test_safe_count_injection_blocked_via_sqlite(self):
        """Simulate _safe_count with allowlist: injection payload must return 0 without executing."""
        # Inline the patched logic — no FastAPI import needed
        _ALLOWED_TABLES = frozenset({"council_verdicts", "feedback_pairs"})

        def _validate_table(table: str) -> str:
            if table not in _ALLOWED_TABLES:
                raise ValueError(f"disallowed table: {table!r}")
            return table

        def _safe_count(conn: sqlite3.Connection, table: str) -> int:
            try:
                t = _validate_table(table)
                row = conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()  # nosec B608
                return int(row[0]) if row else 0
            except (sqlite3.Error, ValueError):
                return 0

        conn = sqlite3.connect(":memory:")
        conn.execute("CREATE TABLE council_verdicts (id INTEGER PRIMARY KEY)")
        conn.execute("CREATE TABLE victim (secret TEXT)")
        conn.execute("INSERT INTO victim VALUES ('top_secret')")
        conn.commit()

        result = _safe_count(conn, "victim; DROP TABLE victim--")
        assert result == 0, f"Expected 0 for disallowed table, got {result}"

        # Victim table must still exist
        rows = conn.execute("SELECT * FROM victim").fetchall()
        assert len(rows) == 1, "victim table was dropped — SQL injection succeeded!"

        # Valid table works
        conn.execute("INSERT INTO council_verdicts VALUES (1)")
        conn.commit()
        assert _safe_count(conn, "council_verdicts") == 1
        conn.close()


# ---------------------------------------------------------------------------
# 3. PGP "key" verdict — secrets_manager.py
# ---------------------------------------------------------------------------

class TestPgpKeyVerdict:
    """Confirm the PGP entry is a detection regex, not a real embedded key."""

    def _load_source(self) -> str:
        return (ROOT / "suite-core/core/secrets_manager.py").read_text()

    def test_no_real_pgp_block(self):
        """Source must not contain an actual PGP private key block (multi-line armored)."""
        src = self._load_source()
        # A real PGP key block has the header AND footer AND base64 body on subsequent lines.
        # A detection regex only has the header as a string pattern inside r"..." quotes.
        real_key_pattern = re.compile(
            r"-----BEGIN PGP PRIVATE KEY BLOCK-----\r?\n"  # header then newline
            r"[A-Za-z0-9+/=\r\n]{40,}",                   # actual base64 body
            re.MULTILINE,
        )
        assert not real_key_pattern.search(src), (
            "A real PGP private key block was found in secrets_manager.py — ROTATE immediately!"
        )

    def test_pgp_entry_is_detection_pattern(self):
        """The PGP entry must be a regex string, not an actual key."""
        src = self._load_source()
        # The pattern value should be a raw string containing only the header marker
        assert r'r"-----BEGIN PGP PRIVATE KEY BLOCK-----"' in src or \
               "r\"-----BEGIN PGP PRIVATE KEY BLOCK-----\"" in src, (
            "PGP detection pattern not found as expected regex string"
        )

    def test_nosec_annotation_present(self):
        """The PGP pattern line must carry a nosec annotation."""
        src = self._load_source()
        for line in src.splitlines():
            if "BEGIN PGP PRIVATE KEY BLOCK" in line:
                assert "nosec" in line, (
                    f"Missing # nosec annotation on PGP pattern line: {line!r}"
                )
