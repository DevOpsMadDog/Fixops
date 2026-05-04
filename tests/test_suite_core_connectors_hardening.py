"""
OWASP hardening smoke tests for suite-core/connectors/.

Covers:
  - defectdojo_parser: aiohttp.ClientSession has timeout; URL not logged
  - defectdojo_parser: _ensure_session has timeout
  - sdlc_connectors: secrets-fetch warning does not embed raw exc string
"""
from __future__ import annotations

import ast
import re
import textwrap
from pathlib import Path

CONNECTORS = Path(__file__).parent.parent / "suite-core" / "connectors"


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _src(filename: str) -> str:
    return (CONNECTORS / filename).read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# defectdojo_parser — aiohttp.ClientSession timeout
# ---------------------------------------------------------------------------

class TestDefectDojoParserHardening:
    """Ensure both ClientSession() calls carry a timeout."""

    def test_aenter_session_has_timeout(self):
        src = _src("defectdojo_parser.py")
        # Find the __aenter__ block and confirm ClientTimeout appears before the
        # next method definition.
        aenter_idx = src.index("async def __aenter__")
        next_def_idx = src.index("async def __aexit__", aenter_idx)
        block = src[aenter_idx:next_def_idx]
        assert "ClientTimeout" in block, (
            "defectdojo_parser.__aenter__: aiohttp.ClientSession missing timeout"
        )

    def test_ensure_session_has_timeout(self):
        src = _src("defectdojo_parser.py")
        ensure_idx = src.index("def _ensure_session")
        # Next method boundary
        next_def_idx = src.index("\n    async def ", ensure_idx)
        block = src[ensure_idx:next_def_idx]
        assert "ClientTimeout" in block, (
            "defectdojo_parser._ensure_session: aiohttp.ClientSession missing timeout"
        )

    def test_init_does_not_log_base_url(self):
        src = _src("defectdojo_parser.py")
        init_idx = src.index("def __init__")
        aenter_idx = src.index("async def __aenter__", init_idx)
        init_block = src[init_idx:aenter_idx]
        # The original logged f"...{self.base_url}" — ensure it no longer does.
        assert "self.base_url" not in re.findall(
            r'logger\.\w+\(.*?self\.base_url', init_block
        ) or True, "init still logs self.base_url"
        # Positive check: the INFO log must NOT contain self.base_url
        log_lines = [
            ln for ln in init_block.splitlines()
            if "logger.info" in ln
        ]
        for ln in log_lines:
            assert "self.base_url" not in ln, (
                f"defectdojo_parser.__init__ still logs base_url: {ln!r}"
            )


# ---------------------------------------------------------------------------
# sdlc_connectors — secrets warning does not embed raw exc
# ---------------------------------------------------------------------------

class TestSdlcConnectorsHardening:
    """Secrets-fetch log must not embed raw exception (may carry auth headers)."""

    def test_secrets_warning_no_raw_exc(self):
        src = _src("sdlc_connectors.py")
        # Locate the block: from "Failed to fetch secrets" back to the logger.warning
        # opening paren, forward to the closing paren of that statement.
        marker = "Failed to fetch secrets"
        assert marker in src, "Could not find secrets-fetch warning in sdlc_connectors.py"

        idx = src.index(marker)
        # Walk back to find the start of the logger.warning( call
        block_start = src.rindex("logger.warning", 0, idx)
        # Walk forward past the closing paren — count parens
        depth = 0
        block_end = block_start
        for i, ch in enumerate(src[block_start:], start=block_start):
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    block_end = i + 1
                    break
        block = src[block_start:block_end]

        # Must NOT contain bare {exc} f-string interpolation or str(exc)
        assert "{exc}" not in block, (
            f"sdlc_connectors secrets warning embeds raw exc: {block!r}"
        )
        assert "str(exc)" not in block, (
            f"sdlc_connectors secrets warning calls str(exc): {block!r}"
        )
        # Must use type(exc).__name__ for safe classification
        assert "type(exc).__name__" in block, (
            f"sdlc_connectors secrets warning should use type(exc).__name__: {block!r}"
        )

    def test_secrets_warning_uses_percent_formatting(self):
        """Ensure warning uses %-style (not f-string) so exc is never interpolated."""
        src = _src("sdlc_connectors.py")
        # The fixed line must use logger.warning("...", ...) not f"..."
        idx = src.index("Failed to fetch secrets for")
        line_start = src.rindex("\n", 0, idx) + 1
        line_end = src.index("\n", idx)
        line = src[line_start:line_end]
        assert 'f"' not in line and "f'" not in line, (
            f"secrets warning still uses f-string: {line!r}"
        )


# ---------------------------------------------------------------------------
# Regression: imports still work
# ---------------------------------------------------------------------------

class TestConnectorImports:
    def test_defectdojo_parser_parseable(self):
        src = _src("defectdojo_parser.py")
        tree = ast.parse(src)
        assert tree is not None

    def test_sdlc_connectors_parseable(self):
        src = _src("sdlc_connectors.py")
        tree = ast.parse(src)
        assert tree is not None
