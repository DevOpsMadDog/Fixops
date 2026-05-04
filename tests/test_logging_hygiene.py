"""Logging hygiene tests.

Asserts that the patched hot-path files:
  - contain no bare `print(` calls outside __main__ blocks
  - contain no eager f-string logger calls: logger.*(f"...") or logger.*(f'...')
  - declare a structlog logger (structlog.get_logger)

Files covered (the 4 files touched in this hardening pass):
  suite-core/core/iac_scanner.py
  suite-core/core/mpte_advanced.py
  suite-core/core/security_connectors.py
  suite-core/core/self_learning.py
"""
from __future__ import annotations

import ast
import re
import textwrap
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent

PATCHED_FILES = [
    REPO_ROOT / "suite-core/core/iac_scanner.py",
    REPO_ROOT / "suite-core/core/mpte_advanced.py",
    REPO_ROOT / "suite-core/core/security_connectors.py",
    REPO_ROOT / "suite-core/core/self_learning.py",
]

# Regex: logger.{method}(f"..." or f'...')
_EAGER_FSTRING_RE = re.compile(
    r"""logger\s*\.\s*(?:info|warning|error|debug|critical)\s*\(\s*f['"]"""
)

# Regex: bare print( at start of a line (ignoring indentation)
_PRINT_RE = re.compile(r"""^[ \t]*print\s*\(""", re.MULTILINE)


def _strip_main_block(source: str) -> str:
    """Remove everything inside `if __name__ == "__main__":` blocks."""
    lines = source.splitlines(keepends=True)
    out: list[str] = []
    in_main = False
    main_indent: int | None = None

    for line in lines:
        stripped = line.lstrip()
        indent = len(line) - len(stripped)

        if re.match(r"""if\s+__name__\s*==\s*['"]__main__['"]\s*:""", stripped):
            in_main = True
            main_indent = indent
            # keep the guard line itself blank so line numbers stay stable
            out.append("\n")
            continue

        if in_main:
            # exit main block when we see a non-empty line at same or lower indent
            if stripped and indent <= (main_indent or 0):
                in_main = False
            else:
                out.append("\n")
                continue

        out.append(line)

    return "".join(out)


@pytest.mark.parametrize("fpath", PATCHED_FILES, ids=[f.name for f in PATCHED_FILES])
def test_no_print_outside_main(fpath: Path) -> None:
    source = fpath.read_text()
    source_no_main = _strip_main_block(source)
    matches = _PRINT_RE.findall(source_no_main)
    assert not matches, (
        f"{fpath.name}: found {len(matches)} bare print() call(s) outside __main__ block. "
        "Replace with structlog logger calls."
    )


@pytest.mark.parametrize("fpath", PATCHED_FILES, ids=[f.name for f in PATCHED_FILES])
def test_no_eager_fstring_logger(fpath: Path) -> None:
    source = fpath.read_text()
    matches = _EAGER_FSTRING_RE.findall(source)
    assert not matches, (
        f"{fpath.name}: found {len(matches)} eager f-string logger call(s). "
        "Use keyword args: logger.info('event', key=value) instead of logger.info(f'...')."
    )


@pytest.mark.parametrize("fpath", PATCHED_FILES, ids=[f.name for f in PATCHED_FILES])
def test_uses_structlog(fpath: Path) -> None:
    source = fpath.read_text()
    assert "structlog.get_logger" in source, (
        f"{fpath.name}: missing structlog.get_logger declaration. "
        "Add `import structlog` and `logger = structlog.get_logger(__name__)`."
    )
