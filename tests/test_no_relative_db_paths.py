"""Database paths must not depend on where the process was started.

A relative SQLite path resolves against the working directory, so the same logical store
lands in different files depending on how the process was launched — and neither copy
knows about the other. Measured in the running container on 2026-08-16: **49 database
names existed at two locations, 13 with genuinely diverged data**, including
deduplication clusters at 5,898 rows in one copy and 0 in the other, and TrustGraph at
250 against 38.

The ``parents[N]`` idiom is the same bug wearing a disguise. The correct depth differs
between ``suite-api/apps/api/x.py`` and ``suite-core/core/y.py``, so when the line is
copied between suites it silently lands somewhere else. Two routers used ``parents[4]``,
which overshoots the repo root onto ``/``, tried to create ``/.fixops_data``, and
returned HTTP 500 on every request until fixed on 2026-08-17.

ADR-006 anchors the data directory, but only for code that reads ``FIXOPS_DATA_DIR``.
Large amounts do not. These tests therefore do two different jobs:

* **Ratchet** the existing debt so it can only shrink (it is far too large to fix in one
  change, and a test that demands the impossible gets deleted rather than obeyed).
* **Reject outright** the one construct that is provably wrong rather than merely
  fragile: a ``parents[N]`` that escapes the repository root.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import List, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
SUITES = (
    "suite-api",
    "suite-core",
    "suite-attack",
    "suite-feeds",
    "suite-evidence-risk",
    "suite-integrations",
)

_RELATIVE_DB = re.compile(r"""["'](?:data|\.fixops_data|\.aldeci)/[^"']*\.db["']""")
_PARENTS = re.compile(r"\.parents\[\s*(\d+)\s*\]")

# Frozen at the counts measured 2026-08-17. Lower them as files migrate; never raise.
MAX_FILES_WITH_RELATIVE_DB_PATHS = 155
MAX_PARENTS_DERIVED_DATA_PATHS = 360


def _python_files() -> List[Path]:
    files: List[Path] = []
    for suite in SUITES:
        root = REPO_ROOT / suite
        if not root.is_dir():
            continue
        for path in root.rglob("*.py"):
            if set(path.parts) & {
                "node_modules",
                ".venv",
                "venv",
                "site-packages",
                "__pycache__",
            }:
                continue
            if "test" in path.name:
                continue
            files.append(path)
    return files


def _data_path_lines(path: Path) -> List[Tuple[int, str, int]]:
    """Lines where ``parents[N]`` is used to build a data path: (line, text, N)."""
    found: List[Tuple[int, str, int]] = []
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return found
    for number, line in enumerate(text.splitlines(), start=1):
        if line.strip().startswith("#"):
            continue  # a comment describing the bug is not the bug
        match = _PARENTS.search(line)
        if match and (".fixops_data" in line or ".db" in line or '"data"' in line):
            found.append((number, line.strip(), int(match.group(1))))
    return found


def test_relative_db_path_debt_does_not_grow() -> None:
    offenders = [
        path
        for path in _python_files()
        if _RELATIVE_DB.search(path.read_text(encoding="utf-8", errors="ignore"))
    ]
    assert len(offenders) <= MAX_FILES_WITH_RELATIVE_DB_PATHS, (
        f"{len(offenders)} files hardcode a relative *.db path, above the frozen "
        f"{MAX_FILES_WITH_RELATIVE_DB_PATHS}. A relative path resolves against the "
        "working directory and silently splits the store — resolve through "
        "FIXOPS_DATA_DIR instead."
    )


def test_parents_derived_data_path_debt_does_not_grow() -> None:
    total = sum(len(_data_path_lines(path)) for path in _python_files())
    assert total <= MAX_PARENTS_DERIVED_DATA_PATHS, (
        f"{total} data paths are derived by counting parent segments, above the frozen "
        f"{MAX_PARENTS_DERIVED_DATA_PATHS}. The correct depth differs per suite, so this "
        "line breaks when copied — resolve through FIXOPS_DATA_DIR instead."
    )


def test_no_parents_index_escapes_the_repository_root() -> None:
    """The provably-wrong case, not merely the fragile one.

    ``suite-api/apps/api/x.py`` is three levels below the root, so ``parents[3]`` is the
    root and ``parents[4]`` is *outside the repository* — in a container that is ``/``,
    which is unwritable. This is exactly what returned HTTP 500 from
    ``security_maturity`` and ``threat_correlation``.
    """
    escapes: List[str] = []
    for path in _python_files():
        depth = len(path.relative_to(REPO_ROOT).parts) - 1  # directories above the file
        for number, text, index in _data_path_lines(path):
            if index > depth:
                escapes.append(
                    f"  {path.relative_to(REPO_ROOT)}:{number} "
                    f"parents[{index}] escapes the repo (file is {depth} deep): {text[:70]}"
                )
    assert not escapes, "data paths resolve outside the repository:\n" + "\n".join(escapes[:10])


def test_a_file_does_not_use_two_different_depths_for_the_same_database() -> None:
    """Two depths for one database is a split store written down in one file.

    ``autofix_router.py`` reached ``data/analytics.db`` through both ``parents[3]`` and
    ``parents[2]`` — two files, one logical store, and whichever the caller hit decided
    what it saw.
    """
    conflicts: List[str] = []
    for path in _python_files():
        by_db: dict = {}
        for number, text, index in _data_path_lines(path):
            db = re.search(r'["\']([A-Za-z0-9_.-]+\.db)["\']', text)
            if not db:
                continue
            by_db.setdefault(db.group(1), set()).add(index)
        for name, depths in by_db.items():
            if len(depths) > 1:
                conflicts.append(
                    f"  {path.relative_to(REPO_ROOT)}: {name} reached via parents{sorted(depths)}"
                )
    assert not conflicts, (
        "the same database is resolved at two different depths in one file:\n"
        + "\n".join(conflicts[:10])
    )
