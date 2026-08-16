"""Guards against the duplicate-store class of bug.

Measured in the running container on 2026-08-16: 49 database *names* existed at
two different filesystem locations and 13 of those pairs held genuinely diverged
data — deduplication clusters at 5,898 rows in one copy and 0 in the other,
TrustGraph at 250 vs 38, CVE enrichment at 100 vs 0.

The mechanism is always the same: an engine binds a *relative* SQLite path at
import time, so the store lands next to whatever directory the process happened
to start in. Start the API from the repo root and a script from ``suite-api/``
and you now have two databases, one of which is invisible to the running app.

These tests pin the two fixes that close it:

1. ``FIXOPS_DATA_DIR`` is anchored to an absolute path before any engine imports.
2. Local databases never enter the Docker build context, so a customer's image
   cannot ship a developer's data.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_data_dir_is_absolute_after_app_import() -> None:
    """Importing the API must leave FIXOPS_DATA_DIR absolute.

    Run in a subprocess with the variable unset so the test observes the real
    default rather than whatever the developer's shell exports.
    """
    env = {k: v for k, v in os.environ.items() if k != "FIXOPS_DATA_DIR"}
    env["PYTHONPATH"] = os.pathsep.join(
        str(REPO_ROOT / p)
        for p in (
            "suite-api",
            "suite-core",
            "suite-attack",
            "suite-feeds",
            "suite-evidence-risk",
            "suite-integrations",
        )
    ) + os.pathsep + str(REPO_ROOT)

    result = subprocess.run(
        [
            "python3",
            "-c",
            "import apps.api.app, os; print(os.environ.get('FIXOPS_DATA_DIR', ''))",
        ],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=600,
    )
    assert result.returncode == 0, f"importing the app failed:\n{result.stderr[-3000:]}"

    value = result.stdout.strip().splitlines()[-1] if result.stdout.strip() else ""
    assert value, "FIXOPS_DATA_DIR was not set at import time"
    assert os.path.isabs(value), (
        f"FIXOPS_DATA_DIR is relative ({value!r}); the store location would depend "
        "on the launch directory and split across two files"
    )


def test_data_dir_anchor_is_independent_of_launch_directory() -> None:
    """The anchor must resolve identically from the repo root and a subdirectory.

    This is the exact condition that produced the diverged stores: the same code
    started from two directories must still agree on where the data lives.
    """
    env = {k: v for k, v in os.environ.items() if k != "FIXOPS_DATA_DIR"}
    env["PYTHONPATH"] = str(REPO_ROOT)
    snippet = "import sitecustomize, os; print(os.environ.get('FIXOPS_DATA_DIR',''))"

    seen = {}
    for cwd in (REPO_ROOT, REPO_ROOT / "suite-api"):
        result = subprocess.run(
            ["python3", "-c", snippet],
            cwd=cwd,
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert result.returncode == 0, result.stderr[-2000:]
        seen[str(cwd)] = result.stdout.strip()

    values = set(seen.values())
    assert len(values) == 1, f"data dir depends on the launch directory: {seen}"
    assert os.path.isabs(next(iter(values))), f"anchor is not absolute: {seen}"


def _dockerignore_patterns() -> list[str]:
    text = (REPO_ROOT / ".dockerignore").read_text(encoding="utf-8")
    return [
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


def test_dockerignore_excludes_local_databases_recursively() -> None:
    """No SQLite file may enter the image via the build context.

    ``COPY suite-*/ ./suite-*/`` copies whole directories, so a developer's local
    databases are swept in unless excluded. Measured 2026-08-16: 53 stale *.db files
    totalling ~80 MB, holding 1,425 dedup clusters and 3,047 events from our own
    dogfooding runs, were present in the built image.

    The pattern must be recursive. ``.dockerignore`` matches with Go's
    ``filepath.Match``, where ``*`` does not cross a path separator, so a bare ``*.db``
    excludes only databases at the context root. An earlier version of this test
    asserted exactly that and passed while the rebuilt image still carried 11 databases
    and ~80 MB — every one of them in a subdirectory.
    """
    patterns = _dockerignore_patterns()
    for suffix in ("db", "db-wal", "db-shm"):
        recursive = f"**/*.{suffix}"
        assert recursive in patterns, (
            f".dockerignore is missing {recursive!r}. A bare '*.{suffix}' only matches "
            "the context root, so databases in subdirectories still ship."
        )


def test_dockerignore_does_not_reinclude_databases() -> None:
    """A negation must never re-admit databases after the exclusion.

    The previous version carried ``!data/`` and ``!data/**`` under a comment about
    an 'enterprise seeded image', which re-included every local store.
    """
    offenders = [
        p
        for p in _dockerignore_patterns()
        if p.startswith("!") and re.search(r"(^!data/|\.db|\.sqlite)", p)
    ]
    # Reference policy bundles are legitimate reference data, not tenant data.
    offenders = [p for p in offenders if "policies" not in p]
    assert not offenders, (
        f"re-inclusion patterns would bake local databases into the image: {offenders}"
    )


@pytest.mark.skipif(
    not (REPO_ROOT / ".git").exists(), reason="not a git checkout"
)
def test_no_databases_tracked_in_git() -> None:
    """Databases must never be committed — they are runtime state, not source."""
    result = subprocess.run(
        ["git", "ls-files", "*.db", "*.sqlite", "*.sqlite3"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=120,
    )
    tracked = [line for line in result.stdout.split() if line]
    assert not tracked, f"database files are tracked in git: {tracked[:10]}"
