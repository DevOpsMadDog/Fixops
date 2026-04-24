"""Tests for IDE Backend Engine (NEW-G071).

Covers: tree build + excludes, violation annotation, content + sha256,
snapshot persist + replay, diff (added/removed/newly-flagged/unflagged),
org isolation, endpoint smoke. stdlib only.
"""
from __future__ import annotations

import hashlib
import os
import sqlite3
import tempfile
import uuid
from pathlib import Path
from typing import List, Tuple

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from core.ide_backend_engine import (
    IDEBackendEngine,
    _guess_language,
    _sha256_bytes,
    _severity_rank,
    _rank_to_severity,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mk_tmp_db(tmp_path: Path, name: str) -> str:
    return str(tmp_path / name)


def _seed_findings_db(db_path: str, rows: List[Tuple[str, str, str, str]]) -> None:
    """Seed security_findings DB with ``rows`` of (org_id, asset_id, severity, status)."""
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS security_findings (
            id                    TEXT PRIMARY KEY,
            org_id                TEXT NOT NULL,
            title                 TEXT NOT NULL DEFAULT '',
            finding_type          TEXT NOT NULL DEFAULT 'vulnerability',
            source_tool           TEXT NOT NULL DEFAULT 'custom',
            severity              TEXT NOT NULL DEFAULT 'medium',
            cvss_score            REAL NOT NULL DEFAULT 0.0,
            asset_id              TEXT NOT NULL DEFAULT '',
            asset_type            TEXT NOT NULL DEFAULT '',
            description           TEXT NOT NULL DEFAULT '',
            remediation           TEXT NOT NULL DEFAULT '',
            status                TEXT NOT NULL DEFAULT 'open',
            first_seen            TEXT NOT NULL DEFAULT '',
            last_seen             TEXT NOT NULL DEFAULT '',
            occurrence_count      INTEGER NOT NULL DEFAULT 1,
            assigned_to           TEXT NOT NULL DEFAULT '',
            created_at            TEXT NOT NULL DEFAULT '',
            correlation_key       TEXT NOT NULL DEFAULT '',
            scan_id               TEXT NOT NULL DEFAULT '',
            first_seen_at         TEXT NOT NULL DEFAULT '',
            previous_violation_id TEXT,
            resolved_at           TEXT,
            unchanged_scan_count  INTEGER NOT NULL DEFAULT 0
        );
        """
    )
    for (org_id, asset_id, severity, status) in rows:
        conn.execute(
            """INSERT INTO security_findings
               (id, org_id, asset_id, severity, status, scan_id, correlation_key,
                first_seen_at, created_at)
               VALUES (?, ?, ?, ?, ?, '', ?, '', '')""",
            (str(uuid.uuid4()), org_id, asset_id, severity, status, f"k-{asset_id}"),
        )
    conn.commit()
    conn.close()


def _seed_findings_db_with_scans(
    db_path: str,
    rows: List[Tuple[str, str, str, str, str]],
) -> None:
    """Seed findings DB with rows ``(org_id, asset_id, severity, status, scan_id)``."""
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS security_findings (
            id TEXT PRIMARY KEY, org_id TEXT NOT NULL,
            title TEXT NOT NULL DEFAULT '',
            finding_type TEXT NOT NULL DEFAULT 'vulnerability',
            source_tool TEXT NOT NULL DEFAULT 'custom',
            severity TEXT NOT NULL DEFAULT 'medium',
            cvss_score REAL NOT NULL DEFAULT 0.0,
            asset_id TEXT NOT NULL DEFAULT '',
            asset_type TEXT NOT NULL DEFAULT '',
            description TEXT NOT NULL DEFAULT '',
            remediation TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'open',
            first_seen TEXT NOT NULL DEFAULT '',
            last_seen TEXT NOT NULL DEFAULT '',
            occurrence_count INTEGER NOT NULL DEFAULT 1,
            assigned_to TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT '',
            correlation_key TEXT NOT NULL DEFAULT '',
            scan_id TEXT NOT NULL DEFAULT '',
            first_seen_at TEXT NOT NULL DEFAULT '',
            previous_violation_id TEXT, resolved_at TEXT,
            unchanged_scan_count INTEGER NOT NULL DEFAULT 0
        );
        """
    )
    for (org_id, asset_id, severity, status, scan_id) in rows:
        conn.execute(
            """INSERT INTO security_findings
               (id, org_id, asset_id, severity, status, scan_id, correlation_key,
                first_seen_at, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, '', '')""",
            (str(uuid.uuid4()), org_id, asset_id, severity, status, scan_id,
             f"k-{asset_id}-{scan_id}"),
        )
    conn.commit()
    conn.close()


def _build_repo(root: Path) -> None:
    """Create a small fixture repo.

      repo/
        README.md
        src/
          app.py
          util.py
        .git/
          objects/pack
        node_modules/
          lodash/index.js
    """
    (root / "src").mkdir(parents=True, exist_ok=True)
    (root / ".git" / "objects").mkdir(parents=True, exist_ok=True)
    (root / "node_modules" / "lodash").mkdir(parents=True, exist_ok=True)
    (root / "README.md").write_text("# Test Repo\n")
    (root / "src" / "app.py").write_text("def main():\n    pass\n")
    (root / "src" / "util.py").write_text("def helper():\n    return 42\n")
    (root / ".git" / "objects" / "pack").write_bytes(b"\x00binary")
    (root / "node_modules" / "lodash" / "index.js").write_text("module.exports = {};")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def engine(tmp_path: Path) -> IDEBackendEngine:
    db = _mk_tmp_db(tmp_path, "ide_backend_test.db")
    findings_db = _mk_tmp_db(tmp_path, "findings_test.db")
    return IDEBackendEngine(db_path=db, findings_db_path=findings_db)


@pytest.fixture()
def repo_root(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    _build_repo(root)
    return root


# ---------------------------------------------------------------------------
# Pure helpers (6 tests)
# ---------------------------------------------------------------------------


def test_sha256_bytes_known_value():
    assert _sha256_bytes(b"hello") == hashlib.sha256(b"hello").hexdigest()


def test_sha256_bytes_empty():
    assert _sha256_bytes(b"") == hashlib.sha256(b"").hexdigest()


def test_severity_rank_ordering():
    assert _severity_rank("critical") > _severity_rank("high")
    assert _severity_rank("high") > _severity_rank("medium")
    assert _severity_rank("medium") > _severity_rank("low")
    assert _severity_rank("low") > _severity_rank("informational")


def test_severity_rank_unknown_is_zero():
    assert _severity_rank("bogus") == 0
    assert _severity_rank("") == 0


def test_rank_roundtrip():
    for sev in ("critical", "high", "medium", "low", "informational"):
        assert _rank_to_severity(_severity_rank(sev)) == sev


def test_guess_language_common_extensions():
    assert _guess_language("x.py") == "python"
    assert _guess_language("x.ts") == "typescript"
    assert _guess_language("X.TSX") == "typescript"
    assert _guess_language("Dockerfile") == "dockerfile"
    assert _guess_language("no_ext") == "plaintext"


# ---------------------------------------------------------------------------
# Tree build (8 tests)
# ---------------------------------------------------------------------------


def test_build_repo_tree_returns_root(engine: IDEBackendEngine, repo_root: Path):
    result = engine.build_repo_tree("org-1", "repo/a", str(repo_root))
    assert result["org_id"] == "org-1"
    assert result["repo_ref"] == "repo/a"
    assert "id" in result and result["id"]
    assert result["tree"]["type"] == "dir"
    assert result["tree"]["path"] == ""


def test_build_repo_tree_excludes_git_and_node_modules(
    engine: IDEBackendEngine, repo_root: Path
):
    result = engine.build_repo_tree("org-1", "repo/a", str(repo_root))
    top_names = {child["name"] for child in result["tree"]["children"]}
    assert ".git" not in top_names
    assert "node_modules" not in top_names
    assert "src" in top_names
    assert "README.md" in top_names


def test_build_repo_tree_file_node_shape(engine: IDEBackendEngine, repo_root: Path):
    result = engine.build_repo_tree("org-1", "repo/a", str(repo_root))
    readme = next(
        c for c in result["tree"]["children"] if c["name"] == "README.md"
    )
    assert readme["type"] == "file"
    assert readme["path"] == "README.md"
    assert "violation_count" in readme
    assert "highest_severity" in readme
    assert readme["size_bytes"] > 0


def test_build_repo_tree_violation_annotation(
    engine: IDEBackendEngine, repo_root: Path
):
    _seed_findings_db(
        engine.findings_db_path,
        [
            ("org-1", "src/app.py", "critical", "open"),
            ("org-1", "src/app.py", "high", "open"),
            ("org-1", "src/util.py", "low", "open"),
        ],
    )
    result = engine.build_repo_tree("org-1", "repo/a", str(repo_root))
    src = next(c for c in result["tree"]["children"] if c["name"] == "src")
    files = {c["name"]: c for c in src["children"]}
    assert files["app.py"]["violation_count"] == 2
    assert files["app.py"]["highest_severity"] == "critical"
    assert files["util.py"]["violation_count"] == 1
    assert files["util.py"]["highest_severity"] == "low"


def test_build_repo_tree_resolved_findings_skipped(
    engine: IDEBackendEngine, repo_root: Path
):
    _seed_findings_db(
        engine.findings_db_path,
        [
            ("org-1", "src/app.py", "critical", "resolved"),
            ("org-1", "src/util.py", "high", "open"),
        ],
    )
    result = engine.build_repo_tree("org-1", "repo/a", str(repo_root))
    src = next(c for c in result["tree"]["children"] if c["name"] == "src")
    files = {c["name"]: c for c in src["children"]}
    assert files["app.py"]["violation_count"] == 0
    assert files["util.py"]["violation_count"] == 1


def test_build_repo_tree_bad_root_raises(engine: IDEBackendEngine):
    with pytest.raises(ValueError):
        engine.build_repo_tree("org-1", "repo/a", "/nonexistent/path/xyz")


def test_build_repo_tree_missing_org_raises(engine: IDEBackendEngine, repo_root: Path):
    with pytest.raises(ValueError):
        engine.build_repo_tree("", "repo/a", str(repo_root))


def test_get_repo_tree_returns_latest(engine: IDEBackendEngine, repo_root: Path):
    engine.build_repo_tree("org-1", "repo/a", str(repo_root), commit_sha="aaa")
    engine.build_repo_tree("org-1", "repo/a", str(repo_root), commit_sha="bbb")
    latest = engine.get_repo_tree("org-1", "repo/a")
    assert latest is not None
    assert latest["commit_sha"] == "bbb"
    assert latest["tree"]["type"] == "dir"


# ---------------------------------------------------------------------------
# File content (6 tests)
# ---------------------------------------------------------------------------


def test_get_file_content_from_disk(engine: IDEBackendEngine, repo_root: Path):
    out = engine.get_file_content(
        "org-1", "repo/a", "src/app.py", root_path=str(repo_root)
    )
    assert out["path"] == "src/app.py"
    assert "def main" in out["content"]
    assert out["source"] == "disk"
    assert out["size_bytes"] > 0
    expected = _sha256_bytes((repo_root / "src" / "app.py").read_bytes())
    assert out["sha256"] == expected
    assert out["language"] == "python"


def test_get_file_content_path_traversal_rejected(
    engine: IDEBackendEngine, repo_root: Path
):
    with pytest.raises(ValueError):
        engine.get_file_content(
            "org-1", "repo/a", "../etc/passwd", root_path=str(repo_root)
        )


def test_get_file_content_missing_file_raises(
    engine: IDEBackendEngine, repo_root: Path
):
    with pytest.raises(FileNotFoundError):
        engine.get_file_content(
            "org-1", "repo/a", "does/not/exist.py", root_path=str(repo_root)
        )


def test_get_file_content_write_through_cache(
    engine: IDEBackendEngine, repo_root: Path
):
    engine.get_file_content(
        "org-1", "repo/a", "src/app.py",
        root_path=str(repo_root), write_through_cache=True,
    )
    # Now remove disk file and read from cache.
    cached = engine.get_file_content(
        "org-1", "repo/a", "src/app.py", root_path=None
    )
    assert cached["source"] == "cache"
    assert "def main" in cached["content"]


def test_get_file_content_empty_path_raises(engine: IDEBackendEngine):
    with pytest.raises(ValueError):
        engine.get_file_content("org-1", "repo/a", "")


def test_get_file_content_normalises_backslashes(
    engine: IDEBackendEngine, repo_root: Path
):
    out = engine.get_file_content(
        "org-1", "repo/a", "src\\app.py", root_path=str(repo_root)
    )
    assert out["path"] == "src/app.py"


# ---------------------------------------------------------------------------
# Snapshots (5 tests)
# ---------------------------------------------------------------------------


def test_snapshot_persists_counts(engine: IDEBackendEngine):
    _seed_findings_db_with_scans(
        engine.findings_db_path,
        [
            ("org-1", "src/a.py", "critical", "open", "scan-1"),
            ("org-1", "src/a.py", "high", "open", "scan-1"),
            ("org-1", "src/b.py", "low", "open", "scan-1"),
        ],
    )
    snap = engine.snapshot_analysis("org-1", "repo/a", "scan-1")
    assert snap["total_violations"] == 3
    assert snap["total_files"] == 2
    assert snap["violation_counts_by_path"]["src/a.py"] == 2
    assert snap["violation_counts_by_path"]["src/b.py"] == 1
    assert snap["highest_severity"] == "critical"


def test_list_analysis_snapshots_newest_first(engine: IDEBackendEngine):
    _seed_findings_db_with_scans(
        engine.findings_db_path,
        [("org-1", "src/a.py", "high", "open", "scan-1")],
    )
    s1 = engine.snapshot_analysis("org-1", "repo/a", "scan-1")
    s2 = engine.snapshot_analysis("org-1", "repo/a", "scan-1")
    rows = engine.list_analysis_snapshots("org-1", "repo/a")
    assert len(rows) == 2
    assert rows[0]["id"] in (s1["id"], s2["id"])
    # newest first — second snapshot should be at index 0 by monotonic time
    assert rows[0]["snapshot_at"] >= rows[1]["snapshot_at"]


def test_replay_snapshot_shape(engine: IDEBackendEngine, repo_root: Path):
    _seed_findings_db_with_scans(
        engine.findings_db_path,
        [("org-1", "src/app.py", "critical", "open", "scan-1")],
    )
    engine.build_repo_tree("org-1", "repo/a", str(repo_root))
    snap = engine.snapshot_analysis("org-1", "repo/a", "scan-1")
    replay = engine.replay_snapshot(snap["id"])
    assert replay["snapshot_id"] == snap["id"]
    assert replay["tree"]["type"] == "dir"
    # Verify the replayed tree's app.py now carries the snapshot count.
    src = next(c for c in replay["tree"]["children"] if c["name"] == "src")
    app_py = next(c for c in src["children"] if c["name"] == "app.py")
    assert app_py["violation_count"] == 1
    # Dir aggregate roll-up.
    assert src["violation_count"] >= 1


def test_replay_snapshot_missing_id_raises(engine: IDEBackendEngine):
    with pytest.raises(LookupError):
        engine.replay_snapshot("no-such-snapshot")


def test_snapshot_missing_org_raises(engine: IDEBackendEngine):
    with pytest.raises(ValueError):
        engine.snapshot_analysis("", "repo/a", "scan-1")


# ---------------------------------------------------------------------------
# Diff (5 tests)
# ---------------------------------------------------------------------------


def test_diff_detects_newly_flagged_and_unflagged(engine: IDEBackendEngine):
    # Snapshot A: only b.py has violations.
    _seed_findings_db_with_scans(
        engine.findings_db_path,
        [("org-1", "src/b.py", "medium", "open", "scan-a")],
    )
    snap_a = engine.snapshot_analysis("org-1", "repo/a", "scan-a")

    # Reset findings DB for snapshot B: only a.py has violations.
    os.remove(engine.findings_db_path)
    _seed_findings_db_with_scans(
        engine.findings_db_path,
        [("org-1", "src/a.py", "high", "open", "scan-b")],
    )
    snap_b = engine.snapshot_analysis("org-1", "repo/a", "scan-b")

    diff = engine.diff_snapshots(snap_a["id"], snap_b["id"])
    assert "src/a.py" in diff["files_added"]
    assert "src/b.py" in diff["files_removed"]
    assert diff["violation_delta"]["src/a.py"] == 1
    assert diff["violation_delta"]["src/b.py"] == -1
    assert diff["total_delta"] == 0  # 1 removed, 1 added


def test_diff_total_delta(engine: IDEBackendEngine):
    _seed_findings_db_with_scans(
        engine.findings_db_path,
        [("org-1", "src/a.py", "high", "open", "scan-a")],
    )
    snap_a = engine.snapshot_analysis("org-1", "repo/a", "scan-a")
    os.remove(engine.findings_db_path)
    _seed_findings_db_with_scans(
        engine.findings_db_path,
        [
            ("org-1", "src/a.py", "high", "open", "scan-b"),
            ("org-1", "src/a.py", "critical", "open", "scan-b"),
            ("org-1", "src/c.py", "low", "open", "scan-b"),
        ],
    )
    snap_b = engine.snapshot_analysis("org-1", "repo/a", "scan-b")
    diff = engine.diff_snapshots(snap_a["id"], snap_b["id"])
    assert diff["total_delta"] == 2  # 1 -> 3
    assert "src/c.py" in diff["files_added"]


def test_diff_empty_both_sides(engine: IDEBackendEngine):
    snap_a = engine.snapshot_analysis("org-1", "repo/a", "scan-a")
    snap_b = engine.snapshot_analysis("org-1", "repo/a", "scan-b")
    diff = engine.diff_snapshots(snap_a["id"], snap_b["id"])
    assert diff["files_added"] == []
    assert diff["files_removed"] == []
    assert diff["files_newly_flagged"] == []
    assert diff["files_unflagged"] == []
    assert diff["total_delta"] == 0


def test_diff_missing_snapshot_raises(engine: IDEBackendEngine):
    _seed_findings_db_with_scans(
        engine.findings_db_path,
        [("org-1", "src/a.py", "high", "open", "scan-a")],
    )
    snap = engine.snapshot_analysis("org-1", "repo/a", "scan-a")
    with pytest.raises(LookupError):
        engine.diff_snapshots(snap["id"], "no-such-id")
    with pytest.raises(LookupError):
        engine.diff_snapshots("no-such-id", snap["id"])


def test_diff_cross_org_rejected(engine: IDEBackendEngine):
    _seed_findings_db_with_scans(
        engine.findings_db_path,
        [
            ("org-1", "src/a.py", "high", "open", "scan-1"),
            ("org-2", "src/b.py", "high", "open", "scan-2"),
        ],
    )
    snap1 = engine.snapshot_analysis("org-1", "repo/a", "scan-1")
    snap2 = engine.snapshot_analysis("org-2", "repo/a", "scan-2")
    with pytest.raises(ValueError):
        engine.diff_snapshots(snap1["id"], snap2["id"])


# ---------------------------------------------------------------------------
# Isolation + stats (3 tests)
# ---------------------------------------------------------------------------


def test_org_isolation_get_tree(engine: IDEBackendEngine, repo_root: Path):
    engine.build_repo_tree("org-1", "repo/a", str(repo_root))
    assert engine.get_repo_tree("org-1", "repo/a") is not None
    assert engine.get_repo_tree("org-2", "repo/a") is None


def test_org_isolation_list_snapshots(engine: IDEBackendEngine):
    _seed_findings_db_with_scans(
        engine.findings_db_path,
        [("org-1", "src/a.py", "high", "open", "scan-1")],
    )
    engine.snapshot_analysis("org-1", "repo/a", "scan-1")
    assert len(engine.list_analysis_snapshots("org-1", "repo/a")) == 1
    assert engine.list_analysis_snapshots("org-2", "repo/a") == []


def test_stats(engine: IDEBackendEngine, repo_root: Path):
    _seed_findings_db_with_scans(
        engine.findings_db_path,
        [("org-1", "src/a.py", "high", "open", "scan-1")],
    )
    engine.build_repo_tree("org-1", "repo/a", str(repo_root))
    engine.snapshot_analysis("org-1", "repo/a", "scan-1")
    s = engine.stats("org-1")
    assert s["org_id"] == "org-1"
    assert s["total_repo_trees"] == 1
    assert s["distinct_repos"] == 1
    assert s["total_snapshots"] == 1
    assert s["latest_snapshot_at"] is not None


# ---------------------------------------------------------------------------
# Endpoint smoke (2 tests — stdlib-compatible FastAPI in-process testing)
# ---------------------------------------------------------------------------


def _build_app(engine: IDEBackendEngine) -> FastAPI:
    """Mount the router with a patched auth dep (bypass) and engine singleton."""
    import apps.api.ide_backend_router as r

    # Bypass auth.
    app = FastAPI()
    r._engine = engine  # inject test engine singleton
    app.dependency_overrides[r.api_key_auth] = lambda: None
    app.include_router(r.router)
    return app


def test_endpoint_health_and_stats(engine: IDEBackendEngine):
    client = TestClient(_build_app(engine))
    r = client.get("/api/v1/ide/health")
    assert r.status_code == 200
    assert r.json()["engine"] == "ide_backend"
    r2 = client.get("/api/v1/ide/status")
    assert r2.status_code == 200
    s = client.get("/api/v1/ide/stats", params={"org_id": "org-1"})
    assert s.status_code == 200
    assert s.json()["org_id"] == "org-1"


def test_endpoint_build_and_diff(engine: IDEBackendEngine, repo_root: Path):
    client = TestClient(_build_app(engine))
    # Build tree
    r = client.post(
        "/api/v1/ide/tree/build",
        json={"org_id": "org-1", "repo_ref": "repo/a", "root_path": str(repo_root)},
    )
    assert r.status_code == 200, r.text

    # Get tree
    r = client.get(
        "/api/v1/ide/tree", params={"org_id": "org-1", "repo_ref": "repo/a"}
    )
    assert r.status_code == 200
    assert r.json()["tree"]["type"] == "dir"

    # Seed findings + snapshot A
    _seed_findings_db_with_scans(
        engine.findings_db_path,
        [("org-1", "src/app.py", "high", "open", "scan-a")],
    )
    r = client.post(
        "/api/v1/ide/snapshot",
        json={"org_id": "org-1", "repo_ref": "repo/a", "scan_id": "scan-a"},
    )
    assert r.status_code == 200
    snap_a_id = r.json()["id"]

    # Swap findings and snapshot B
    os.remove(engine.findings_db_path)
    _seed_findings_db_with_scans(
        engine.findings_db_path,
        [
            ("org-1", "src/app.py", "high", "open", "scan-b"),
            ("org-1", "src/util.py", "low", "open", "scan-b"),
        ],
    )
    r = client.post(
        "/api/v1/ide/snapshot",
        json={"org_id": "org-1", "repo_ref": "repo/a", "scan_id": "scan-b"},
    )
    assert r.status_code == 200
    snap_b_id = r.json()["id"]

    # Diff
    r = client.post(
        "/api/v1/ide/snapshots/diff",
        json={"snapshot_id_a": snap_a_id, "snapshot_id_b": snap_b_id},
    )
    assert r.status_code == 200
    body = r.json()
    assert "src/util.py" in body["files_added"]
    assert body["total_delta"] == 1

    # Replay
    r = client.get(f"/api/v1/ide/snapshots/{snap_b_id}/replay")
    assert r.status_code == 200
    assert r.json()["total_violations"] == 2

    # List
    r = client.get(
        "/api/v1/ide/snapshots",
        params={"org_id": "org-1", "repo_ref": "repo/a"},
    )
    assert r.status_code == 200
    assert r.json()["count"] >= 2

    # 404 on missing tree
    r = client.get(
        "/api/v1/ide/tree", params={"org_id": "org-x", "repo_ref": "ghost"}
    )
    assert r.status_code == 404
