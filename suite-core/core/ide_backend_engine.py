"""IDE Backend Engine — ALDECI (NEW-G071).

Server-side APIs that an in-browser IDE-style UI calls. Pairs with GAP-066
diff-mode and GAP-063 violation lifecycle.

Capabilities
  - File tree (annotated with per-file violation counts pulled from
    ``security_findings`` via direct SQL join on ``asset_id`` / path).
  - Code content retrieval (from disk + optional write-through cache).
  - Analysis snapshot history (time-travel over scan state).
  - Snapshot replay (returns tree-with-counts as-of a snapshot).
  - Snapshot diff (per-file delta between two snapshots).

Storage: SQLite with WAL + RLock + org_id isolation.
DB path: ``.fixops_data/ide_backend_engine.db``

Security: org_id is enforced on every read/write. No cross-tenant bleed.
Stdlib only — no third-party deps.
"""
from __future__ import annotations

# ---------------------------------------------------------------------------
# TrustGraph second-brain wiring
# ---------------------------------------------------------------------------
try:  # pragma: no cover - optional dependency
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except Exception:  # noqa: BLE001
    _get_tg_bus = None  # type: ignore[assignment]


def _emit_event(event_type: str, payload: dict) -> None:
    """Emit to TrustGraph event bus. Never raises."""
    if _get_tg_bus is None:
        return
    try:
        bus = _get_tg_bus()
        if bus is None:
            return
        emit = getattr(bus, "emit", None) or getattr(bus, "publish", None)
        if emit is None:
            return
        result = emit(event_type, payload)
        try:
            import asyncio as _aio
            import inspect as _insp
            if _insp.iscoroutine(result):
                try:
                    loop = _aio.get_running_loop()
                    loop.create_task(result)
                except RuntimeError:
                    result.close()
        except Exception:  # pragma: no cover
            pass
    except Exception:  # pragma: no cover
        pass


try:  # pragma: no cover
    _emit_event("engine.loaded", {"module": __name__})
except Exception:  # noqa: BLE001
    pass

import hashlib
import json
import logging
import os
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "ide_backend_engine.db"
)

# Findings DB — joined via direct SQL ATTACH for annotations.
_FINDINGS_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "security_findings_engine.db"
)

# Directories that are always skipped when walking a repo tree.
_EXCLUDED_DIRS: Set[str] = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".idea",
    ".vscode",
    "dist",
    "build",
    ".next",
    ".turbo",
    "target",
}

# Max bytes to return for a single file via ``get_file_content``.
_MAX_CONTENT_BYTES = 2 * 1024 * 1024  # 2 MiB safety cap

# Language guess from extension (best-effort; front-end may override).
_LANG_BY_EXT: Dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".java": "java",
    ".go": "go",
    ".rb": "ruby",
    ".rs": "rust",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".hpp": "cpp",
    ".cs": "csharp",
    ".kt": "kotlin",
    ".swift": "swift",
    ".php": "php",
    ".scala": "scala",
    ".sh": "shell",
    ".bash": "shell",
    ".zsh": "shell",
    ".sql": "sql",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".json": "json",
    ".toml": "toml",
    ".ini": "ini",
    ".xml": "xml",
    ".html": "html",
    ".css": "css",
    ".scss": "scss",
    ".md": "markdown",
    ".tf": "terraform",
    ".dockerfile": "dockerfile",
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _guess_language(file_path: str) -> str:
    name = os.path.basename(file_path).lower()
    if name == "dockerfile":
        return "dockerfile"
    if name == "makefile":
        return "makefile"
    _, ext = os.path.splitext(name)
    return _LANG_BY_EXT.get(ext, "plaintext")


def _severity_rank(sev: str) -> int:
    return {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "low": 1,
        "informational": 0,
    }.get((sev or "").lower(), 0)


def _rank_to_severity(rank: int) -> str:
    return {
        4: "critical",
        3: "high",
        2: "medium",
        1: "low",
        0: "informational",
    }.get(rank, "informational")


class IDEBackendEngine:
    """Backend for an in-browser IDE-style UI.

    Thread-safe via RLock; multi-tenant via org_id. Writes go through
    SQLite with WAL journaling. Findings DB is read-only (ATTACHed or
    queried with a second connection) — this engine never mutates
    ``security_findings``.
    """

    def __init__(
        self,
        db_path: str = _DEFAULT_DB,
        findings_db_path: str = _FINDINGS_DB,
    ) -> None:
        self.db_path = db_path
        self.findings_db_path = findings_db_path
        self._lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS repo_trees (
                    id          TEXT PRIMARY KEY,
                    org_id      TEXT NOT NULL,
                    repo_ref    TEXT NOT NULL,
                    commit_sha  TEXT NOT NULL DEFAULT '',
                    tree_json   TEXT NOT NULL DEFAULT '{}',
                    built_at    TEXT NOT NULL DEFAULT ''
                );

                CREATE INDEX IF NOT EXISTS idx_ide_tree_org
                    ON repo_trees (org_id, repo_ref, built_at DESC);

                CREATE TABLE IF NOT EXISTS analysis_snapshots (
                    id                              TEXT PRIMARY KEY,
                    org_id                          TEXT NOT NULL,
                    repo_ref                        TEXT NOT NULL,
                    scan_id                         TEXT NOT NULL DEFAULT '',
                    snapshot_at                     TEXT NOT NULL DEFAULT '',
                    violation_counts_by_path_json   TEXT NOT NULL DEFAULT '{}',
                    total_violations                INTEGER NOT NULL DEFAULT 0,
                    total_files                     INTEGER NOT NULL DEFAULT 0,
                    highest_severity                TEXT NOT NULL DEFAULT 'informational'
                );

                CREATE INDEX IF NOT EXISTS idx_ide_snap_org
                    ON analysis_snapshots (org_id, repo_ref, snapshot_at DESC);

                CREATE TABLE IF NOT EXISTS code_content_cache (
                    id             TEXT PRIMARY KEY,
                    org_id         TEXT NOT NULL,
                    repo_ref       TEXT NOT NULL,
                    file_path      TEXT NOT NULL,
                    content_hash   TEXT NOT NULL,
                    content_bytes  BLOB NOT NULL,
                    cached_at      TEXT NOT NULL DEFAULT '',
                    UNIQUE (org_id, repo_ref, file_path, content_hash)
                );

                CREATE INDEX IF NOT EXISTS idx_ide_cache_lookup
                    ON code_content_cache (org_id, repo_ref, file_path);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    def _findings_conn(self) -> Optional[sqlite3.Connection]:
        """Open a read-only connection to the security_findings DB.

        Returns ``None`` if the DB does not yet exist (fresh install,
        no scans ran yet). Callers must treat ``None`` as "no violations".
        """
        if not os.path.isfile(self.findings_db_path):
            return None
        try:
            conn = sqlite3.connect(self.findings_db_path, timeout=10)
            conn.row_factory = sqlite3.Row
            return conn
        except sqlite3.Error as exc:
            _logger.warning("ide_backend: findings DB open failed: %s", exc)
            return None

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    # ------------------------------------------------------------------
    # Violation lookups (joined against security_findings)
    # ------------------------------------------------------------------

    def _load_violations_by_path(
        self,
        org_id: str,
        scan_id: Optional[str] = None,
    ) -> Tuple[Dict[str, Dict[str, Any]], str]:
        """Return ``{path: {count, highest_severity}}`` and overall highest severity.

        File path is stored in ``asset_id`` of ``security_findings`` when the
        asset_type is ``file``/``code``. We accept both and are forgiving —
        any asset_id that is a non-empty string is bucketed by that string.

        Only rows with ``status`` in open/in-progress count toward annotations.
        """
        result: Dict[str, Dict[str, Any]] = {}
        overall_rank = 0

        conn = self._findings_conn()
        if conn is None:
            return result, _rank_to_severity(overall_rank)
        try:
            if scan_id:
                rows = conn.execute(
                    """SELECT asset_id, severity FROM security_findings
                       WHERE org_id = ?
                         AND scan_id = ?
                         AND status IN ('open', 'in-progress')
                         AND asset_id != ''""",
                    (org_id, scan_id),
                ).fetchall()
            else:
                rows = conn.execute(
                    """SELECT asset_id, severity FROM security_findings
                       WHERE org_id = ?
                         AND status IN ('open', 'in-progress')
                         AND asset_id != ''""",
                    (org_id,),
                ).fetchall()
        except sqlite3.Error as exc:
            _logger.warning("ide_backend: findings query failed: %s", exc)
            conn.close()
            return result, _rank_to_severity(overall_rank)
        finally:
            try:
                conn.close()
            except sqlite3.Error:
                pass

        for r in rows:
            path = r["asset_id"] or ""
            if not path:
                continue
            sev = r["severity"] or "informational"
            rank = _severity_rank(sev)
            if rank > overall_rank:
                overall_rank = rank
            bucket = result.get(path)
            if bucket is None:
                result[path] = {
                    "count": 1,
                    "highest_severity_rank": rank,
                    "highest_severity": sev,
                }
            else:
                bucket["count"] += 1
                if rank > bucket["highest_severity_rank"]:
                    bucket["highest_severity_rank"] = rank
                    bucket["highest_severity"] = sev

        return result, _rank_to_severity(overall_rank)

    # ------------------------------------------------------------------
    # Tree build / read
    # ------------------------------------------------------------------

    def _walk_tree(
        self,
        root_path: str,
        relative_to: str,
        violations_by_path: Dict[str, Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Recursive filesystem walk. Returns nested dict.

        Each directory node: ``{name, path, type: 'dir', children: [...]}``.
        Each file node: ``{name, path, type: 'file', size_bytes,
        violation_count, highest_severity}``.

        Symlinks are followed only when they resolve inside ``relative_to``
        (defence-in-depth against symlink escape).
        """
        basename = os.path.basename(root_path.rstrip(os.sep)) or root_path
        rel = os.path.relpath(root_path, relative_to).replace(os.sep, "/")
        if rel == ".":
            rel = ""

        if os.path.isdir(root_path):
            node: Dict[str, Any] = {
                "name": basename,
                "path": rel,
                "type": "dir",
                "children": [],
            }
            try:
                entries = sorted(os.listdir(root_path))
            except OSError as exc:
                _logger.warning("ide_backend: listdir failed for %s: %s", root_path, exc)
                return node
            for entry in entries:
                if entry in _EXCLUDED_DIRS:
                    continue
                if entry.startswith(".") and entry in _EXCLUDED_DIRS:
                    continue
                child_path = os.path.join(root_path, entry)
                # Symlink containment: skip if resolves outside root.
                if os.path.islink(child_path):
                    try:
                        real = os.path.realpath(child_path)
                        root_real = os.path.realpath(relative_to)
                        if not (real == root_real or real.startswith(root_real + os.sep)):
                            continue
                    except OSError:
                        continue
                try:
                    child = self._walk_tree(child_path, relative_to, violations_by_path)
                except OSError as exc:
                    _logger.warning("ide_backend: walk failed for %s: %s", child_path, exc)
                    continue
                if child:
                    node["children"].append(child)
            return node

        # File node
        try:
            size = os.path.getsize(root_path)
        except OSError:
            size = 0
        viol = violations_by_path.get(rel, {})
        return {
            "name": basename,
            "path": rel,
            "type": "file",
            "size_bytes": size,
            "violation_count": int(viol.get("count", 0)),
            "highest_severity": viol.get("highest_severity", "informational"),
        }

    def build_repo_tree(
        self,
        org_id: str,
        repo_ref: str,
        root_path: str,
        commit_sha: str = "",
    ) -> Dict[str, Any]:
        """Walk ``root_path`` and persist annotated tree.

        ``violation_count`` per file comes from ``security_findings``
        (open + in-progress) keyed by ``asset_id == file path relative to root``.
        """
        if not org_id:
            raise ValueError("org_id is required")
        if not repo_ref:
            raise ValueError("repo_ref is required")
        if not root_path or not os.path.isdir(root_path):
            raise ValueError(f"root_path does not exist or is not a directory: {root_path}")

        violations, _highest = self._load_violations_by_path(org_id)

        abs_root = os.path.abspath(root_path)
        tree = self._walk_tree(abs_root, abs_root, violations)
        # The top-level node represents the repo root — normalise path to "".
        tree["path"] = ""
        now = _now_iso()
        tree_json = json.dumps(tree, separators=(",", ":"))

        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "repo_ref": repo_ref,
            "commit_sha": commit_sha or "",
            "tree_json": tree_json,
            "built_at": now,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO repo_trees
                       (id, org_id, repo_ref, commit_sha, tree_json, built_at)
                       VALUES (:id, :org_id, :repo_ref, :commit_sha, :tree_json, :built_at)""",
                    record,
                )

        _emit_event("ide_backend_engine.repo_tree_built", {
            "id": record["id"],
            "org_id": org_id,
            "repo_ref": repo_ref,
            "commit_sha": commit_sha,
        })
        return {
            "id": record["id"],
            "org_id": org_id,
            "repo_ref": repo_ref,
            "commit_sha": commit_sha,
            "built_at": now,
            "tree": tree,
        }

    def get_repo_tree(
        self,
        org_id: str,
        repo_ref: str,
    ) -> Optional[Dict[str, Any]]:
        """Return the most recently built tree for this (org, repo)."""
        with self._conn() as conn:
            row = conn.execute(
                """SELECT * FROM repo_trees
                   WHERE org_id = ? AND repo_ref = ?
                   ORDER BY built_at DESC
                   LIMIT 1""",
                (org_id, repo_ref),
            ).fetchone()
        if not row:
            return None
        record = self._row(row)
        try:
            record["tree"] = json.loads(record.pop("tree_json") or "{}")
        except json.JSONDecodeError:
            record["tree"] = {}
        return record

    # ------------------------------------------------------------------
    # File content
    # ------------------------------------------------------------------

    def get_file_content(
        self,
        org_id: str,
        repo_ref: str,
        file_path: str,
        root_path: Optional[str] = None,
        write_through_cache: bool = False,
    ) -> Dict[str, Any]:
        """Read file content from disk (preferred) or cache.

        When ``root_path`` is provided the file is read from
        ``root_path/file_path`` (with path-traversal containment enforced).
        Otherwise we try the latest cache entry for (org, repo, path).

        Returns ``{path, content, sha256, size_bytes, language, source}``.
        ``source`` is either ``disk`` or ``cache``.
        """
        if not org_id:
            raise ValueError("org_id is required")
        if not repo_ref:
            raise ValueError("repo_ref is required")
        if not file_path:
            raise ValueError("file_path is required")

        # Normalise and protect against path traversal.
        normalised = file_path.replace("\\", "/").lstrip("/")
        if ".." in normalised.split("/"):
            raise ValueError("file_path must not contain '..' segments")

        # 1) Prefer disk read.
        if root_path and os.path.isdir(root_path):
            abs_root = os.path.abspath(root_path)
            candidate = os.path.abspath(os.path.join(abs_root, normalised))
            if not (candidate == abs_root or candidate.startswith(abs_root + os.sep)):
                raise ValueError("file_path resolves outside root_path")
            if os.path.isfile(candidate):
                try:
                    size = os.path.getsize(candidate)
                    if size > _MAX_CONTENT_BYTES:
                        with open(candidate, "rb") as fh:
                            raw = fh.read(_MAX_CONTENT_BYTES)
                    else:
                        with open(candidate, "rb") as fh:
                            raw = fh.read()
                except OSError as exc:
                    raise RuntimeError(f"read failed: {exc}") from exc

                sha = _sha256_bytes(raw)
                try:
                    content = raw.decode("utf-8")
                except UnicodeDecodeError:
                    content = raw.decode("utf-8", errors="replace")

                if write_through_cache:
                    self._cache_write_through(org_id, repo_ref, normalised, sha, raw)

                return {
                    "path": normalised,
                    "content": content,
                    "sha256": sha,
                    "size_bytes": len(raw),
                    "language": _guess_language(normalised),
                    "source": "disk",
                }

        # 2) Fall back to cache.
        with self._conn() as conn:
            row = conn.execute(
                """SELECT content_bytes, content_hash FROM code_content_cache
                   WHERE org_id = ? AND repo_ref = ? AND file_path = ?
                   ORDER BY cached_at DESC
                   LIMIT 1""",
                (org_id, repo_ref, normalised),
            ).fetchone()
        if row is None:
            raise FileNotFoundError(
                f"file not found on disk or in cache: org_id={org_id} "
                f"repo_ref={repo_ref} path={normalised}"
            )
        raw = row["content_bytes"] or b""
        sha = row["content_hash"] or _sha256_bytes(raw)
        try:
            content = raw.decode("utf-8")
        except (UnicodeDecodeError, AttributeError):
            content = str(raw)
        return {
            "path": normalised,
            "content": content,
            "sha256": sha,
            "size_bytes": len(raw) if isinstance(raw, (bytes, bytearray)) else len(content),
            "language": _guess_language(normalised),
            "source": "cache",
        }

    def _cache_write_through(
        self,
        org_id: str,
        repo_ref: str,
        file_path: str,
        sha: str,
        raw: bytes,
    ) -> None:
        """Best-effort write-through cache. UNIQUE prevents dup rows for same hash."""
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "repo_ref": repo_ref,
            "file_path": file_path,
            "content_hash": sha,
            "content_bytes": raw,
            "cached_at": _now_iso(),
        }
        try:
            with self._lock:
                with self._conn() as conn:
                    conn.execute(
                        """INSERT OR IGNORE INTO code_content_cache
                           (id, org_id, repo_ref, file_path, content_hash,
                            content_bytes, cached_at)
                           VALUES (:id, :org_id, :repo_ref, :file_path,
                                   :content_hash, :content_bytes, :cached_at)""",
                        record,
                    )
        except sqlite3.Error as exc:
            _logger.warning("ide_backend: cache write-through failed: %s", exc)

    # ------------------------------------------------------------------
    # Analysis snapshots
    # ------------------------------------------------------------------

    def list_analysis_snapshots(
        self,
        org_id: str,
        repo_ref: str,
        limit: int = 20,
    ) -> List[Dict[str, Any]]:
        """List snapshots newest-first (metadata only — no full counts map)."""
        if limit <= 0:
            limit = 20
        limit = min(limit, 200)
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT id, org_id, repo_ref, scan_id, snapshot_at,
                          total_violations, total_files, highest_severity
                   FROM analysis_snapshots
                   WHERE org_id = ? AND repo_ref = ?
                   ORDER BY snapshot_at DESC
                   LIMIT ?""",
                (org_id, repo_ref, limit),
            ).fetchall()
        return [self._row(r) for r in rows]

    def snapshot_analysis(
        self,
        org_id: str,
        repo_ref: str,
        scan_id: str,
    ) -> Dict[str, Any]:
        """Capture the current findings state for (org, repo, scan) as a snapshot.

        ``violation_counts_by_path`` is a dict keyed by file path. We also
        persist a rough file count (distinct paths) and the org-wide highest
        severity in this snapshot.
        """
        if not org_id:
            raise ValueError("org_id is required")
        if not repo_ref:
            raise ValueError("repo_ref is required")
        scan_id_val = (scan_id or "").strip()

        violations, _ignored = self._load_violations_by_path(
            org_id, scan_id=scan_id_val or None
        )

        counts_by_path: Dict[str, int] = {
            path: int(info.get("count", 0)) for path, info in violations.items()
        }
        total_violations = sum(counts_by_path.values())
        total_files = len(counts_by_path)
        highest_rank = 0
        for info in violations.values():
            rank = int(info.get("highest_severity_rank", 0))
            if rank > highest_rank:
                highest_rank = rank
        highest_severity = _rank_to_severity(highest_rank)

        now = _now_iso()
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "repo_ref": repo_ref,
            "scan_id": scan_id_val,
            "snapshot_at": now,
            "violation_counts_by_path_json": json.dumps(counts_by_path, separators=(",", ":")),
            "total_violations": total_violations,
            "total_files": total_files,
            "highest_severity": highest_severity,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO analysis_snapshots
                       (id, org_id, repo_ref, scan_id, snapshot_at,
                        violation_counts_by_path_json, total_violations,
                        total_files, highest_severity)
                       VALUES (:id, :org_id, :repo_ref, :scan_id, :snapshot_at,
                               :violation_counts_by_path_json, :total_violations,
                               :total_files, :highest_severity)""",
                    record,
                )

        _emit_event("ide_backend_engine.snapshot_taken", {
            "id": record["id"],
            "org_id": org_id,
            "repo_ref": repo_ref,
            "scan_id": scan_id_val,
            "total_violations": total_violations,
            "total_files": total_files,
            "highest_severity": highest_severity,
        })
        # Return without the raw JSON blob — include parsed counts_by_path.
        return {
            "id": record["id"],
            "org_id": org_id,
            "repo_ref": repo_ref,
            "scan_id": scan_id_val,
            "snapshot_at": now,
            "violation_counts_by_path": counts_by_path,
            "total_violations": total_violations,
            "total_files": total_files,
            "highest_severity": highest_severity,
        }

    def _get_snapshot(
        self,
        snapshot_id: str,
        org_id: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Fetch raw snapshot row (with JSON parsed). Org-scoped if provided."""
        with self._conn() as conn:
            if org_id:
                row = conn.execute(
                    "SELECT * FROM analysis_snapshots WHERE id = ? AND org_id = ?",
                    (snapshot_id, org_id),
                ).fetchone()
            else:
                row = conn.execute(
                    "SELECT * FROM analysis_snapshots WHERE id = ?",
                    (snapshot_id,),
                ).fetchone()
        if not row:
            return None
        record = self._row(row)
        try:
            record["violation_counts_by_path"] = json.loads(
                record.pop("violation_counts_by_path_json") or "{}"
            )
        except json.JSONDecodeError:
            record["violation_counts_by_path"] = {}
        return record

    def _annotate_tree_with_counts(
        self,
        tree_node: Dict[str, Any],
        counts_by_path: Dict[str, int],
    ) -> int:
        """Mutates ``tree_node`` in place, setting ``violation_count`` on files.

        Directories receive an aggregated count computed from descendants.
        Returns the subtree total for the caller's convenience.
        """
        if not isinstance(tree_node, dict):
            return 0
        node_type = tree_node.get("type")
        if node_type == "file":
            path = tree_node.get("path", "")
            count = int(counts_by_path.get(path, 0))
            tree_node["violation_count"] = count
            return count
        # dir (or unknown container)
        total = 0
        for child in tree_node.get("children", []) or []:
            total += self._annotate_tree_with_counts(child, counts_by_path)
        tree_node["violation_count"] = total
        return total

    def replay_snapshot(self, snapshot_id: str) -> Dict[str, Any]:
        """Return the annotated repo tree as-of a snapshot.

        Uses the latest stored tree for this (org, repo_ref) but overlays
        the snapshot's per-path violation counts instead of the live ones.
        """
        snap = self._get_snapshot(snapshot_id)
        if not snap:
            raise LookupError(f"snapshot not found: {snapshot_id}")

        tree_record = self.get_repo_tree(snap["org_id"], snap["repo_ref"])
        tree: Dict[str, Any]
        if tree_record and isinstance(tree_record.get("tree"), dict):
            # Deep copy via JSON round-trip so the stored tree is not mutated.
            tree = json.loads(json.dumps(tree_record["tree"]))
        else:
            tree = {"name": snap["repo_ref"], "path": "", "type": "dir", "children": []}

        counts = snap.get("violation_counts_by_path", {}) or {}
        self._annotate_tree_with_counts(tree, counts)

        return {
            "snapshot_id": snap["id"],
            "org_id": snap["org_id"],
            "repo_ref": snap["repo_ref"],
            "scan_id": snap.get("scan_id", ""),
            "snapshot_at": snap["snapshot_at"],
            "total_violations": snap["total_violations"],
            "total_files": snap["total_files"],
            "highest_severity": snap["highest_severity"],
            "tree": tree,
        }

    def diff_snapshots(
        self,
        snapshot_id_a: str,
        snapshot_id_b: str,
    ) -> Dict[str, Any]:
        """Diff two snapshots. Returns per-file delta and aggregate.

        ``A`` is the baseline, ``B`` is the later state.

        Result keys:
          - ``files_added``          — paths present in B only (at least 1 violation)
          - ``files_removed``        — paths present in A only
          - ``files_newly_flagged``  — paths in both, A=0 violations, B>0
          - ``files_unflagged``      — paths in both, A>0 violations, B=0
          - ``violation_delta``      — {path: b_count - a_count} for paths with change
          - ``total_delta``          — B.total - A.total
        """
        snap_a = self._get_snapshot(snapshot_id_a)
        if not snap_a:
            raise LookupError(f"snapshot A not found: {snapshot_id_a}")
        snap_b = self._get_snapshot(snapshot_id_b)
        if not snap_b:
            raise LookupError(f"snapshot B not found: {snapshot_id_b}")
        if snap_a["org_id"] != snap_b["org_id"]:
            raise ValueError("snapshots belong to different orgs")

        counts_a: Dict[str, int] = snap_a.get("violation_counts_by_path", {}) or {}
        counts_b: Dict[str, int] = snap_b.get("violation_counts_by_path", {}) or {}

        all_paths: Set[str] = set(counts_a.keys()) | set(counts_b.keys())

        files_added: List[str] = []
        files_removed: List[str] = []
        files_newly_flagged: List[str] = []
        files_unflagged: List[str] = []
        violation_delta: Dict[str, int] = {}

        for path in all_paths:
            a = int(counts_a.get(path, 0))
            b = int(counts_b.get(path, 0))

            in_a = path in counts_a
            in_b = path in counts_b

            if in_b and not in_a:
                if b > 0:
                    files_added.append(path)
            elif in_a and not in_b:
                if a > 0:
                    files_removed.append(path)
            else:
                if a == 0 and b > 0:
                    files_newly_flagged.append(path)
                elif a > 0 and b == 0:
                    files_unflagged.append(path)

            if b != a:
                violation_delta[path] = b - a

        files_added.sort()
        files_removed.sort()
        files_newly_flagged.sort()
        files_unflagged.sort()

        total_delta = int(snap_b["total_violations"]) - int(snap_a["total_violations"])

        return {
            "org_id": snap_a["org_id"],
            "repo_ref_a": snap_a["repo_ref"],
            "repo_ref_b": snap_b["repo_ref"],
            "snapshot_id_a": snap_a["id"],
            "snapshot_id_b": snap_b["id"],
            "snapshot_at_a": snap_a["snapshot_at"],
            "snapshot_at_b": snap_b["snapshot_at"],
            "files_added": files_added,
            "files_removed": files_removed,
            "files_newly_flagged": files_newly_flagged,
            "files_unflagged": files_unflagged,
            "violation_delta": violation_delta,
            "total_delta": total_delta,
        }

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def stats(self, org_id: str) -> Dict[str, Any]:
        """Return engine-wide stats for an org."""
        with self._conn() as conn:
            trees_row = conn.execute(
                "SELECT COUNT(*) AS cnt FROM repo_trees WHERE org_id = ?",
                (org_id,),
            ).fetchone()
            snap_row = conn.execute(
                "SELECT COUNT(*) AS cnt FROM analysis_snapshots WHERE org_id = ?",
                (org_id,),
            ).fetchone()
            cache_row = conn.execute(
                "SELECT COUNT(*) AS cnt FROM code_content_cache WHERE org_id = ?",
                (org_id,),
            ).fetchone()
            distinct_repos_row = conn.execute(
                """SELECT COUNT(DISTINCT repo_ref) AS cnt
                   FROM repo_trees WHERE org_id = ?""",
                (org_id,),
            ).fetchone()
            total_violations_row = conn.execute(
                """SELECT COALESCE(SUM(total_violations), 0) AS s
                   FROM analysis_snapshots WHERE org_id = ?""",
                (org_id,),
            ).fetchone()
            latest_row = conn.execute(
                """SELECT snapshot_at FROM analysis_snapshots
                   WHERE org_id = ?
                   ORDER BY snapshot_at DESC
                   LIMIT 1""",
                (org_id,),
            ).fetchone()

        return {
            "org_id": org_id,
            "total_repo_trees": trees_row["cnt"] if trees_row else 0,
            "distinct_repos": distinct_repos_row["cnt"] if distinct_repos_row else 0,
            "total_snapshots": snap_row["cnt"] if snap_row else 0,
            "total_cached_files": cache_row["cnt"] if cache_row else 0,
            "sum_snapshot_violations": total_violations_row["s"] if total_violations_row else 0,
            "latest_snapshot_at": latest_row["snapshot_at"] if latest_row else None,
        }
