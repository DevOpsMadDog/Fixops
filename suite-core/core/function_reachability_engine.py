"""Function Reachability Engine — ALDECI (GAP-010).

Implements function-level reachability analysis: given a CVE on a dependency,
determine whether the vulnerable function is actually reachable from the
customer's codebase call graph.

This is the Endor Labs moat — filters out vulnerabilities in code the customer
never calls, which typically eliminates 60-80% of CVE noise.

v0 scope (this file):
    - Python support via stdlib ``ast`` module (no new dependencies).
    - Call graph nodes (function definitions) + edges (direct + attribute calls).
    - BFS reachability with cycle-safety, max-depth, and query cache.
    - Vulnerable-reachability: resolve CVEs on a dependency to their callers.
    - TypeScript + Java are stubbed (NotImplementedError) pending NEW-G070
      semantic layer (Tree-sitter based DCA engine).

Schema:
    callgraph_nodes       — function definitions (FQN, source file, line range)
    callgraph_edges       — caller -> callee edges with edge_type + confidence
    reachability_queries  — cache of start_fqn -> target_fqn BFS results

Compliance: informs GAP-006 (auto-waivers), GAP-063 (finding lifecycle),
            pairs with GAP-048 (OSS call-graph corpus).
"""

from __future__ import annotations

import ast
import asyncio
import inspect
import json
import logging
import os
import re
import sqlite3
import threading
import uuid
from collections import deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None

_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "function_reachability.db"
)

# Separate cache DB for repo_sha-keyed reachability verdicts (per spec).
_DEFAULT_CACHE_DB = str(
    Path(__file__).resolve().parents[1] / "data" / "reachability_cache.db"
)


# ----------------------------------------------------------------------
# Public dataclass — what callers receive from analyse_vulnerable_symbol
# ----------------------------------------------------------------------


@dataclass
class FunctionReachabilityResult:
    """Reachability verdict for a single vulnerable function/symbol.

    NOTE: distinct from ``core.vuln_prioritizer.ReachabilityResult`` (Pydantic,
    used by the prioritisation pipeline) and
    ``core.sandbox_verifier.ReachabilityResult`` (sandbox network probe).
    This one represents *static* call-graph reachability from an application
    entry point to a CVE-vulnerable symbol.

    Fields:
        is_reachable        Conservative verdict — True if any entry point can
                            reach the vulnerable symbol via the call graph, OR
                            if the analysis falls back due to dynamic dispatch
                            (so customers never silently miss a real risk).
        call_path           BFS path of FQNs from entry-point to vuln symbol.
                            Empty list when unreachable or fallback path used.
        confidence          0.0–1.0 — based on call-graph completeness and
                            whether dynamic dispatch / reflection was hit.
        entry_point         FQN of the entry point that reaches the vuln, or
                            None when unreachable / fallback.
        analysis_method     "call_graph"   — clean static BFS hit
                            "ast_static"   — partial AST inference
                            "fallback_conservative"
                                           — dynamic dispatch / unknown symbol
                                             → conservatively flagged reachable
        vuln_function_fqn   The vulnerable symbol that was analysed.
        repo_sha            Git SHA / repo_ref the analysis was performed at.
        cached              True when the result was served from the cache.
    """

    is_reachable: bool
    call_path: List[str] = field(default_factory=list)
    confidence: float = 0.0
    entry_point: Optional[str] = None
    analysis_method: str = "call_graph"
    vuln_function_fqn: str = ""
    repo_sha: str = ""
    cached: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ----------------------------------------------------------------------
# Heuristics — what counts as an "entry point" / dynamic dispatch
# ----------------------------------------------------------------------

# Entry-point name patterns — HTTP handlers, CLI commands, scheduled jobs.
# Conservative: matches function basename or decorator hints.
_ENTRY_POINT_NAME_PATTERNS = (
    "handler", "handle_request", "endpoint",
    "route", "view",                 # FastAPI/Flask/Django views
    "main", "cli", "command",        # CLI / argparse / click
    "task", "job", "scheduled",      # Celery / cron
    "lambda_handler", "consume",     # AWS Lambda / Kafka consumers
    "on_event", "on_message",        # webhook / WS
)

# Symbols that indicate dynamic dispatch — call graph cannot follow these
# safely so we MUST fall back to the conservative-reachable verdict.
_DYNAMIC_DISPATCH_PATTERNS = re.compile(
    r"\b(eval|exec|getattr|setattr|__import__|importlib|"
    r"globals|locals|compile|hasattr)\b"
)

_VALID_LANGUAGES = {"python", "typescript", "javascript", "java"}
_VALID_EDGE_TYPES = {
    "direct_call",
    "dynamic_dispatch",
    "imported",
    "via_reflection",
}

_DEFAULT_MAX_DEPTH = 10


class FunctionReachabilityEngine:
    """Call-graph + reachability engine.

    Per-org isolation is enforced on every read/write.  All tables carry
    ``org_id`` and all public methods require it as the first argument.
    """

    def __init__(
        self,
        db_path: Optional[str] = None,
        cache_db_path: Optional[str] = None,
    ) -> None:
        # Resolve _DEFAULT_DB at call-time so tests can monkeypatch it via
        # ``monkeypatch.setattr("core.function_reachability_engine._DEFAULT_DB", ...)``.
        self.db_path = db_path if db_path is not None else _DEFAULT_DB
        self.cache_db_path = (
            cache_db_path if cache_db_path is not None else _DEFAULT_CACHE_DB
        )
        self._lock = threading.RLock()
        self._cache_lock = threading.RLock()
        self.ensure_schema()
        self.ensure_cache_schema()

    # ------------------------------------------------------------------
    # DB INIT
    # ------------------------------------------------------------------

    def ensure_schema(self) -> None:
        """Idempotent schema creation. Safe to call multiple times."""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS callgraph_nodes (
                    id            TEXT PRIMARY KEY,
                    org_id        TEXT NOT NULL,
                    repo_ref      TEXT NOT NULL,
                    language      TEXT NOT NULL,
                    function_fqn  TEXT NOT NULL,
                    source_file   TEXT NOT NULL DEFAULT '',
                    start_line    INTEGER NOT NULL DEFAULT 0,
                    end_line      INTEGER NOT NULL DEFAULT 0,
                    created_at    TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_fr_node_org
                    ON callgraph_nodes(org_id);
                CREATE INDEX IF NOT EXISTS idx_fr_node_repo
                    ON callgraph_nodes(org_id, repo_ref);
                CREATE INDEX IF NOT EXISTS idx_fr_node_fqn
                    ON callgraph_nodes(org_id, repo_ref, function_fqn);

                CREATE TABLE IF NOT EXISTS callgraph_edges (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    caller_node_id  TEXT NOT NULL,
                    callee_node_id  TEXT NOT NULL,
                    edge_type       TEXT NOT NULL DEFAULT 'direct_call',
                    confidence      REAL NOT NULL DEFAULT 1.0,
                    created_at      TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_fr_edge_org
                    ON callgraph_edges(org_id);
                CREATE INDEX IF NOT EXISTS idx_fr_edge_caller
                    ON callgraph_edges(org_id, caller_node_id);
                CREATE INDEX IF NOT EXISTS idx_fr_edge_callee
                    ON callgraph_edges(org_id, callee_node_id);

                CREATE TABLE IF NOT EXISTS reachability_queries (
                    id            TEXT PRIMARY KEY,
                    org_id        TEXT NOT NULL,
                    start_fqn     TEXT NOT NULL,
                    target_fqn    TEXT NOT NULL,
                    reachable_bool INTEGER NOT NULL DEFAULT 0,
                    path_json     TEXT NOT NULL DEFAULT '[]',
                    computed_at   TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_fr_query_org
                    ON reachability_queries(org_id);
                CREATE INDEX IF NOT EXISTS idx_fr_query_lookup
                    ON reachability_queries(org_id, start_fqn, target_fqn);

                CREATE TABLE IF NOT EXISTS finding_reachability_verdicts (
                    id            TEXT PRIMARY KEY,
                    org_id        TEXT NOT NULL,
                    finding_id    TEXT NOT NULL,
                    cve_id        TEXT NOT NULL DEFAULT '',
                    dependency_fqn_pattern TEXT NOT NULL DEFAULT '',
                    verdict       TEXT NOT NULL DEFAULT 'unknown',
                    reachable_callers TEXT NOT NULL DEFAULT '[]',
                    computed_at   TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_fr_fv_org
                    ON finding_reachability_verdicts(org_id);
                CREATE INDEX IF NOT EXISTS idx_fr_fv_finding
                    ON finding_reachability_verdicts(org_id, finding_id);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    # ------------------------------------------------------------------
    # REACHABILITY CACHE  (separate SQLite DB per spec)
    # ------------------------------------------------------------------

    def ensure_cache_schema(self) -> None:
        """Idempotent cache-DB schema. WAL + (repo_sha, vuln_function_signature) PK."""
        Path(self.cache_db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._cache_conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS reachability_cache (
                    repo_sha               TEXT NOT NULL,
                    vuln_function_signature TEXT NOT NULL,
                    org_id                 TEXT NOT NULL DEFAULT '',
                    is_reachable           INTEGER NOT NULL,
                    confidence             REAL NOT NULL,
                    entry_point            TEXT,
                    analysis_method        TEXT NOT NULL,
                    call_path_json         TEXT NOT NULL DEFAULT '[]',
                    cached_at              TEXT NOT NULL,
                    PRIMARY KEY (repo_sha, vuln_function_signature)
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_reach_cache_org "
                "ON reachability_cache(org_id)"
            )

    def _cache_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.cache_db_path, timeout=10, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _cache_get(
        self, repo_sha: str, vuln_function_signature: str
    ) -> Optional[FunctionReachabilityResult]:
        if not repo_sha or not vuln_function_signature:
            return None
        with self._cache_conn() as conn:
            row = conn.execute(
                """SELECT is_reachable, confidence, entry_point, analysis_method,
                          call_path_json
                   FROM reachability_cache
                   WHERE repo_sha=? AND vuln_function_signature=?""",
                (repo_sha, vuln_function_signature),
            ).fetchone()
        if row is None:
            return None
        try:
            call_path = json.loads(row["call_path_json"]) or []
        except json.JSONDecodeError:
            call_path = []
        return FunctionReachabilityResult(
            is_reachable=bool(row["is_reachable"]),
            call_path=call_path,
            confidence=float(row["confidence"]),
            entry_point=row["entry_point"],
            analysis_method=row["analysis_method"],
            vuln_function_fqn=vuln_function_signature,
            repo_sha=repo_sha,
            cached=True,
        )

    def _cache_put(
        self,
        repo_sha: str,
        vuln_function_signature: str,
        org_id: str,
        result: FunctionReachabilityResult,
    ) -> None:
        if not repo_sha or not vuln_function_signature:
            return
        with self._cache_lock, self._cache_conn() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO reachability_cache
                   (repo_sha, vuln_function_signature, org_id,
                    is_reachable, confidence, entry_point, analysis_method,
                    call_path_json, cached_at)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (
                    repo_sha,
                    vuln_function_signature,
                    org_id,
                    1 if result.is_reachable else 0,
                    float(result.confidence),
                    result.entry_point,
                    result.analysis_method,
                    json.dumps(result.call_path or []),
                    self._now(),
                ),
            )

    # ------------------------------------------------------------------
    # ENTRY-POINT DETECTION
    # ------------------------------------------------------------------

    def _is_entry_point(self, fqn: str, source_file: str = "") -> bool:
        """Return True when the FQN looks like an application entry point.

        Heuristic — matches well-known HTTP/CLI/job names.  Conservative: false
        positives only inflate the candidate-entry set, never miss reachability.
        """
        if not fqn:
            return False
        basename = fqn.rsplit(".", 1)[-1].lower()
        for pat in _ENTRY_POINT_NAME_PATTERNS:
            if pat in basename:
                return True
        # Files under /routers/, /handlers/, /views/, /tasks/ are entry-point hubs.
        sf = (source_file or "").lower()
        if any(seg in sf for seg in ("/router", "/handler", "/view", "/task", "/cli")):
            return True
        return False

    def list_entry_points(
        self, org_id: str, repo_ref: Optional[str] = None
    ) -> List[Dict[str, str]]:
        """Return all callgraph nodes that match the entry-point heuristic."""
        with self._conn() as conn:
            if repo_ref:
                rows = conn.execute(
                    """SELECT function_fqn, source_file FROM callgraph_nodes
                       WHERE org_id=? AND repo_ref=?""",
                    (org_id, repo_ref),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT function_fqn, source_file FROM callgraph_nodes "
                    "WHERE org_id=?",
                    (org_id,),
                ).fetchall()
        return [
            {"function_fqn": r["function_fqn"], "source_file": r["source_file"]}
            for r in rows
            if self._is_entry_point(r["function_fqn"], r["source_file"] or "")
        ]

    # ------------------------------------------------------------------
    # PRIMARY API — analyse_vulnerable_symbol
    # ------------------------------------------------------------------

    def analyse_vulnerable_symbol(
        self,
        org_id: str,
        repo_sha: str,
        vuln_function_fqn: str,
        cve_id: str = "",
        max_depth: int = _DEFAULT_MAX_DEPTH,
        candidate_entry_points: Optional[Iterable[str]] = None,
    ) -> FunctionReachabilityResult:
        """Decide whether ``vuln_function_fqn`` is reachable in ``repo_sha``.

        Resolution order:
            1. Cache lookup keyed by (repo_sha, vuln_function_fqn).
            2. Inspect the vulnerable symbol's source body for dynamic-dispatch
               markers (eval/getattr/...).  If present → conservative fallback.
            3. BFS from every detected entry point to the vuln symbol.
            4. If neither (2) nor (3) yields a verdict and the vuln symbol is
               NOT in the call graph at all → conservative fallback (we can't
               prove unreachability without coverage).
            5. Emit ``reachability.analyzed`` to the TrustGraph event bus and
               persist into the cache.

        Returns a :class:`FunctionReachabilityResult` (always non-None).
        """
        if not org_id:
            raise ValueError("org_id is required")
        if not repo_sha:
            raise ValueError("repo_sha is required")
        if not vuln_function_fqn:
            raise ValueError("vuln_function_fqn is required")

        # 1) Cache hit?
        cached = self._cache_get(repo_sha, vuln_function_fqn)
        if cached is not None:
            self._emit_reachability_analyzed(cve_id, cached)
            return cached

        # 2) Dynamic-dispatch fallback — inspect the vuln symbol's source body
        #    if we have it indexed.
        if self._symbol_uses_dynamic_dispatch(org_id, vuln_function_fqn):
            result = FunctionReachabilityResult(
                is_reachable=True,
                call_path=[],
                confidence=0.3,
                entry_point=None,
                analysis_method="fallback_conservative",
                vuln_function_fqn=vuln_function_fqn,
                repo_sha=repo_sha,
            )
            self._finalise(org_id, repo_sha, vuln_function_fqn, cve_id, result)
            return result

        # 3) Call-graph BFS from entry points.
        if candidate_entry_points is not None:
            entries = [e for e in candidate_entry_points if e]
        else:
            entries = [
                ep["function_fqn"] for ep in self.list_entry_points(org_id)
            ]

        # 3a) If the vuln symbol isn't even in the graph, we can't prove
        #     anything — conservative fallback.
        with self._conn() as conn:
            sym_present = conn.execute(
                "SELECT 1 FROM callgraph_nodes "
                "WHERE org_id=? AND function_fqn=? LIMIT 1",
                (org_id, vuln_function_fqn),
            ).fetchone()
        if sym_present is None:
            result = FunctionReachabilityResult(
                is_reachable=True,
                call_path=[],
                confidence=0.3,
                entry_point=None,
                analysis_method="fallback_conservative",
                vuln_function_fqn=vuln_function_fqn,
                repo_sha=repo_sha,
            )
            self._finalise(org_id, repo_sha, vuln_function_fqn, cve_id, result)
            return result

        # 3b) Real BFS — walk every entry point.
        for entry in entries:
            reachable, path = self.is_reachable(
                org_id, entry, vuln_function_fqn, max_depth=max_depth
            )
            if reachable and path:
                # Confidence: 1.0 minus a small per-hop penalty (clamped 0.5..1.0)
                confidence = max(0.5, 1.0 - 0.05 * (len(path) - 1))
                result = FunctionReachabilityResult(
                    is_reachable=True,
                    call_path=path,
                    confidence=confidence,
                    entry_point=entry,
                    analysis_method="call_graph",
                    vuln_function_fqn=vuln_function_fqn,
                    repo_sha=repo_sha,
                )
                self._finalise(org_id, repo_sha, vuln_function_fqn, cve_id, result)
                return result

        # 3c) Exhausted all entries with no path → genuinely unreachable.
        result = FunctionReachabilityResult(
            is_reachable=False,
            call_path=[],
            confidence=0.85,  # high — we have coverage and ran BFS over all entries
            entry_point=None,
            analysis_method="call_graph",
            vuln_function_fqn=vuln_function_fqn,
            repo_sha=repo_sha,
        )
        self._finalise(org_id, repo_sha, vuln_function_fqn, cve_id, result)
        return result

    # --- helpers for analyse_vulnerable_symbol -------------------------

    def _symbol_uses_dynamic_dispatch(self, org_id: str, fqn: str) -> bool:
        """Return True when the symbol's source body contains dynamic dispatch.

        Reads the source file/line range from ``callgraph_nodes`` and greps the
        body for ``eval/exec/getattr/...``.  If we can't read the file (external
        symbol, source missing), returns False — caller has its own fallback for
        symbols missing from the graph entirely.
        """
        with self._conn() as conn:
            row = conn.execute(
                "SELECT source_file, start_line, end_line FROM callgraph_nodes "
                "WHERE org_id=? AND function_fqn=? LIMIT 1",
                (org_id, fqn),
            ).fetchone()
        if row is None:
            return False
        sf = row["source_file"]
        if not sf or sf == "<external>":
            return False
        path = Path(sf)
        if not path.is_absolute():
            # relative paths are stored as-is; we don't have repo root here so
            # attempt cwd-relative read, otherwise bail.
            candidate = Path.cwd() / sf
            if candidate.exists():
                path = candidate
            else:
                return False
        if not path.exists() or not path.is_file():
            return False
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            return False
        start = max(0, int(row["start_line"] or 1) - 1)
        end = max(start + 1, int(row["end_line"] or start + 1))
        body = "\n".join(lines[start:end])
        return bool(_DYNAMIC_DISPATCH_PATTERNS.search(body))

    def _finalise(
        self,
        org_id: str,
        repo_sha: str,
        vuln_function_fqn: str,
        cve_id: str,
        result: FunctionReachabilityResult,
    ) -> None:
        """Cache + emit. Best-effort on emit, never raises."""
        self._cache_put(repo_sha, vuln_function_fqn, org_id, result)
        self._emit_reachability_analyzed(cve_id, result)

    def _emit_reachability_analyzed(
        self, cve_id: str, result: FunctionReachabilityResult
    ) -> None:
        """Emit ``reachability.analyzed`` to the TrustGraph event bus.

        Compatible with both async ``emit`` and sync ``publish`` shapes used
        across the platform.  Never raises.
        """
        if _get_tg_bus is None:
            return
        try:
            bus = _get_tg_bus()
            if bus is None:
                return
            payload = {
                "cve_id": cve_id,
                "vuln_function_fqn": result.vuln_function_fqn,
                "repo_sha": result.repo_sha,
                "is_reachable": result.is_reachable,
                "entry_point": result.entry_point,
                "confidence": result.confidence,
                "analysis_method": result.analysis_method,
            }
            emit = getattr(bus, "emit", None) or getattr(bus, "publish", None)
            if emit is None:
                return
            res = emit("reachability.analyzed", payload)
            if inspect.iscoroutine(res):
                try:
                    loop = asyncio.get_running_loop()
                    loop.create_task(res)
                except RuntimeError:
                    res.close()
        except Exception:  # nosec B110 — best-effort telemetry
            pass

    # ------------------------------------------------------------------
    # PYTHON AST PARSER
    # ------------------------------------------------------------------

    def parse_python_repo(
        self, org_id: str, repo_ref: str, root_path: str
    ) -> int:
        """Walk a Python repo, extract function defs + call edges.

        FQN format:
            module.func_name                    (top-level function)
            module.ClassName.method_name        (instance / class method)
            module.Outer.inner_func             (nested function)

        Edge extraction:
            - ``ast.Call`` with ``func = ast.Name(id=...)`` -> direct call to
              same-module name (best-effort local resolution)
            - ``ast.Call`` with ``func = ast.Attribute(...)`` -> attribute
              call, resolved to ``<receiver_fqn_hint>.attr``

        Call-site resolution is conservative: if the callee FQN is not found
        among parsed nodes in the same repo+org, an edge is still created to a
        synthetic "external" callee node.  This is intentional — the Endor use
        case is resolving CVE functions on *external* dependencies, so we must
        track edges to names that do not exist inside the customer repo.

        Returns:
            Number of nodes inserted for this call.
        """
        if not repo_ref:
            raise ValueError("repo_ref is required")
        if not root_path:
            raise ValueError("root_path is required")

        root = Path(root_path)
        if not root.exists():
            raise ValueError(f"root_path '{root_path}' does not exist")

        nodes_to_insert: List[Dict[str, Any]] = []
        edges_to_insert: List[Dict[str, Any]] = []
        # Map fqn -> node_id (local to this parse call) so edges can resolve
        fqn_to_node_id: Dict[str, str] = {}

        py_files: List[Path] = []
        if root.is_file() and root.suffix == ".py":
            py_files.append(root)
        else:
            for dirpath, _, filenames in os.walk(root):
                # Skip common noise dirs
                if any(
                    skip in dirpath
                    for skip in (
                        f"{os.sep}.git",
                        f"{os.sep}__pycache__",
                        f"{os.sep}.venv",
                        f"{os.sep}node_modules",
                    )
                ):
                    continue
                for fn in filenames:
                    if fn.endswith(".py"):
                        py_files.append(Path(dirpath) / fn)

        now = self._now()

        for py_file in py_files:
            try:
                source = py_file.read_text(encoding="utf-8")
                tree = ast.parse(source, filename=str(py_file))
            except (SyntaxError, UnicodeDecodeError) as exc:
                _logger.warning(
                    "fn_reach.parse_skip file=%s err=%s", py_file, exc
                )
                continue

            # Derive the module name from the relative path
            if root.is_file():
                # Single-file mode: the module name is just the stem
                rel = Path(py_file.name)
            else:
                try:
                    rel = py_file.relative_to(root)
                except ValueError:
                    rel = Path(py_file.name)
            module_parts = list(rel.with_suffix("").parts)
            if module_parts and module_parts[-1] == "__init__":
                module_parts = module_parts[:-1]
            module_name = ".".join(module_parts) if module_parts else py_file.stem

            # Build an import-name resolution table for this module:
            #   "call_external" -> "pkg.service.call_external"
            #       (from pkg.service import call_external)
            #   "requests"      -> "requests"          (import requests)
            #   "np"            -> "numpy"             (import numpy as np)
            import_aliases: Dict[str, str] = {}
            for top_node in ast.walk(tree):
                if isinstance(top_node, ast.ImportFrom):
                    if top_node.module is None:
                        continue
                    for alias in top_node.names:
                        local = alias.asname or alias.name
                        import_aliases[local] = f"{top_node.module}.{alias.name}"
                elif isinstance(top_node, ast.Import):
                    for alias in top_node.names:
                        local = alias.asname or alias.name
                        import_aliases[local] = alias.name

            # Walk collecting function defs (with class context) and their Call nodes
            for fn_def, class_stack in _iter_function_defs(tree):
                qualname_parts = class_stack + [fn_def.name]
                fqn = (
                    f"{module_name}.{'.'.join(qualname_parts)}"
                    if module_name
                    else ".".join(qualname_parts)
                )
                node_id = str(uuid.uuid4())
                fqn_to_node_id[fqn] = node_id

                end_line = getattr(fn_def, "end_lineno", None)
                if end_line is None:
                    end_line = fn_def.lineno

                nodes_to_insert.append(
                    {
                        "id": node_id,
                        "org_id": org_id,
                        "repo_ref": repo_ref,
                        "language": "python",
                        "function_fqn": fqn,
                        "source_file": str(rel),
                        "start_line": int(fn_def.lineno or 0),
                        "end_line": int(end_line or 0),
                        "created_at": now,
                    }
                )

                # Collect call sites inside this function
                for call_node in ast.walk(fn_def):
                    if not isinstance(call_node, ast.Call):
                        continue
                    callee_fqn, edge_type = _resolve_callee(
                        call_node.func, module_name, import_aliases
                    )
                    if not callee_fqn:
                        continue
                    edges_to_insert.append(
                        {
                            "caller_fqn": fqn,
                            "callee_fqn": callee_fqn,
                            "edge_type": edge_type,
                        }
                    )

        # Also pull already-indexed nodes in the DB for this (org, repo)
        with self._conn() as conn:
            existing = conn.execute(
                "SELECT function_fqn, id FROM callgraph_nodes "
                "WHERE org_id=? AND repo_ref=?",
                (org_id, repo_ref),
            ).fetchall()
        for r in existing:
            fqn_to_node_id.setdefault(r["function_fqn"], r["id"])

        # Second pass: materialise edges, creating synthetic callee nodes for
        # external callees (library APIs) so BFS can land on them.
        resolved_edges: List[Dict[str, Any]] = []
        for raw in edges_to_insert:
            caller_id = fqn_to_node_id.get(raw["caller_fqn"])
            if caller_id is None:
                continue
            callee_id = fqn_to_node_id.get(raw["callee_fqn"])
            confidence = 1.0
            if callee_id is None:
                # Synthetic external node for unresolved callees
                callee_id = str(uuid.uuid4())
                fqn_to_node_id[raw["callee_fqn"]] = callee_id
                nodes_to_insert.append(
                    {
                        "id": callee_id,
                        "org_id": org_id,
                        "repo_ref": repo_ref,
                        "language": "python",
                        "function_fqn": raw["callee_fqn"],
                        "source_file": "<external>",
                        "start_line": 0,
                        "end_line": 0,
                        "created_at": now,
                    }
                )
                confidence = 0.6  # lower confidence for unresolved externals
            resolved_edges.append(
                {
                    "id": str(uuid.uuid4()),
                    "org_id": org_id,
                    "caller_node_id": caller_id,
                    "callee_node_id": callee_id,
                    "edge_type": raw["edge_type"],
                    "confidence": confidence,
                    "created_at": now,
                }
            )

        # Bulk insert with lock
        inserted = 0
        with self._lock, self._conn() as conn:
            for node in nodes_to_insert:
                # Dedup on (org_id, repo_ref, function_fqn)
                existing_row = conn.execute(
                    "SELECT id FROM callgraph_nodes "
                    "WHERE org_id=? AND repo_ref=? AND function_fqn=?",
                    (node["org_id"], node["repo_ref"], node["function_fqn"]),
                ).fetchone()
                if existing_row is not None:
                    # Update our local map to point at the existing id
                    fqn_to_node_id[node["function_fqn"]] = existing_row["id"]
                    continue
                conn.execute(
                    """INSERT INTO callgraph_nodes
                        (id, org_id, repo_ref, language, function_fqn,
                         source_file, start_line, end_line, created_at)
                        VALUES (?,?,?,?,?,?,?,?,?)""",
                    (
                        node["id"], node["org_id"], node["repo_ref"],
                        node["language"], node["function_fqn"],
                        node["source_file"], node["start_line"],
                        node["end_line"], node["created_at"],
                    ),
                )
                inserted += 1

            # Re-resolve edges against (possibly updated) fqn_to_node_id
            for edge in resolved_edges:
                conn.execute(
                    """INSERT INTO callgraph_edges
                        (id, org_id, caller_node_id, callee_node_id,
                         edge_type, confidence, created_at)
                        VALUES (?,?,?,?,?,?,?)""",
                    (
                        edge["id"], edge["org_id"], edge["caller_node_id"],
                        edge["callee_node_id"], edge["edge_type"],
                        edge["confidence"], edge["created_at"],
                    ),
                )

        _logger.info(
            "fn_reach.parse_python org=%s repo=%s files=%d nodes_added=%d edges=%d",
            org_id, repo_ref, len(py_files), inserted, len(resolved_edges),
        )

        # TrustGraph emit (best-effort)
        if _get_tg_bus is not None:
            try:
                bus = _get_tg_bus()
                if bus is not None:
                    bus.publish(
                        "callgraph.parsed",
                        {
                            "org_id": org_id,
                            "repo_ref": repo_ref,
                            "language": "python",
                            "nodes_added": inserted,
                            "edges_added": len(resolved_edges),
                        },
                    )
            except Exception:  # nosec B110 — best-effort telemetry
                pass

        return inserted

    def parse_typescript_repo(
        self, org_id: str, repo_ref: str, root_path: str
    ) -> int:
        """Parse a TypeScript / JavaScript repo via tree-sitter.

        Walks ``*.ts``, ``*.tsx``, ``*.js``, ``*.jsx`` files; extracts
        function/method/arrow definitions and their call sites.  Skips
        ``node_modules``, ``.git``, ``dist``, ``build``, ``.next``.

        Falls back gracefully (NotImplementedError with install hint) when
        the optional ``tree-sitter-typescript`` bundle isn't installed.
        """
        if not repo_ref:
            raise ValueError("repo_ref is required")
        if not root_path:
            raise ValueError("root_path is required")

        try:
            import tree_sitter_typescript as tst
            from tree_sitter import Language, Parser
            ts_lang = Language(tst.language_typescript())
            tsx_lang = Language(tst.language_tsx())
            ts_parser = Parser(ts_lang)
            tsx_parser = Parser(tsx_lang)
        except ImportError:
            raise NotImplementedError(
                "tree-sitter-typescript not installed. "
                "Run: pip install tree-sitter tree-sitter-typescript"
            )

        root = Path(root_path)
        if not root.exists():
            raise ValueError(f"root_path '{root_path}' does not exist")

        nodes_to_insert: List[Dict[str, Any]] = []
        edges_to_insert: List[Dict[str, Any]] = []
        fqn_to_node_id: Dict[str, str] = {}
        now = self._now()

        ts_files = (
            list(root.rglob("*.ts"))
            + list(root.rglob("*.tsx"))
            + list(root.rglob("*.js"))
            + list(root.rglob("*.jsx"))
        )
        ts_files = [
            f for f in ts_files
            if not any(
                skip in f.parts
                for skip in ("node_modules", ".git", "dist", "build", ".next")
            )
        ]

        for ts_file in ts_files:
            try:
                source = ts_file.read_bytes()
                parser = tsx_parser if ts_file.suffix == ".tsx" else ts_parser
                tree = parser.parse(source)
                try:
                    rel = ts_file.relative_to(root)
                except ValueError:
                    rel = Path(ts_file.name)
                module_name = str(rel.with_suffix("")).replace(os.sep, ".")

                for node in self._walk_ts_tree(tree.root_node):
                    if node.type in (
                        "function_declaration", "method_definition",
                        "arrow_function", "function_expression",
                    ):
                        name_node = node.child_by_field_name("name")
                        if name_node is not None:
                            fn_name = name_node.text.decode(errors="ignore")
                        else:
                            # arrow / anonymous: try to capture parent
                            # variable_declarator name
                            parent = node.parent
                            if (
                                parent is not None
                                and parent.type == "variable_declarator"
                            ):
                                pn = parent.child_by_field_name("name")
                                fn_name = (
                                    pn.text.decode(errors="ignore")
                                    if pn is not None
                                    else f"<anon:{node.start_point[0]}>"
                                )
                            else:
                                fn_name = f"<anon:{node.start_point[0]}>"
                        fqn = f"{module_name}.{fn_name}" if module_name else fn_name
                        node_id = str(uuid.uuid4())
                        fqn_to_node_id[fqn] = node_id
                        nodes_to_insert.append({
                            "id": node_id, "org_id": org_id, "repo_ref": repo_ref,
                            "language": "typescript", "function_fqn": fqn,
                            "source_file": str(rel),
                            "start_line": int(node.start_point[0]),
                            "end_line": int(node.end_point[0]),
                            "created_at": now,
                        })
                        for callee_fqn in self._find_ts_calls(node):
                            edges_to_insert.append({
                                "caller_fqn": fqn,
                                "callee_fqn": callee_fqn,
                                "edge_type": "direct_call",
                            })
            except Exception as exc:  # nosec B112 — best-effort per-file
                _logger.warning("ts_parse_skip file=%s err=%s", ts_file, exc)
                continue

        return self._bulk_insert_nodes_edges(
            org_id, repo_ref, "typescript",
            nodes_to_insert, edges_to_insert, fqn_to_node_id, now,
            files_count=len(ts_files),
        )

    def parse_java_repo(
        self, org_id: str, repo_ref: str, root_path: str
    ) -> int:
        """Parse a Java repo via tree-sitter.

        Walks ``*.java`` files; extracts method/constructor declarations
        and ``method_invocation`` call sites.  Skips ``target``, ``build``,
        ``.gradle``, ``out``, ``.git``.
        """
        if not repo_ref:
            raise ValueError("repo_ref is required")
        if not root_path:
            raise ValueError("root_path is required")

        try:
            import tree_sitter_java as tsj
            from tree_sitter import Language, Parser
            java_lang = Language(tsj.language())
            parser = Parser(java_lang)
        except ImportError:
            raise NotImplementedError(
                "tree-sitter-java not installed. "
                "Run: pip install tree-sitter tree-sitter-java"
            )

        root = Path(root_path)
        if not root.exists():
            raise ValueError(f"root_path '{root_path}' does not exist")

        nodes_to_insert: List[Dict[str, Any]] = []
        edges_to_insert: List[Dict[str, Any]] = []
        fqn_to_node_id: Dict[str, str] = {}
        now = self._now()

        java_files = list(root.rglob("*.java"))
        java_files = [
            f for f in java_files
            if not any(
                skip in f.parts
                for skip in ("target", "build", ".gradle", "out", ".git")
            )
        ]

        for java_file in java_files:
            try:
                source = java_file.read_bytes()
                tree = parser.parse(source)
                try:
                    rel = java_file.relative_to(root)
                except ValueError:
                    rel = Path(java_file.name)
                module_name = str(rel.with_suffix("")).replace(os.sep, ".")

                # Build class-context stack while walking
                for cls_name, fn_node in self._walk_java_methods(tree.root_node):
                    name_node = fn_node.child_by_field_name("name")
                    fn_name = (
                        name_node.text.decode(errors="ignore")
                        if name_node is not None
                        else f"<anon:{fn_node.start_point[0]}>"
                    )
                    qualname = f"{cls_name}.{fn_name}" if cls_name else fn_name
                    fqn = (
                        f"{module_name}.{qualname}" if module_name else qualname
                    )
                    node_id = str(uuid.uuid4())
                    fqn_to_node_id[fqn] = node_id
                    nodes_to_insert.append({
                        "id": node_id, "org_id": org_id, "repo_ref": repo_ref,
                        "language": "java", "function_fqn": fqn,
                        "source_file": str(rel),
                        "start_line": int(fn_node.start_point[0]),
                        "end_line": int(fn_node.end_point[0]),
                        "created_at": now,
                    })
                    for callee_fqn in self._find_java_calls(fn_node):
                        edges_to_insert.append({
                            "caller_fqn": fqn,
                            "callee_fqn": callee_fqn,
                            "edge_type": "direct_call",
                        })
            except Exception as exc:  # nosec B112 — best-effort per-file
                _logger.warning("java_parse_skip file=%s err=%s", java_file, exc)
                continue

        return self._bulk_insert_nodes_edges(
            org_id, repo_ref, "java",
            nodes_to_insert, edges_to_insert, fqn_to_node_id, now,
            files_count=len(java_files),
        )

    # ------------------------------------------------------------------
    # tree-sitter helpers (TS / Java)
    # ------------------------------------------------------------------

    def _walk_ts_tree(self, node: Any):
        """Iterative DFS yielding every descendant tree-sitter node."""
        stack = [node]
        while stack:
            cur = stack.pop()
            yield cur
            # iterate in reverse so children are visited in source order
            for child in reversed(cur.children):
                stack.append(child)

    def _ts_callee_fqn(self, callee_node: Any) -> Optional[str]:
        """Resolve a TS call-expression callee to a dotted FQN string."""
        if callee_node is None:
            return None
        ntype = callee_node.type
        if ntype == "identifier":
            return callee_node.text.decode(errors="ignore")
        if ntype == "member_expression":
            # Walk down property chain: object.property.property...
            parts: List[str] = []
            cur = callee_node
            while cur is not None and cur.type == "member_expression":
                prop = cur.child_by_field_name("property")
                if prop is not None:
                    parts.append(prop.text.decode(errors="ignore"))
                cur = cur.child_by_field_name("object")
            if cur is not None and cur.type == "identifier":
                parts.append(cur.text.decode(errors="ignore"))
            parts.reverse()
            return ".".join(parts) if parts else None
        # call_expression callee, super, this, etc — try generic text
        try:
            return callee_node.text.decode(errors="ignore")
        except Exception:
            return None

    def _find_ts_calls(self, fn_node: Any) -> List[str]:
        """Walk fn_node subtree, return FQNs of every call_expression callee.

        Skips nested function definitions so callees belong to the enclosing
        function only (nested fns are emitted separately by the top-level walk).
        """
        out: List[str] = []
        nested_def_types = {
            "function_declaration", "method_definition",
            "arrow_function", "function_expression",
        }
        stack = list(fn_node.children)
        while stack:
            cur = stack.pop()
            if cur is fn_node:
                pass
            elif cur.type in nested_def_types:
                # Don't descend — calls inside nested fns belong to them.
                continue
            if cur.type == "call_expression":
                callee = cur.child_by_field_name("function")
                fqn = self._ts_callee_fqn(callee)
                if fqn:
                    out.append(fqn)
            for child in reversed(cur.children):
                stack.append(child)
        return out

    def _walk_java_methods(self, root_node: Any):
        """Yield (class_fqn, method_node) for every method/constructor.

        Tracks nested classes so inner-class methods get a dotted FQN
        (e.g. ``Outer.Inner.doThing``).
        """
        stack: List[Tuple[Any, List[str]]] = [(root_node, [])]
        while stack:
            node, class_stack = stack.pop()
            for child in node.children:
                if child.type in ("class_declaration", "interface_declaration",
                                  "enum_declaration", "record_declaration"):
                    name_node = child.child_by_field_name("name")
                    cls_name = (
                        name_node.text.decode(errors="ignore")
                        if name_node is not None else "<anon>"
                    )
                    body = child.child_by_field_name("body")
                    if body is not None:
                        stack.append((body, class_stack + [cls_name]))
                elif child.type in ("method_declaration", "constructor_declaration"):
                    yield (".".join(class_stack), child)
                else:
                    # Descend into other nodes (package, blocks, etc.)
                    stack.append((child, class_stack))

    def _java_callee_fqn(self, invocation_node: Any) -> Optional[str]:
        """Resolve a Java method_invocation to a dotted callee FQN."""
        if invocation_node is None:
            return None
        name_node = invocation_node.child_by_field_name("name")
        obj_node = invocation_node.child_by_field_name("object")
        method_name = (
            name_node.text.decode(errors="ignore") if name_node is not None else None
        )
        if not method_name:
            return None
        if obj_node is None:
            return method_name
        # object can itself be an identifier, field_access, method_invocation, etc.
        try:
            obj_text = obj_node.text.decode(errors="ignore")
        except Exception:
            obj_text = ""
        return f"{obj_text}.{method_name}" if obj_text else method_name

    def _find_java_calls(self, fn_node: Any) -> List[str]:
        """Walk a Java method body, return FQNs of every method_invocation."""
        out: List[str] = []
        nested_def_types = {
            "method_declaration", "constructor_declaration",
            "class_declaration", "interface_declaration",
        }
        stack = list(fn_node.children)
        while stack:
            cur = stack.pop()
            if cur is not fn_node and cur.type in nested_def_types:
                continue
            if cur.type == "method_invocation":
                fqn = self._java_callee_fqn(cur)
                if fqn:
                    out.append(fqn)
            for child in reversed(cur.children):
                stack.append(child)
        return out

    # ------------------------------------------------------------------
    # Shared bulk-insert (Python uses inline path; TS/Java use this)
    # ------------------------------------------------------------------

    def _bulk_insert_nodes_edges(
        self,
        org_id: str,
        repo_ref: str,
        language: str,
        nodes_to_insert: List[Dict[str, Any]],
        edges_to_insert: List[Dict[str, Any]],
        fqn_to_node_id: Dict[str, str],
        now: str,
        files_count: int = 0,
    ) -> int:
        """Materialise nodes + edges for non-Python parsers.

        Mirrors the second-pass logic in ``parse_python_repo``: pulls already
        indexed nodes for (org, repo), creates synthetic ``<external>`` nodes
        for unresolved callees, then writes everything under ``self._lock``.
        Returns the number of newly inserted nodes.
        """
        with self._conn() as conn:
            existing = conn.execute(
                "SELECT function_fqn, id FROM callgraph_nodes "
                "WHERE org_id=? AND repo_ref=?",
                (org_id, repo_ref),
            ).fetchall()
        for r in existing:
            fqn_to_node_id.setdefault(r["function_fqn"], r["id"])

        resolved_edges: List[Dict[str, Any]] = []
        for raw in edges_to_insert:
            caller_id = fqn_to_node_id.get(raw["caller_fqn"])
            if caller_id is None:
                continue
            callee_id = fqn_to_node_id.get(raw["callee_fqn"])
            confidence = 1.0
            if callee_id is None:
                callee_id = str(uuid.uuid4())
                fqn_to_node_id[raw["callee_fqn"]] = callee_id
                nodes_to_insert.append({
                    "id": callee_id,
                    "org_id": org_id,
                    "repo_ref": repo_ref,
                    "language": language,
                    "function_fqn": raw["callee_fqn"],
                    "source_file": "<external>",
                    "start_line": 0,
                    "end_line": 0,
                    "created_at": now,
                })
                confidence = 0.6
            resolved_edges.append({
                "id": str(uuid.uuid4()),
                "org_id": org_id,
                "caller_node_id": caller_id,
                "callee_node_id": callee_id,
                "edge_type": raw["edge_type"],
                "confidence": confidence,
                "created_at": now,
            })

        inserted = 0
        with self._lock, self._conn() as conn:
            for node in nodes_to_insert:
                existing_row = conn.execute(
                    "SELECT id FROM callgraph_nodes "
                    "WHERE org_id=? AND repo_ref=? AND function_fqn=?",
                    (node["org_id"], node["repo_ref"], node["function_fqn"]),
                ).fetchone()
                if existing_row is not None:
                    fqn_to_node_id[node["function_fqn"]] = existing_row["id"]
                    continue
                conn.execute(
                    """INSERT INTO callgraph_nodes
                        (id, org_id, repo_ref, language, function_fqn,
                         source_file, start_line, end_line, created_at)
                        VALUES (?,?,?,?,?,?,?,?,?)""",
                    (
                        node["id"], node["org_id"], node["repo_ref"],
                        node["language"], node["function_fqn"],
                        node["source_file"], node["start_line"],
                        node["end_line"], node["created_at"],
                    ),
                )
                inserted += 1
            for edge in resolved_edges:
                conn.execute(
                    """INSERT INTO callgraph_edges
                        (id, org_id, caller_node_id, callee_node_id,
                         edge_type, confidence, created_at)
                        VALUES (?,?,?,?,?,?,?)""",
                    (
                        edge["id"], edge["org_id"], edge["caller_node_id"],
                        edge["callee_node_id"], edge["edge_type"],
                        edge["confidence"], edge["created_at"],
                    ),
                )

        _logger.info(
            "fn_reach.parse_%s org=%s repo=%s files=%d nodes_added=%d edges=%d",
            language, org_id, repo_ref, files_count, inserted, len(resolved_edges),
        )

        if _get_tg_bus is not None:
            try:
                bus = _get_tg_bus()
                if bus is not None:
                    bus.publish(
                        "callgraph.parsed",
                        {
                            "org_id": org_id,
                            "repo_ref": repo_ref,
                            "language": language,
                            "nodes_added": inserted,
                            "edges_added": len(resolved_edges),
                        },
                    )
            except Exception:  # nosec B110 — best-effort telemetry
                pass

        return inserted

    # ------------------------------------------------------------------
    # REACHABILITY BFS
    # ------------------------------------------------------------------

    def is_reachable(
        self,
        org_id: str,
        start_fqn: str,
        target_fqn: str,
        max_depth: int = _DEFAULT_MAX_DEPTH,
    ) -> Tuple[bool, Optional[List[str]]]:
        """BFS from ``start_fqn`` to ``target_fqn``.

        Returns (reachable, path_or_None).  Path is a list of FQNs from start
        to target (inclusive).  Caches the result in ``reachability_queries``.

        Per-org only — edges from other orgs are never traversed.
        """
        if not start_fqn or not target_fqn:
            raise ValueError("start_fqn and target_fqn are required")
        if max_depth < 1:
            raise ValueError("max_depth must be >= 1")

        # Cache lookup — only short-circuit on a positive hit (reachable=True)
        # because a previous negative result may have been depth-truncated and
        # a retry with a larger max_depth should NOT be blocked by the cache.
        with self._conn() as conn:
            cached = conn.execute(
                """SELECT reachable_bool, path_json FROM reachability_queries
                   WHERE org_id=? AND start_fqn=? AND target_fqn=?
                     AND reachable_bool=1
                   ORDER BY computed_at DESC LIMIT 1""",
                (org_id, start_fqn, target_fqn),
            ).fetchone()
        if cached is not None:
            path = json.loads(cached["path_json"])
            # Only use the cached path if it fits within max_depth
            # (path length - 1 == hop count).
            if path and len(path) - 1 <= max_depth:
                return True, path

        # Resolve start node
        with self._conn() as conn:
            start_rows = conn.execute(
                "SELECT id FROM callgraph_nodes WHERE org_id=? AND function_fqn=?",
                (org_id, start_fqn),
            ).fetchall()
        if not start_rows:
            # start not in graph -> unreachable
            self._record_query(org_id, start_fqn, target_fqn, False, None)
            return False, None

        start_ids = [r["id"] for r in start_rows]

        # BFS over edges, carrying parent links to reconstruct the path.
        visited: Dict[str, Optional[str]] = {sid: None for sid in start_ids}
        queue: deque = deque((sid, 0) for sid in start_ids)

        found_node_id: Optional[str] = None

        while queue:
            current, depth = queue.popleft()
            # Check if current is a target node
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT function_fqn FROM callgraph_nodes "
                    "WHERE id=? AND org_id=?",
                    (current, org_id),
                ).fetchone()
            if row is not None and row["function_fqn"] == target_fqn:
                found_node_id = current
                break

            if depth >= max_depth:
                continue

            with self._conn() as conn:
                neighbors = conn.execute(
                    "SELECT callee_node_id FROM callgraph_edges "
                    "WHERE org_id=? AND caller_node_id=?",
                    (org_id, current),
                ).fetchall()
            for n in neighbors:
                nid = n["callee_node_id"]
                if nid in visited:
                    continue
                visited[nid] = current
                queue.append((nid, depth + 1))

        if found_node_id is None:
            self._record_query(org_id, start_fqn, target_fqn, False, None)
            return False, None

        # Reconstruct path (FQNs)
        chain_ids: List[str] = []
        cur: Optional[str] = found_node_id
        while cur is not None:
            chain_ids.append(cur)
            cur = visited.get(cur)
        chain_ids.reverse()

        # Batch-resolve node_ids -> fqns (one SELECT is enough)
        with self._conn() as conn:
            placeholders = ",".join("?" * len(chain_ids))
            rows = conn.execute(
                f"SELECT id, function_fqn FROM callgraph_nodes "
                f"WHERE org_id=? AND id IN ({placeholders})",  # nosec B608
                [org_id] + chain_ids,
            ).fetchall()
        id_to_fqn = {r["id"]: r["function_fqn"] for r in rows}
        path = [id_to_fqn.get(i, "<?>") for i in chain_ids]

        self._record_query(org_id, start_fqn, target_fqn, True, path)
        return True, path

    def _record_query(
        self,
        org_id: str,
        start_fqn: str,
        target_fqn: str,
        reachable: bool,
        path: Optional[List[str]],
    ) -> None:
        with self._lock, self._conn() as conn:
            conn.execute(
                """INSERT INTO reachability_queries
                    (id, org_id, start_fqn, target_fqn,
                     reachable_bool, path_json, computed_at)
                    VALUES (?,?,?,?,?,?,?)""",
                (
                    str(uuid.uuid4()), org_id, start_fqn, target_fqn,
                    1 if reachable else 0,
                    json.dumps(path or []),
                    self._now(),
                ),
            )

    # ------------------------------------------------------------------
    # VULNERABILITY REACHABILITY
    # ------------------------------------------------------------------

    def vulnerable_reachability(
        self,
        org_id: str,
        cve_id: str,
        dependency_fqn_pattern: str,
    ) -> List[Dict[str, Any]]:
        """For a CVE on a dependency, find all customer callers that reach it.

        ``dependency_fqn_pattern`` is matched against ``function_fqn`` with
        SQL LIKE (e.g. ``requests.Session.mount`` or ``requests.%``).

        Returns a list of caller records:
            {
                "caller_fqn": "...",
                "caller_source_file": "...",
                "target_fqn": "...",
                "path": [...],
            }

        Strategy:
            1. Find all nodes whose FQN matches the pattern (the "sinks").
            2. For each sink, find all callers via reverse edges (single hop)
               and record them; fully-transitive paths can be resolved with
               ``is_reachable`` on demand.
        """
        if not cve_id:
            raise ValueError("cve_id is required")
        if not dependency_fqn_pattern:
            raise ValueError("dependency_fqn_pattern is required")

        # Step 1: sink nodes (vulnerable function set)
        with self._conn() as conn:
            sinks = conn.execute(
                "SELECT id, function_fqn FROM callgraph_nodes "
                "WHERE org_id=? AND function_fqn LIKE ?",
                (org_id, dependency_fqn_pattern),
            ).fetchall()

        if not sinks:
            return []

        callers: List[Dict[str, Any]] = []
        seen_pairs: set = set()

        for sink in sinks:
            # Reverse edges (direct callers of the vulnerable function)
            with self._conn() as conn:
                edge_rows = conn.execute(
                    """SELECT DISTINCT caller_node_id FROM callgraph_edges
                       WHERE org_id=? AND callee_node_id=?""",
                    (org_id, sink["id"]),
                ).fetchall()
            for er in edge_rows:
                caller_id = er["caller_node_id"]
                with self._conn() as conn:
                    cr = conn.execute(
                        "SELECT function_fqn, source_file FROM callgraph_nodes "
                        "WHERE id=? AND org_id=?",
                        (caller_id, org_id),
                    ).fetchone()
                if cr is None:
                    continue
                # Exclude callers that are themselves inside the vulnerable
                # dependency (we only want *customer* callers).  The heuristic:
                # customer callers have a real source_file (not "<external>").
                if cr["source_file"] == "<external>":
                    continue
                pair = (cr["function_fqn"], sink["function_fqn"])
                if pair in seen_pairs:
                    continue
                seen_pairs.add(pair)
                callers.append(
                    {
                        "cve_id": cve_id,
                        "caller_fqn": cr["function_fqn"],
                        "caller_source_file": cr["source_file"],
                        "target_fqn": sink["function_fqn"],
                        "path": [cr["function_fqn"], sink["function_fqn"]],
                    }
                )

        _logger.info(
            "fn_reach.vuln_reach org=%s cve=%s pattern=%s callers=%d",
            org_id, cve_id, dependency_fqn_pattern, len(callers),
        )
        return callers

    # ------------------------------------------------------------------
    # FINDING VERDICT PERSISTENCE
    # ------------------------------------------------------------------

    def record_finding_verdict(
        self,
        org_id: str,
        finding_id: str,
        cve_id: str,
        dependency_fqn_pattern: str,
        verdict: str,
        reachable_callers: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Persist a reachability verdict for a finding."""
        if verdict not in {"reachable", "unreachable", "unknown"}:
            raise ValueError(
                "verdict must be 'reachable', 'unreachable' or 'unknown'"
            )
        vid = str(uuid.uuid4())
        now = self._now()
        with self._lock, self._conn() as conn:
            conn.execute(
                """INSERT INTO finding_reachability_verdicts
                    (id, org_id, finding_id, cve_id, dependency_fqn_pattern,
                     verdict, reachable_callers, computed_at)
                    VALUES (?,?,?,?,?,?,?,?)""",
                (
                    vid, org_id, finding_id, cve_id, dependency_fqn_pattern,
                    verdict, json.dumps(reachable_callers), now,
                ),
            )
        return {
            "id": vid,
            "org_id": org_id,
            "finding_id": finding_id,
            "cve_id": cve_id,
            "dependency_fqn_pattern": dependency_fqn_pattern,
            "verdict": verdict,
            "reachable_callers": reachable_callers,
            "computed_at": now,
        }

    def get_finding_verdict(
        self, org_id: str, finding_id: str
    ) -> Optional[Dict[str, Any]]:
        """Return the most recent verdict for a finding, or None."""
        with self._conn() as conn:
            row = conn.execute(
                """SELECT * FROM finding_reachability_verdicts
                   WHERE org_id=? AND finding_id=?
                   ORDER BY computed_at DESC LIMIT 1""",
                (org_id, finding_id),
            ).fetchone()
        if row is None:
            return None
        data = self._row(row)
        try:
            data["reachable_callers"] = json.loads(
                data.get("reachable_callers") or "[]"
            )
        except json.JSONDecodeError:
            data["reachable_callers"] = []
        return data

    # ------------------------------------------------------------------
    # QUERIES / STATS
    # ------------------------------------------------------------------

    def list_callgraph(self, org_id: str, repo_ref: str) -> Dict[str, Any]:
        """Return all nodes + edges for a repo (for UI visualisation)."""
        with self._conn() as conn:
            nodes = conn.execute(
                """SELECT * FROM callgraph_nodes
                   WHERE org_id=? AND repo_ref=?
                   ORDER BY function_fqn""",
                (org_id, repo_ref),
            ).fetchall()
            node_ids = [n["id"] for n in nodes]
            edges: List[sqlite3.Row] = []
            if node_ids:
                placeholders = ",".join("?" * len(node_ids))
                edges = conn.execute(
                    f"""SELECT * FROM callgraph_edges
                        WHERE org_id=?
                          AND caller_node_id IN ({placeholders})""",  # nosec B608
                    [org_id] + node_ids,
                ).fetchall()
        return {
            "repo_ref": repo_ref,
            "nodes": [self._row(n) for n in nodes],
            "edges": [self._row(e) for e in edges],
            "node_count": len(nodes),
            "edge_count": len(edges),
        }

    def stats(self, org_id: str) -> Dict[str, Any]:
        """Aggregate counts for this org."""
        with self._conn() as conn:
            node_count = conn.execute(
                "SELECT COUNT(*) FROM callgraph_nodes WHERE org_id=?",
                (org_id,),
            ).fetchone()[0]
            edge_count = conn.execute(
                "SELECT COUNT(*) FROM callgraph_edges WHERE org_id=?",
                (org_id,),
            ).fetchone()[0]
            query_count = conn.execute(
                "SELECT COUNT(*) FROM reachability_queries WHERE org_id=?",
                (org_id,),
            ).fetchone()[0]
            reachable_hits = conn.execute(
                """SELECT COUNT(*) FROM reachability_queries
                   WHERE org_id=? AND reachable_bool=1""",
                (org_id,),
            ).fetchone()[0]
            verdict_rows = conn.execute(
                """SELECT verdict, COUNT(*) AS cnt
                   FROM finding_reachability_verdicts
                   WHERE org_id=? GROUP BY verdict""",
                (org_id,),
            ).fetchall()
            by_language = conn.execute(
                """SELECT language, COUNT(*) AS cnt
                   FROM callgraph_nodes
                   WHERE org_id=? GROUP BY language""",
                (org_id,),
            ).fetchall()
            by_repo = conn.execute(
                """SELECT repo_ref, COUNT(*) AS cnt
                   FROM callgraph_nodes
                   WHERE org_id=? GROUP BY repo_ref""",
                (org_id,),
            ).fetchall()

        return {
            "node_count": node_count,
            "edge_count": edge_count,
            "query_count": query_count,
            "reachable_hits": reachable_hits,
            "by_language": {r["language"]: r["cnt"] for r in by_language},
            "by_repo": {r["repo_ref"]: r["cnt"] for r in by_repo},
            "verdicts": {r["verdict"]: r["cnt"] for r in verdict_rows},
        }


# ----------------------------------------------------------------------
# AST helpers
# ----------------------------------------------------------------------


def _iter_function_defs(tree: ast.AST):
    """Yield (FunctionDef-or-AsyncFunctionDef, class_stack) pairs.

    ``class_stack`` is a list of enclosing class names, outermost first.
    Nested functions are flattened with their parent function's name included
    in the stack so that FQNs like ``mod.outer.inner`` resolve correctly.
    """
    # Iterative walk so we can maintain an explicit scope stack.
    stack: List[Tuple[ast.AST, List[str]]] = [(tree, [])]
    while stack:
        node, scope = stack.pop()
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.ClassDef):
                stack.append((child, scope + [child.name]))
            elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                yield child, list(scope)
                # Allow nested defs — their enclosing scope includes the fn name
                stack.append((child, scope + [child.name]))
            else:
                stack.append((child, scope))


def _resolve_callee(
    func_node: ast.AST,
    module_name: str,
    import_aliases: Optional[Dict[str, str]] = None,
) -> Tuple[Optional[str], str]:
    """Best-effort callee FQN resolution.

    Resolution strategy:
        1. ``ast.Name(id=X)``:
             - If X is an imported alias -> use the imported FQN.
             - Else fall back to ``<module_name>.X`` (same-module hypothesis).
        2. ``ast.Attribute(...)``:
             Build a dotted chain.  If the root Name is in ``import_aliases``,
             rewrite the chain's root to the imported FQN so external calls
             land in the right ecosystem namespace (e.g. ``requests.Session.mount``
             stays intact; ``np.array`` becomes ``numpy.array``).

    Returns (callee_fqn_or_None, edge_type).
    """
    if import_aliases is None:
        import_aliases = {}

    if isinstance(func_node, ast.Name):
        target = func_node.id
        if target in import_aliases:
            return import_aliases[target], "imported"
        if module_name:
            return f"{module_name}.{target}", "direct_call"
        return target, "direct_call"

    if isinstance(func_node, ast.Attribute):
        parts: List[str] = []
        cur: ast.AST = func_node
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            root_name = cur.id
            parts.reverse()
            if root_name in import_aliases:
                # Replace the root with the imported FQN
                return ".".join([import_aliases[root_name]] + parts), "imported"
            # Otherwise: ``self.xyz()`` / ``cls.xyz()`` fall into here.
            # For ``self.x()``, treat as dynamic_dispatch with unresolved receiver.
            if root_name in ("self", "cls"):
                return ".".join([root_name] + parts), "dynamic_dispatch"
            return ".".join([root_name] + parts), "direct_call"
        # call().attr(), not statically resolvable
        parts.reverse()
        if parts:
            return ".".join(parts), "dynamic_dispatch"

    if isinstance(func_node, ast.Call):
        return None, "dynamic_dispatch"
    return None, "direct_call"


# Convenience singleton for shared access (matches other engines' pattern)
_SHARED: Optional[FunctionReachabilityEngine] = None


def get_engine() -> FunctionReachabilityEngine:
    global _SHARED
    if _SHARED is None:
        _SHARED = FunctionReachabilityEngine()
    return _SHARED
