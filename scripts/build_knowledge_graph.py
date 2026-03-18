#!/usr/bin/env python3
"""
build_knowledge_graph.py — Populate the ALdeci KnowledgeBrain with real codebase data.

Indexes:
  1. All Python source files (with LOC + suite metadata)
  2. All API endpoints (parsed from router decorator patterns)
  3. All classes and public functions (via ast module)
  4. All database files (with table names via sqlite3)
  5. All cross-suite import edges (from X import Y)

Idempotent — safe to run multiple times (uses upsert_node / add_edge with ON CONFLICT).
Runs in under 60 seconds for ~550 files.

Usage:
    .venv/bin/python scripts/build_knowledge_graph.py
"""

from __future__ import annotations

import ast
import os
import re
import sqlite3
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Bootstrap sys.path so we can import KnowledgeBrain without pip install
# ---------------------------------------------------------------------------
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

# sitecustomize.py at repo root already injects all suite paths, but we call
# it explicitly here so the script works even if the venv does not pick it up.
_sitecustomize = REPO_ROOT / "sitecustomize.py"
if _sitecustomize.exists():
    exec(compile(_sitecustomize.read_text(), str(_sitecustomize), "exec"))  # noqa: S102

from core.knowledge_brain import (  # noqa: E402
    EdgeType,
    EntityType,
    GraphEdge,
    GraphNode,
    KnowledgeBrain,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
SUITES: Dict[str, str] = {
    "suite-api": "suite-api",
    "suite-core": "suite-core",
    "suite-attack": "suite-attack",
    "suite-feeds": "suite-feeds",
    "suite-evidence-risk": "suite-evidence-risk",
    "suite-integrations": "suite-integrations",
}

# Regex for HTTP method decorators used in FastAPI routers
ENDPOINT_RE = re.compile(
    r"""
    @\s*(?:router|app)\s*\.\s*
    (get|post|put|patch|delete|head|options|websocket)\s*\(
    \s*["'](.*?)["']          # path literal
    """,
    re.VERBOSE | re.IGNORECASE,
)

# Auth detection patterns — presence of any of these in the same decorator
# block or within the next few lines suggests auth is required.
AUTH_RE = re.compile(
    r"(require_auth|verify_api_key|Depends\(.*?auth|Depends\(.*?key|get_org_id|Security\()",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Counters
# ---------------------------------------------------------------------------
stats: Dict[str, int] = {
    "files_indexed": 0,
    "endpoints_found": 0,
    "classes_indexed": 0,
    "functions_indexed": 0,
    "databases_indexed": 0,
    "tables_indexed": 0,
    "import_edges": 0,
    "defines_edges": 0,
    "contains_edges": 0,
    "total_edges": 0,
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def suite_for_path(rel: str) -> str:
    """Return the suite name for a relative path string."""
    for suite in SUITES:
        if rel.startswith(suite + "/") or rel.startswith(suite + os.sep):
            return suite
    return "unknown"


def node_id_for_file(rel: str) -> str:
    return f"file:{rel}"


def node_id_for_class(rel: str, class_name: str) -> str:
    return f"class:{rel}::{class_name}"


def node_id_for_func(rel: str, func_name: str) -> str:
    return f"func:{rel}::{func_name}"


def node_id_for_endpoint(method: str, path: str) -> str:
    return f"endpoint:{method.upper()}:{path}"


def node_id_for_db(rel: str) -> str:
    return f"database:{rel}"


def node_id_for_table(db_rel: str, table: str) -> str:
    return f"table:{db_rel}::{table}"


def count_lines(path: Path) -> int:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return sum(1 for _ in fh)
    except OSError:
        return 0


def resolve_import_path(
    import_name: str,
    current_suite: str,
    all_module_ids: Dict[str, str],
) -> Optional[str]:
    """
    Try to map a bare import name (e.g. 'core.brain_pipeline') to a node_id.

    We check:
      1. Exact match of module path within any suite directory.
      2. Prefix match with suite package roots.
    """
    # Convert dotted module to path fragment
    fragment = import_name.replace(".", "/") + ".py"
    # Try each suite
    for suite in SUITES:
        candidate = f"{suite}/{fragment}"
        if candidate in all_module_ids:
            return all_module_ids[candidate]
    # Also try without suite prefix (e.g. 'brain_pipeline' inside suite-core/core/)
    for known_rel, node_id in all_module_ids.items():
        if known_rel.endswith(f"/{fragment}") or known_rel.endswith(f"/{import_name.split('.')[-1]}.py"):
            return node_id
    return None


# ---------------------------------------------------------------------------
# Phase 1: Index Python files
# ---------------------------------------------------------------------------

def collect_python_files() -> List[Tuple[Path, str]]:
    """Return (absolute_path, relative_path_from_repo_root) for all .py files."""
    results: List[Tuple[Path, str]] = []
    for suite_dir in SUITES:
        suite_abs = REPO_ROOT / suite_dir
        if not suite_abs.exists():
            continue
        for py_file in suite_abs.rglob("*.py"):
            # Skip compiled / cache
            if "__pycache__" in py_file.parts:
                continue
            if ".venv" in py_file.parts:
                continue
            rel = str(py_file.relative_to(REPO_ROOT))
            results.append((py_file, rel))
    return results


def index_files(brain: KnowledgeBrain, py_files: List[Tuple[Path, str]]) -> None:
    print(f"  Indexing {len(py_files)} Python files...")
    for abs_path, rel in py_files:
        suite = suite_for_path(rel)
        loc = count_lines(abs_path)
        node = GraphNode(
            node_id=node_id_for_file(rel),
            node_type=EntityType.COMPONENT,
            properties={
                "name": rel,
                "file_type": "python",
                "loc": loc,
                "suite": suite,
                "basename": abs_path.name,
            },
        )
        brain.upsert_node(node)
        stats["files_indexed"] += 1
    print(f"    -> {stats['files_indexed']} file nodes created.")


# ---------------------------------------------------------------------------
# Phase 2: Index API endpoints
# ---------------------------------------------------------------------------

def _detect_auth(source_lines: List[str], decorator_line_idx: int) -> bool:
    """
    Scan the decorator block (from decorator_line_idx to the def line, max 10 lines)
    for auth indicators.
    """
    window = source_lines[decorator_line_idx : decorator_line_idx + 12]
    snippet = "\n".join(window)
    return bool(AUTH_RE.search(snippet))


def index_endpoints(
    brain: KnowledgeBrain, py_files: List[Tuple[Path, str]]
) -> None:
    print("  Indexing API endpoints from router files...")
    for abs_path, rel in py_files:
        # Only parse files that look like router files for speed
        if not (
            rel.endswith("_router.py")
            or rel.endswith("_router.py")
            or "router" in abs_path.name
            or abs_path.name in ("app.py", "health.py")
        ):
            continue

        try:
            source = abs_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        lines = source.splitlines()
        file_node_id = node_id_for_file(rel)

        for i, line in enumerate(lines):
            m = ENDPOINT_RE.search(line)
            if not m:
                continue

            method = m.group(1).upper()
            path = m.group(2)

            # Normalise path — strip trailing slashes, ensure leading /
            path = "/" + path.strip("/")

            auth_required = _detect_auth(lines, i)

            ep_id = node_id_for_endpoint(method, path)
            ep_node = GraphNode(
                node_id=ep_id,
                node_type=EntityType.SERVICE,
                properties={
                    "name": f"{method} {path}",
                    "method": method,
                    "path": path,
                    "router_file": rel,
                    "auth_required": auth_required,
                    "entity_subtype": "api_endpoint",
                },
            )
            brain.upsert_node(ep_node)
            stats["endpoints_found"] += 1

            # Edge: file defines endpoint
            brain.add_edge(
                GraphEdge(
                    source_id=file_node_id,
                    target_id=ep_id,
                    edge_type=EdgeType.PRODUCED_BY,
                    properties={"relationship": "defines"},
                )
            )
            stats["defines_edges"] += 1
            stats["total_edges"] += 1

    print(f"    -> {stats['endpoints_found']} endpoint nodes, {stats['defines_edges']} defines edges.")


# ---------------------------------------------------------------------------
# Phase 3: Index classes and public functions via AST
# ---------------------------------------------------------------------------

def index_ast(brain: KnowledgeBrain, py_files: List[Tuple[Path, str]]) -> None:
    print(f"  Parsing AST for {len(py_files)} files (classes + functions)...")
    parse_errors = 0

    for abs_path, rel in py_files:
        file_node_id = node_id_for_file(rel)

        try:
            source = abs_path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source, filename=str(abs_path))
        except SyntaxError:
            parse_errors += 1
            continue
        except OSError:
            parse_errors += 1
            continue

        for node in ast.walk(tree):
            # --- Classes ---
            if isinstance(node, ast.ClassDef):
                cls_id = node_id_for_class(rel, node.name)
                bases = [ast.unparse(b) for b in node.bases] if hasattr(ast, "unparse") else []
                cls_node = GraphNode(
                    node_id=cls_id,
                    node_type=EntityType.COMPONENT,
                    properties={
                        "name": node.name,
                        "source_file": rel,
                        "line": node.lineno,
                        "bases": bases,
                        "entity_subtype": "class",
                    },
                )
                brain.upsert_node(cls_node)
                stats["classes_indexed"] += 1

                # Edge: file contains class
                brain.add_edge(
                    GraphEdge(
                        source_id=file_node_id,
                        target_id=cls_id,
                        edge_type=EdgeType.INCLUDES,
                        properties={"relationship": "contains_class"},
                    )
                )
                stats["contains_edges"] += 1
                stats["total_edges"] += 1

                # Index methods on this class (skip private _)
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        if item.name.startswith("_"):
                            continue
                        func_id = node_id_for_func(rel, f"{node.name}.{item.name}")
                        func_node = GraphNode(
                            node_id=func_id,
                            node_type=EntityType.COMPONENT,
                            properties={
                                "name": f"{node.name}.{item.name}",
                                "source_file": rel,
                                "line": item.lineno,
                                "is_async": isinstance(item, ast.AsyncFunctionDef),
                                "entity_subtype": "method",
                            },
                        )
                        brain.upsert_node(func_node)
                        stats["functions_indexed"] += 1

                        # Edge: class contains method
                        brain.add_edge(
                            GraphEdge(
                                source_id=cls_id,
                                target_id=func_id,
                                edge_type=EdgeType.INCLUDES,
                                properties={"relationship": "contains_method"},
                            )
                        )
                        stats["contains_edges"] += 1
                        stats["total_edges"] += 1

            # --- Top-level functions (direct children of module) ---
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # Only top-level: parent is Module
                # ast.walk does not give parent info — we approximate by checking
                # if the function name does not contain a dot (not a method)
                if node.name.startswith("_"):
                    continue
                func_id = node_id_for_func(rel, node.name)
                # Avoid double-indexing methods already captured above
                # We'll key on the flat function name at module level
                func_node = GraphNode(
                    node_id=func_id,
                    node_type=EntityType.COMPONENT,
                    properties={
                        "name": node.name,
                        "source_file": rel,
                        "line": node.lineno,
                        "is_async": isinstance(node, ast.AsyncFunctionDef),
                        "entity_subtype": "function",
                    },
                )
                brain.upsert_node(func_node)
                stats["functions_indexed"] += 1

                brain.add_edge(
                    GraphEdge(
                        source_id=file_node_id,
                        target_id=func_id,
                        edge_type=EdgeType.INCLUDES,
                        properties={"relationship": "contains_function"},
                    )
                )
                stats["contains_edges"] += 1
                stats["total_edges"] += 1

    print(
        f"    -> {stats['classes_indexed']} classes, "
        f"{stats['functions_indexed']} functions. "
        f"({parse_errors} parse errors skipped)"
    )


# ---------------------------------------------------------------------------
# Phase 4: Index database files and tables
# ---------------------------------------------------------------------------

def collect_db_files() -> List[Tuple[Path, str]]:
    """Collect .db files under data/ and suite-*/data/ (skip .venv, .claude/worktrees)."""
    results: List[Tuple[Path, str]] = []
    search_roots = [
        REPO_ROOT / "data",
        REPO_ROOT / ".fixops_data",
        REPO_ROOT / "suite-api" / "data",
    ]
    # Also check suite dirs for any stray .db files
    for suite_dir in SUITES:
        suite_abs = REPO_ROOT / suite_dir
        if suite_abs.exists():
            search_roots.append(suite_abs)

    seen: set = set()
    for root in search_roots:
        if not root.exists():
            continue
        for db_file in root.rglob("*.db"):
            # Skip worktrees, venv, pycache
            parts = db_file.parts
            if any(
                skip in parts
                for skip in (".venv", "__pycache__", "worktrees", "agent-memory")
            ):
                continue
            abs_str = str(db_file.resolve())
            if abs_str in seen:
                continue
            seen.add(abs_str)
            try:
                rel = str(db_file.relative_to(REPO_ROOT))
            except ValueError:
                rel = abs_str
            results.append((db_file, rel))
    return results


def get_table_names(db_path: Path) -> List[str]:
    """Return table names from a SQLite database, or [] on any error."""
    try:
        conn = sqlite3.connect(str(db_path), timeout=2.0)
        cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]
        conn.close()
        return tables
    except Exception:
        return []


def index_databases(brain: KnowledgeBrain) -> None:
    db_files = collect_db_files()
    print(f"  Indexing {len(db_files)} database files...")

    for abs_path, rel in db_files:
        db_id = node_id_for_db(rel)
        tables = get_table_names(abs_path)

        db_node = GraphNode(
            node_id=db_id,
            node_type=EntityType.COMPONENT,
            properties={
                "name": rel,
                "basename": abs_path.name,
                "table_count": len(tables),
                "entity_subtype": "database",
            },
        )
        brain.upsert_node(db_node)
        stats["databases_indexed"] += 1

        for table in tables:
            tbl_id = node_id_for_table(rel, table)
            tbl_node = GraphNode(
                node_id=tbl_id,
                node_type=EntityType.COMPONENT,
                properties={
                    "name": table,
                    "database": rel,
                    "entity_subtype": "table",
                },
            )
            brain.upsert_node(tbl_node)
            stats["tables_indexed"] += 1

            brain.add_edge(
                GraphEdge(
                    source_id=db_id,
                    target_id=tbl_id,
                    edge_type=EdgeType.INCLUDES,
                    properties={"relationship": "has_table"},
                )
            )
            stats["total_edges"] += 1

    print(
        f"    -> {stats['databases_indexed']} databases, "
        f"{stats['tables_indexed']} tables."
    )


# ---------------------------------------------------------------------------
# Phase 5: Index cross-suite import edges
# ---------------------------------------------------------------------------

def index_imports(
    brain: KnowledgeBrain, py_files: List[Tuple[Path, str]]
) -> None:
    print(f"  Indexing import edges across {len(py_files)} files...")

    # Build lookup: rel_path -> node_id for fast resolution
    all_module_ids: Dict[str, str] = {rel: node_id_for_file(rel) for _, rel in py_files}

    for abs_path, rel in py_files:
        file_node_id = node_id_for_file(rel)
        current_suite = suite_for_path(rel)

        try:
            source = abs_path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source, filename=str(abs_path))
        except (SyntaxError, OSError):
            continue

        for node in ast.walk(tree):
            import_names: List[str] = []

            if isinstance(node, ast.Import):
                for alias in node.names:
                    import_names.append(alias.name)

            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    import_names.append(node.module)

            for imp_name in import_names:
                target_node_id = resolve_import_path(imp_name, current_suite, all_module_ids)
                if target_node_id and target_node_id != file_node_id:
                    try:
                        brain.add_edge(
                            GraphEdge(
                                source_id=file_node_id,
                                target_id=target_node_id,
                                edge_type=EdgeType.DEPENDS_ON,
                                properties={"import_name": imp_name},
                            )
                        )
                        stats["import_edges"] += 1
                        stats["total_edges"] += 1
                    except Exception:
                        pass  # Duplicate edges silently ignored by ON CONFLICT

    print(f"    -> {stats['import_edges']} cross-suite import edges created.")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    t0 = time.monotonic()

    # Use the canonical brain DB path (matches what the API server uses)
    brain_db = REPO_ROOT / "data" / "fixops_brain.db"
    brain_db.parent.mkdir(parents=True, exist_ok=True)

    # Reset singleton in case another instance was cached
    KnowledgeBrain.reset_instance()
    brain = KnowledgeBrain.get_instance(db_path=brain_db)

    print(f"\n=== ALdeci Codebase Knowledge Graph Builder ===")
    print(f"Database: {brain_db}")
    print(f"Repo:     {REPO_ROOT}\n")

    # --- Phase 1: files ---
    t1 = time.monotonic()
    py_files = collect_python_files()
    index_files(brain, py_files)
    print(f"  (Phase 1 done in {time.monotonic()-t1:.1f}s)\n")

    # --- Phase 2: endpoints ---
    t2 = time.monotonic()
    index_endpoints(brain, py_files)
    print(f"  (Phase 2 done in {time.monotonic()-t2:.1f}s)\n")

    # --- Phase 3: AST ---
    t3 = time.monotonic()
    index_ast(brain, py_files)
    print(f"  (Phase 3 done in {time.monotonic()-t3:.1f}s)\n")

    # --- Phase 4: databases ---
    t4 = time.monotonic()
    index_databases(brain)
    print(f"  (Phase 4 done in {time.monotonic()-t4:.1f}s)\n")

    # --- Phase 5: imports ---
    t5 = time.monotonic()
    index_imports(brain, py_files)
    print(f"  (Phase 5 done in {time.monotonic()-t5:.1f}s)\n")

    # --- Final stats ---
    elapsed = time.monotonic() - t0
    graph_stats = brain.stats()

    print("=" * 52)
    print("CODEBASE KNOWLEDGE GRAPH — BUILD COMPLETE")
    print("=" * 52)
    print(f"  Total time:         {elapsed:.1f}s")
    print(f"  Files indexed:      {stats['files_indexed']}")
    print(f"  Endpoints found:    {stats['endpoints_found']}")
    print(f"  Classes indexed:    {stats['classes_indexed']}")
    print(f"  Functions indexed:  {stats['functions_indexed']}")
    print(f"  Databases indexed:  {stats['databases_indexed']}")
    print(f"  Tables indexed:     {stats['tables_indexed']}")
    print(f"  Import edges:       {stats['import_edges']}")
    print(f"  Defines edges:      {stats['defines_edges']}")
    print(f"  Contains edges:     {stats['contains_edges']}")
    print(f"  Edges total:        {stats['total_edges']}")
    print()
    print(f"  Graph nodes (DB):   {graph_stats['total_nodes']}")
    print(f"  Graph edges (DB):   {graph_stats['total_edges']}")
    print()
    print("  Node type breakdown:")
    for ntype, count in sorted(graph_stats["node_types"].items(), key=lambda x: -x[1]):
        print(f"    {ntype:<20} {count}")
    print()
    print("  Edge type breakdown:")
    for etype, count in sorted(graph_stats["edge_types"].items(), key=lambda x: -x[1]):
        print(f"    {etype:<20} {count}")
    print("=" * 52)

    brain.log_event(
        "CODEBASE_INDEXED",
        source="build_knowledge_graph.py",
        data={
            "files": stats["files_indexed"],
            "endpoints": stats["endpoints_found"],
            "classes": stats["classes_indexed"],
            "functions": stats["functions_indexed"],
            "databases": stats["databases_indexed"],
            "total_nodes": graph_stats["total_nodes"],
            "total_edges": graph_stats["total_edges"],
            "elapsed_seconds": round(elapsed, 2),
        },
    )


if __name__ == "__main__":
    main()
