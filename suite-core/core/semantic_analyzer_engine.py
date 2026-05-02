"""Semantic Analyzer Engine — ALDECI (NEW-G070).

Multi-language semantic layer. v0 implementation:
  - Python via stdlib `ast` (fully works).
  - SQLAlchemy / Django ORM detectors via `ast` (work).
  - Minimal Prisma DSL parser (works, no external deps).
  - TypeScript / Java / Go / Drizzle stubbed (raise NotImplementedError).

Pairs with GAP-012 deep_code_analysis and GAP-065 arch-graph.

Schema:
  - semantic_repos
  - semantic_symbols    (function/class/variable/interface/type_alias)
  - semantic_references (call/inherit/implement/use/import)
  - semantic_orm_schemas (prisma/drizzle/sqlalchemy/django_orm)

Compliance: Engineering enablement for SAST/arch-review.
"""

from __future__ import annotations

import ast
import json
import logging
import os
import re
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None

# Optional tree-sitter integration. We import lazily so this module continues
# to work in environments where tree-sitter wheels are unavailable.
_TS_AVAILABLE = False
_TS_LANGS: Dict[str, Any] = {}
_TS_PARSERS: Dict[str, Any] = {}

try:  # pragma: no cover - import-only branch
    from tree_sitter import Language as _TSLanguage  # type: ignore
    from tree_sitter import Parser as _TSParser

    try:
        import tree_sitter_typescript as _ts_typescript  # type: ignore

        _TS_LANGS["typescript"] = _TSLanguage(_ts_typescript.language_typescript())
        _TS_LANGS["tsx"] = _TSLanguage(_ts_typescript.language_tsx())
    except Exception:  # pragma: no cover
        pass

    try:
        import tree_sitter_java as _ts_java  # type: ignore

        _TS_LANGS["java"] = _TSLanguage(_ts_java.language())
    except Exception:  # pragma: no cover
        pass

    try:
        import tree_sitter_go as _ts_go  # type: ignore

        _TS_LANGS["go"] = _TSLanguage(_ts_go.language())
    except Exception:  # pragma: no cover
        pass

    for _name, _lang in _TS_LANGS.items():
        _TS_PARSERS[_name] = _TSParser(_lang)
    _TS_AVAILABLE = bool(_TS_PARSERS)
except Exception:  # pragma: no cover
    _TS_AVAILABLE = False

_logger = logging.getLogger(__name__)

_DEFAULT_DB_DIR = str(Path(__file__).resolve().parents[2] / ".fixops_data")

_VALID_SYMBOL_TYPES = {"function", "class", "variable", "interface", "type_alias"}
_VALID_REFERENCE_KINDS = {"call", "inherit", "implement", "use", "import"}
_VALID_ORM_FRAMEWORKS = {"prisma", "drizzle", "sqlalchemy", "django_orm"}

# Extension → canonical language name.
_LANGUAGE_EXTENSIONS: Dict[str, str] = {
    ".py": "python",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".js": "javascript",
    ".jsx": "javascript",
    ".java": "java",
    ".go": "go",
    ".rb": "ruby",
    ".rs": "rust",
    ".kt": "kotlin",
    ".swift": "swift",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".hpp": "cpp",
    ".cs": "csharp",
    ".php": "php",
    ".scala": "scala",
    ".sql": "sql",
    ".prisma": "prisma",
}

_SKIP_DIRS = {
    "node_modules", ".git", ".venv", "venv", "__pycache__",
    ".tox", "dist", "build", ".next", ".mypy_cache", ".pytest_cache",
    ".ruff_cache", "target",
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class SemanticAnalyzerEngine:
    """Multi-language semantic analyzer engine, WAL-backed SQLite."""

    def __init__(self, db_path: Optional[str] = None) -> None:
        if db_path is None:
            db_path = str(Path(_DEFAULT_DB_DIR) / "semantic_analyzer.db")
        self._db_path = db_path
        self._lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS semantic_repos (
                    id                      TEXT PRIMARY KEY,
                    org_id                  TEXT NOT NULL,
                    repo_ref                TEXT NOT NULL,
                    languages_detected_json TEXT NOT NULL DEFAULT '{}',
                    parsers_used_json       TEXT NOT NULL DEFAULT '[]',
                    last_analyzed_at        TEXT,
                    created_at              TEXT NOT NULL,
                    UNIQUE(org_id, repo_ref)
                );

                CREATE INDEX IF NOT EXISTS idx_sem_repos_org
                    ON semantic_repos (org_id, repo_ref);

                CREATE TABLE IF NOT EXISTS semantic_symbols (
                    id              TEXT PRIMARY KEY,
                    repo_id         TEXT NOT NULL,
                    symbol_type     TEXT NOT NULL,
                    symbol_name     TEXT NOT NULL,
                    fqn             TEXT NOT NULL,
                    file_ref        TEXT NOT NULL DEFAULT '',
                    start_line      INTEGER NOT NULL DEFAULT 0,
                    end_line        INTEGER NOT NULL DEFAULT 0,
                    semantic_type   TEXT NOT NULL DEFAULT '',
                    metadata_json   TEXT NOT NULL DEFAULT '{}',
                    created_at      TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_sem_symbols_repo
                    ON semantic_symbols (repo_id, symbol_type, symbol_name);
                CREATE INDEX IF NOT EXISTS idx_sem_symbols_fqn
                    ON semantic_symbols (repo_id, fqn);

                CREATE TABLE IF NOT EXISTS semantic_references (
                    id                TEXT PRIMARY KEY,
                    repo_id           TEXT NOT NULL,
                    source_symbol_id  TEXT NOT NULL DEFAULT '',
                    target_symbol_id  TEXT NOT NULL DEFAULT '',
                    target_fqn        TEXT NOT NULL DEFAULT '',
                    reference_kind    TEXT NOT NULL,
                    file_ref          TEXT NOT NULL DEFAULT '',
                    line_number       INTEGER NOT NULL DEFAULT 0,
                    created_at        TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_sem_refs_repo
                    ON semantic_references (repo_id, reference_kind);
                CREATE INDEX IF NOT EXISTS idx_sem_refs_target
                    ON semantic_references (repo_id, target_fqn);

                CREATE TABLE IF NOT EXISTS semantic_orm_schemas (
                    id                 TEXT PRIMARY KEY,
                    repo_id            TEXT NOT NULL,
                    orm_framework      TEXT NOT NULL,
                    model_name         TEXT NOT NULL,
                    file_ref           TEXT NOT NULL DEFAULT '',
                    fields_json        TEXT NOT NULL DEFAULT '[]',
                    relationships_json TEXT NOT NULL DEFAULT '[]',
                    created_at         TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_sem_orm_repo
                    ON semantic_orm_schemas (repo_id, orm_framework, model_name);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # Repo registration helpers
    # ------------------------------------------------------------------

    def _get_or_create_repo(
        self, org_id: str, repo_ref: str
    ) -> Dict[str, Any]:
        now = _now_iso()
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM semantic_repos WHERE org_id = ? AND repo_ref = ?",
                    (org_id, repo_ref),
                ).fetchone()
                if row:
                    return dict(row)
                rid = str(uuid.uuid4())
                conn.execute(
                    """
                    INSERT INTO semantic_repos
                        (id, org_id, repo_ref, languages_detected_json,
                         parsers_used_json, last_analyzed_at, created_at)
                    VALUES (?, ?, ?, '{}', '[]', NULL, ?)
                    """,
                    (rid, org_id, repo_ref, now),
                )
                return {
                    "id": rid,
                    "org_id": org_id,
                    "repo_ref": repo_ref,
                    "languages_detected_json": "{}",
                    "parsers_used_json": "[]",
                    "last_analyzed_at": None,
                    "created_at": now,
                }

    def _update_repo_meta(
        self,
        repo_id: str,
        languages: Optional[Dict[str, int]] = None,
        parser_used: Optional[str] = None,
    ) -> None:
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT languages_detected_json, parsers_used_json FROM semantic_repos WHERE id = ?",
                    (repo_id,),
                ).fetchone()
                if not row:
                    return
                cur_langs = json.loads(row["languages_detected_json"] or "{}")
                cur_parsers = json.loads(row["parsers_used_json"] or "[]")
                if languages is not None:
                    cur_langs = languages
                if parser_used and parser_used not in cur_parsers:
                    cur_parsers.append(parser_used)
                conn.execute(
                    """
                    UPDATE semantic_repos
                       SET languages_detected_json = ?,
                           parsers_used_json = ?,
                           last_analyzed_at = ?
                     WHERE id = ?
                    """,
                    (
                        json.dumps(cur_langs, sort_keys=True),
                        json.dumps(cur_parsers, sort_keys=True),
                        _now_iso(),
                        repo_id,
                    ),
                )

    # ------------------------------------------------------------------
    # Language detection
    # ------------------------------------------------------------------

    def detect_languages(self, root_path: str) -> Dict[str, Any]:
        """Walk the tree and count files per canonical language."""
        counts: Dict[str, int] = {}
        total_files = 0
        root = Path(root_path)
        if not root.exists():
            return {"root": str(root), "total_files": 0, "languages": {}}
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
            for fn in filenames:
                ext = Path(fn).suffix.lower()
                lang = _LANGUAGE_EXTENSIONS.get(ext)
                if lang:
                    counts[lang] = counts.get(lang, 0) + 1
                    total_files += 1
        return {
            "root": str(root),
            "total_files": total_files,
            "languages": counts,
        }

    # ------------------------------------------------------------------
    # Symbol / reference insertion helpers
    # ------------------------------------------------------------------

    def _insert_symbol(
        self,
        repo_id: str,
        symbol_type: str,
        symbol_name: str,
        fqn: str,
        file_ref: str = "",
        start_line: int = 0,
        end_line: int = 0,
        semantic_type: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        if symbol_type not in _VALID_SYMBOL_TYPES:
            raise ValueError(f"invalid symbol_type: {symbol_type}")
        sid = str(uuid.uuid4())
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO semantic_symbols
                        (id, repo_id, symbol_type, symbol_name, fqn, file_ref,
                         start_line, end_line, semantic_type, metadata_json, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        sid, repo_id, symbol_type, symbol_name, fqn, file_ref,
                        start_line, end_line, semantic_type,
                        json.dumps(metadata or {}, sort_keys=True),
                        _now_iso(),
                    ),
                )
        return sid

    def _insert_reference(
        self,
        repo_id: str,
        reference_kind: str,
        source_symbol_id: str = "",
        target_symbol_id: str = "",
        target_fqn: str = "",
        file_ref: str = "",
        line_number: int = 0,
    ) -> str:
        if reference_kind not in _VALID_REFERENCE_KINDS:
            raise ValueError(f"invalid reference_kind: {reference_kind}")
        rid = str(uuid.uuid4())
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO semantic_references
                        (id, repo_id, source_symbol_id, target_symbol_id,
                         target_fqn, reference_kind, file_ref, line_number, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        rid, repo_id, source_symbol_id, target_symbol_id,
                        target_fqn, reference_kind, file_ref, line_number,
                        _now_iso(),
                    ),
                )
        return rid

    # ------------------------------------------------------------------
    # Python AST-based symbol extraction
    # ------------------------------------------------------------------

    def parse_python_semantic(
        self, repo_id: str, root_path: str
    ) -> Dict[str, Any]:
        """Walk Python files, extract classes/functions/module-level assigns,
        and extract call/inherit/import references."""
        root = Path(root_path)
        if not root.exists():
            raise ValueError(f"root_path does not exist: {root_path}")

        symbols_inserted = 0
        refs_inserted = 0
        files_scanned = 0
        # fqn -> symbol_id (for current repo) so calls/inherits can resolve locally.
        local_fqns: Dict[str, str] = {}

        py_files: List[Path] = []
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
            for fn in filenames:
                if fn.endswith(".py"):
                    py_files.append(Path(dirpath) / fn)

        # First pass: register all module-level classes & functions so later
        # refs can resolve.
        file_trees: List[Tuple[Path, ast.AST, str]] = []
        for pyf in py_files:
            try:
                src = pyf.read_text(encoding="utf-8", errors="replace")
                tree = ast.parse(src, filename=str(pyf))
            except (SyntaxError, ValueError, OSError) as exc:
                _logger.debug("skip python file %s: %s", pyf, exc)
                continue
            files_scanned += 1
            rel = str(pyf.relative_to(root)) if pyf.is_absolute() else str(pyf)
            module_fqn = rel.replace(os.sep, ".").removesuffix(".py")
            file_trees.append((pyf, tree, module_fqn))

            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef):
                    fqn = f"{module_fqn}.{node.name}"
                    meta = {"bases": [self._ast_name(b) for b in node.bases]}
                    sid = self._insert_symbol(
                        repo_id,
                        "class",
                        node.name,
                        fqn,
                        file_ref=rel,
                        start_line=node.lineno,
                        end_line=getattr(node, "end_lineno", node.lineno) or node.lineno,
                        semantic_type="class",
                        metadata=meta,
                    )
                    local_fqns[fqn] = sid
                    local_fqns[node.name] = sid
                    symbols_inserted += 1
                elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    # only module-level funcs for this pass; method fqns below
                    pass
                elif isinstance(node, ast.Assign):
                    # module-level consts
                    for tgt in node.targets:
                        if isinstance(tgt, ast.Name):
                            fqn = f"{module_fqn}.{tgt.id}"
                            sid = self._insert_symbol(
                                repo_id,
                                "variable",
                                tgt.id,
                                fqn,
                                file_ref=rel,
                                start_line=node.lineno,
                                end_line=getattr(node, "end_lineno", node.lineno) or node.lineno,
                                semantic_type="variable",
                            )
                            local_fqns[fqn] = sid
                            symbols_inserted += 1

            # functions (module-level + methods)
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    fqn = f"{module_fqn}.{node.name}"
                    meta = {"args": [a.arg for a in node.args.args]}
                    sid = self._insert_symbol(
                        repo_id,
                        "function",
                        node.name,
                        fqn,
                        file_ref=rel,
                        start_line=node.lineno,
                        end_line=getattr(node, "end_lineno", node.lineno) or node.lineno,
                        semantic_type="function",
                        metadata=meta,
                    )
                    local_fqns[fqn] = sid
                    symbols_inserted += 1

        # Second pass: references.
        for pyf, tree, module_fqn in file_trees:
            rel = str(pyf.relative_to(root)) if pyf.is_absolute() else str(pyf)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    name = self._ast_name(node.func)
                    if name:
                        target_sid = local_fqns.get(name, "")
                        self._insert_reference(
                            repo_id,
                            "call",
                            target_symbol_id=target_sid,
                            target_fqn=name,
                            file_ref=rel,
                            line_number=node.lineno,
                        )
                        refs_inserted += 1
                elif isinstance(node, ast.ClassDef):
                    for base in node.bases:
                        bname = self._ast_name(base)
                        if not bname:
                            continue
                        self._insert_reference(
                            repo_id,
                            "inherit",
                            target_symbol_id=local_fqns.get(bname, ""),
                            target_fqn=bname,
                            file_ref=rel,
                            line_number=node.lineno,
                        )
                        refs_inserted += 1
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        self._insert_reference(
                            repo_id,
                            "import",
                            target_fqn=alias.name,
                            file_ref=rel,
                            line_number=node.lineno,
                        )
                        refs_inserted += 1
                elif isinstance(node, ast.ImportFrom):
                    mod = node.module or ""
                    for alias in node.names:
                        self._insert_reference(
                            repo_id,
                            "import",
                            target_fqn=f"{mod}.{alias.name}" if mod else alias.name,
                            file_ref=rel,
                            line_number=node.lineno,
                        )
                        refs_inserted += 1

        self._update_repo_meta(repo_id, parser_used="python_ast")
        self._emit_event(repo_id, "semantic_parsed_python")
        return {
            "repo_id": repo_id,
            "files_scanned": files_scanned,
            "symbols_inserted": symbols_inserted,
            "references_inserted": refs_inserted,
        }

    # ------------------------------------------------------------------
    # tree-sitter helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _ts_text(src: bytes, node: Any) -> str:
        """Extract source slice for a tree-sitter node."""
        if node is None:
            return ""
        try:
            return src[node.start_byte:node.end_byte].decode("utf-8", "replace")
        except Exception:
            return ""

    @classmethod
    def _ts_field(cls, src: bytes, node: Any, field: str) -> str:
        """Read a named child field via child_by_field_name and return text."""
        if node is None:
            return ""
        try:
            child = node.child_by_field_name(field)
        except Exception:
            child = None
        return cls._ts_text(src, child) if child else ""

    @staticmethod
    def _ts_walk(node: Any):
        """Recursive node iterator (depth-first, pre-order)."""
        if node is None:
            return
        stack = [node]
        while stack:
            n = stack.pop()
            yield n
            # Reverse so visitation order is left-to-right
            stack.extend(reversed(list(n.children)))

    def _ts_collect_files(self, root: Path, exts: Tuple[str, ...]) -> List[Path]:
        out: List[Path] = []
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
            for fn in filenames:
                if fn.endswith(exts):
                    out.append(Path(dirpath) / fn)
        return out

    def _ts_parse_file(
        self, parser_key: str, file_path: Path
    ) -> Optional[Tuple[bytes, Any]]:
        parser = _TS_PARSERS.get(parser_key)
        if parser is None:
            return None
        try:
            src = file_path.read_bytes()
        except OSError as exc:
            _logger.debug("ts read fail %s: %s", file_path, exc)
            return None
        try:
            tree = parser.parse(src)
        except Exception as exc:  # pragma: no cover
            _logger.debug("ts parse fail %s: %s", file_path, exc)
            return None
        return src, tree

    # ------------------------------------------------------------------
    # TypeScript / TSX semantic parser
    # ------------------------------------------------------------------

    def parse_typescript_semantic(
        self, repo_id: str, root_path: str
    ) -> Dict[str, Any]:
        """Parse TypeScript / TSX files via tree-sitter and persist symbols
        and references (call / inherit / implement / import)."""
        if not _TS_AVAILABLE or "typescript" not in _TS_PARSERS:
            raise NotImplementedError(
                "parse_typescript_semantic requires tree-sitter-typescript bundle"
            )

        root = Path(root_path)
        if not root.exists():
            raise ValueError(f"root_path does not exist: {root_path}")

        symbols_inserted = 0
        refs_inserted = 0
        files_scanned = 0
        local_fqns: Dict[str, str] = {}

        files = self._ts_collect_files(root, (".ts", ".tsx", ".mts", ".cts"))

        # First pass: register all top-level symbols.
        parsed: List[Tuple[Path, str, bytes, Any]] = []
        for fp in files:
            parser_key = "tsx" if fp.suffix == ".tsx" else "typescript"
            res = self._ts_parse_file(parser_key, fp)
            if res is None:
                continue
            src, tree = res
            files_scanned += 1
            rel = str(fp.relative_to(root)) if fp.is_absolute() else str(fp)
            module_fqn = rel.replace(os.sep, "/").rsplit(".", 1)[0]
            parsed.append((fp, rel, src, tree))

            for n in self._ts_walk(tree.root_node):
                t = n.type
                if t == "class_declaration":
                    name = self._ts_field(src, n, "name")
                    if not name:
                        continue
                    fqn = f"{module_fqn}::{name}"
                    bases: List[str] = []
                    for ch in n.children:
                        if ch.type == "class_heritage":
                            for sub in ch.children:
                                if sub.type in ("extends_clause", "implements_clause"):
                                    for id_node in sub.children:
                                        if id_node.type in (
                                            "identifier", "type_identifier",
                                        ):
                                            bases.append(self._ts_text(src, id_node))
                    sid = self._insert_symbol(
                        repo_id, "class", name, fqn,
                        file_ref=rel,
                        start_line=n.start_point[0] + 1,
                        end_line=n.end_point[0] + 1,
                        semantic_type="class",
                        metadata={"bases": bases, "language": "typescript"},
                    )
                    local_fqns[fqn] = sid
                    local_fqns[name] = sid
                    symbols_inserted += 1
                elif t == "interface_declaration":
                    name = self._ts_field(src, n, "name")
                    if not name:
                        continue
                    fqn = f"{module_fqn}::{name}"
                    sid = self._insert_symbol(
                        repo_id, "interface", name, fqn,
                        file_ref=rel,
                        start_line=n.start_point[0] + 1,
                        end_line=n.end_point[0] + 1,
                        semantic_type="interface",
                        metadata={"language": "typescript"},
                    )
                    local_fqns[fqn] = sid
                    local_fqns[name] = sid
                    symbols_inserted += 1
                elif t == "type_alias_declaration":
                    name = self._ts_field(src, n, "name")
                    if not name:
                        continue
                    fqn = f"{module_fqn}::{name}"
                    sid = self._insert_symbol(
                        repo_id, "type_alias", name, fqn,
                        file_ref=rel,
                        start_line=n.start_point[0] + 1,
                        end_line=n.end_point[0] + 1,
                        semantic_type="type_alias",
                        metadata={"language": "typescript"},
                    )
                    local_fqns[fqn] = sid
                    symbols_inserted += 1
                elif t == "function_declaration":
                    name = self._ts_field(src, n, "name")
                    if not name:
                        continue
                    fqn = f"{module_fqn}::{name}"
                    params: List[str] = []
                    for ch in n.children:
                        if ch.type == "formal_parameters":
                            for sub in ch.children:
                                if sub.type == "required_parameter":
                                    params.append(
                                        self._ts_field(src, sub, "pattern")
                                        or self._ts_text(src, sub)
                                    )
                    sid = self._insert_symbol(
                        repo_id, "function", name, fqn,
                        file_ref=rel,
                        start_line=n.start_point[0] + 1,
                        end_line=n.end_point[0] + 1,
                        semantic_type="function",
                        metadata={"params": params, "language": "typescript"},
                    )
                    local_fqns[fqn] = sid
                    local_fqns[name] = sid
                    symbols_inserted += 1
                elif t == "variable_declarator":
                    name = self._ts_field(src, n, "name")
                    if not name:
                        continue
                    fqn = f"{module_fqn}::{name}"
                    sid = self._insert_symbol(
                        repo_id, "variable", name, fqn,
                        file_ref=rel,
                        start_line=n.start_point[0] + 1,
                        end_line=n.end_point[0] + 1,
                        semantic_type="variable",
                        metadata={"language": "typescript"},
                    )
                    local_fqns[fqn] = sid
                    symbols_inserted += 1

        # Second pass: references (calls, imports, inheritance).
        for _fp, rel, src, tree in parsed:
            for n in self._ts_walk(tree.root_node):
                t = n.type
                if t == "call_expression":
                    fn_node = n.child_by_field_name("function")
                    fn_name = self._ts_text(src, fn_node) if fn_node else ""
                    if fn_name:
                        self._insert_reference(
                            repo_id, "call",
                            target_symbol_id=local_fqns.get(fn_name, ""),
                            target_fqn=fn_name,
                            file_ref=rel,
                            line_number=n.start_point[0] + 1,
                        )
                        refs_inserted += 1
                elif t == "new_expression":
                    # `new Foo()` — treat as call against a class name.
                    ident = None
                    for ch in n.children:
                        if ch.type in ("identifier", "type_identifier"):
                            ident = ch
                            break
                    if ident is not None:
                        cname = self._ts_text(src, ident)
                        self._insert_reference(
                            repo_id, "call",
                            target_symbol_id=local_fqns.get(cname, ""),
                            target_fqn=cname,
                            file_ref=rel,
                            line_number=n.start_point[0] + 1,
                        )
                        refs_inserted += 1
                elif t == "extends_clause":
                    for ch in n.children:
                        if ch.type in ("identifier", "type_identifier"):
                            base = self._ts_text(src, ch)
                            self._insert_reference(
                                repo_id, "inherit",
                                target_symbol_id=local_fqns.get(base, ""),
                                target_fqn=base,
                                file_ref=rel,
                                line_number=n.start_point[0] + 1,
                            )
                            refs_inserted += 1
                elif t == "implements_clause":
                    for ch in n.children:
                        if ch.type in ("identifier", "type_identifier"):
                            iface = self._ts_text(src, ch)
                            self._insert_reference(
                                repo_id, "implement",
                                target_symbol_id=local_fqns.get(iface, ""),
                                target_fqn=iface,
                                file_ref=rel,
                                line_number=n.start_point[0] + 1,
                            )
                            refs_inserted += 1
                elif t == "import_statement":
                    src_node = n.child_by_field_name("source")
                    module = self._ts_text(src, src_node).strip("'\"") if src_node else ""
                    if module:
                        self._insert_reference(
                            repo_id, "import",
                            target_fqn=module,
                            file_ref=rel,
                            line_number=n.start_point[0] + 1,
                        )
                        refs_inserted += 1

        self._update_repo_meta(repo_id, parser_used="tree_sitter_typescript")
        self._emit_event(repo_id, "semantic_parsed_typescript")
        return {
            "repo_id": repo_id,
            "files_scanned": files_scanned,
            "symbols_inserted": symbols_inserted,
            "references_inserted": refs_inserted,
        }

    # ------------------------------------------------------------------
    # Java semantic parser
    # ------------------------------------------------------------------

    def parse_java_semantic(
        self, repo_id: str, root_path: str
    ) -> Dict[str, Any]:
        """Parse Java sources via tree-sitter."""
        if not _TS_AVAILABLE or "java" not in _TS_PARSERS:
            raise NotImplementedError(
                "parse_java_semantic requires tree-sitter-java bundle"
            )

        root = Path(root_path)
        if not root.exists():
            raise ValueError(f"root_path does not exist: {root_path}")

        symbols_inserted = 0
        refs_inserted = 0
        files_scanned = 0
        local_fqns: Dict[str, str] = {}

        files = self._ts_collect_files(root, (".java",))

        parsed: List[Tuple[Path, str, bytes, Any, str]] = []
        for fp in files:
            res = self._ts_parse_file("java", fp)
            if res is None:
                continue
            src, tree = res
            files_scanned += 1
            rel = str(fp.relative_to(root)) if fp.is_absolute() else str(fp)
            # Resolve the package declaration to use as fqn prefix.
            package = ""
            for n in tree.root_node.children:
                if n.type == "package_declaration":
                    for sub in n.children:
                        if sub.type in ("scoped_identifier", "identifier"):
                            package = self._ts_text(src, sub)
                            break
                    break
            parsed.append((fp, rel, src, tree, package))

            for n in self._ts_walk(tree.root_node):
                t = n.type
                if t == "class_declaration":
                    name = self._ts_field(src, n, "name")
                    if not name:
                        continue
                    fqn = f"{package}.{name}" if package else name
                    bases: List[str] = []
                    for ch in n.children:
                        if ch.type == "superclass":
                            for sub in ch.children:
                                if sub.type in ("type_identifier", "identifier"):
                                    bases.append(self._ts_text(src, sub))
                        elif ch.type == "super_interfaces":
                            for sub in ch.children:
                                if sub.type == "type_list":
                                    for ti in sub.children:
                                        if ti.type == "type_identifier":
                                            bases.append(self._ts_text(src, ti))
                    sid = self._insert_symbol(
                        repo_id, "class", name, fqn,
                        file_ref=rel,
                        start_line=n.start_point[0] + 1,
                        end_line=n.end_point[0] + 1,
                        semantic_type="class",
                        metadata={"bases": bases, "package": package, "language": "java"},
                    )
                    local_fqns[fqn] = sid
                    local_fqns[name] = sid
                    symbols_inserted += 1
                elif t == "interface_declaration":
                    name = self._ts_field(src, n, "name")
                    if not name:
                        continue
                    fqn = f"{package}.{name}" if package else name
                    sid = self._insert_symbol(
                        repo_id, "interface", name, fqn,
                        file_ref=rel,
                        start_line=n.start_point[0] + 1,
                        end_line=n.end_point[0] + 1,
                        semantic_type="interface",
                        metadata={"package": package, "language": "java"},
                    )
                    local_fqns[fqn] = sid
                    local_fqns[name] = sid
                    symbols_inserted += 1
                elif t == "method_declaration":
                    mname = self._ts_field(src, n, "name")
                    if not mname:
                        continue
                    # qualify method by enclosing class if any
                    parent_class = ""
                    cur = n.parent
                    while cur is not None:
                        if cur.type in (
                            "class_declaration", "interface_declaration",
                        ):
                            parent_class = self._ts_field(src, cur, "name") or ""
                            break
                        cur = cur.parent
                    parts = [package, parent_class, mname]
                    fqn = ".".join([p for p in parts if p])
                    sid = self._insert_symbol(
                        repo_id, "function", mname, fqn,
                        file_ref=rel,
                        start_line=n.start_point[0] + 1,
                        end_line=n.end_point[0] + 1,
                        semantic_type="method",
                        metadata={
                            "package": package,
                            "owner": parent_class,
                            "language": "java",
                        },
                    )
                    local_fqns[fqn] = sid
                    local_fqns[mname] = sid
                    symbols_inserted += 1
                elif t == "field_declaration":
                    # field_declaration -> variable_declarator -> name
                    for ch in n.children:
                        if ch.type == "variable_declarator":
                            fname = self._ts_field(src, ch, "name")
                            if not fname:
                                continue
                            parent_class = ""
                            cur = n.parent
                            while cur is not None:
                                if cur.type in (
                                    "class_declaration", "interface_declaration",
                                ):
                                    parent_class = self._ts_field(src, cur, "name") or ""
                                    break
                                cur = cur.parent
                            fqn = ".".join(
                                [p for p in (package, parent_class, fname) if p]
                            )
                            sid = self._insert_symbol(
                                repo_id, "variable", fname, fqn,
                                file_ref=rel,
                                start_line=n.start_point[0] + 1,
                                end_line=n.end_point[0] + 1,
                                semantic_type="field",
                                metadata={
                                    "package": package,
                                    "owner": parent_class,
                                    "language": "java",
                                },
                            )
                            local_fqns[fqn] = sid
                            symbols_inserted += 1

        # Second pass: references.
        for _fp, rel, src, tree, package in parsed:
            for n in self._ts_walk(tree.root_node):
                t = n.type
                if t == "method_invocation":
                    name_node = n.child_by_field_name("name")
                    obj_node = n.child_by_field_name("object")
                    mname = self._ts_text(src, name_node) if name_node else ""
                    obj = self._ts_text(src, obj_node) if obj_node else ""
                    if mname:
                        target = f"{obj}.{mname}" if obj else mname
                        self._insert_reference(
                            repo_id, "call",
                            target_symbol_id=local_fqns.get(mname, ""),
                            target_fqn=target,
                            file_ref=rel,
                            line_number=n.start_point[0] + 1,
                        )
                        refs_inserted += 1
                elif t == "object_creation_expression":
                    type_node = n.child_by_field_name("type")
                    cname = self._ts_text(src, type_node) if type_node else ""
                    if cname:
                        self._insert_reference(
                            repo_id, "call",
                            target_symbol_id=local_fqns.get(cname, ""),
                            target_fqn=cname,
                            file_ref=rel,
                            line_number=n.start_point[0] + 1,
                        )
                        refs_inserted += 1
                elif t == "superclass":
                    for ch in n.children:
                        if ch.type == "type_identifier":
                            base = self._ts_text(src, ch)
                            self._insert_reference(
                                repo_id, "inherit",
                                target_symbol_id=local_fqns.get(base, ""),
                                target_fqn=base,
                                file_ref=rel,
                                line_number=n.start_point[0] + 1,
                            )
                            refs_inserted += 1
                elif t == "super_interfaces":
                    for ch in n.children:
                        if ch.type == "type_list":
                            for ti in ch.children:
                                if ti.type == "type_identifier":
                                    iface = self._ts_text(src, ti)
                                    self._insert_reference(
                                        repo_id, "implement",
                                        target_symbol_id=local_fqns.get(iface, ""),
                                        target_fqn=iface,
                                        file_ref=rel,
                                        line_number=n.start_point[0] + 1,
                                    )
                                    refs_inserted += 1
                elif t == "import_declaration":
                    # Whole text minus 'import' keyword and trailing ';'
                    txt = self._ts_text(src, n)
                    cleaned = (
                        txt.replace("import", "", 1)
                           .replace("static", "")
                           .strip()
                           .rstrip(";")
                           .strip()
                    )
                    if cleaned:
                        self._insert_reference(
                            repo_id, "import",
                            target_fqn=cleaned,
                            file_ref=rel,
                            line_number=n.start_point[0] + 1,
                        )
                        refs_inserted += 1

        self._update_repo_meta(repo_id, parser_used="tree_sitter_java")
        self._emit_event(repo_id, "semantic_parsed_java")
        return {
            "repo_id": repo_id,
            "files_scanned": files_scanned,
            "symbols_inserted": symbols_inserted,
            "references_inserted": refs_inserted,
        }

    # ------------------------------------------------------------------
    # Go semantic parser
    # ------------------------------------------------------------------

    def parse_go_semantic(
        self, repo_id: str, root_path: str
    ) -> Dict[str, Any]:
        """Parse Go sources via tree-sitter."""
        if not _TS_AVAILABLE or "go" not in _TS_PARSERS:
            raise NotImplementedError(
                "parse_go_semantic requires tree-sitter-go bundle"
            )

        root = Path(root_path)
        if not root.exists():
            raise ValueError(f"root_path does not exist: {root_path}")

        symbols_inserted = 0
        refs_inserted = 0
        files_scanned = 0
        local_fqns: Dict[str, str] = {}

        files = self._ts_collect_files(root, (".go",))

        parsed: List[Tuple[Path, str, bytes, Any, str]] = []
        for fp in files:
            res = self._ts_parse_file("go", fp)
            if res is None:
                continue
            src, tree = res
            files_scanned += 1
            rel = str(fp.relative_to(root)) if fp.is_absolute() else str(fp)
            # Find package name.
            package = ""
            for n in tree.root_node.children:
                if n.type == "package_clause":
                    for sub in n.children:
                        if sub.type == "package_identifier":
                            package = self._ts_text(src, sub)
                            break
                    break
            parsed.append((fp, rel, src, tree, package))

            for n in self._ts_walk(tree.root_node):
                t = n.type
                if t == "function_declaration":
                    fname = self._ts_field(src, n, "name")
                    if not fname:
                        continue
                    fqn = f"{package}.{fname}" if package else fname
                    sid = self._insert_symbol(
                        repo_id, "function", fname, fqn,
                        file_ref=rel,
                        start_line=n.start_point[0] + 1,
                        end_line=n.end_point[0] + 1,
                        semantic_type="function",
                        metadata={"package": package, "language": "go"},
                    )
                    local_fqns[fqn] = sid
                    local_fqns[fname] = sid
                    symbols_inserted += 1
                elif t == "method_declaration":
                    mname = self._ts_field(src, n, "name")
                    if not mname:
                        continue
                    # Receiver type → owner
                    owner = ""
                    recv = n.child_by_field_name("receiver")
                    if recv is not None:
                        for ch in recv.children:
                            if ch.type == "parameter_declaration":
                                for sub in ch.children:
                                    if sub.type == "type_identifier":
                                        owner = self._ts_text(src, sub)
                                    elif sub.type == "pointer_type":
                                        for px in sub.children:
                                            if px.type == "type_identifier":
                                                owner = self._ts_text(src, px)
                    parts = [package, owner, mname]
                    fqn = ".".join([p for p in parts if p])
                    sid = self._insert_symbol(
                        repo_id, "function", mname, fqn,
                        file_ref=rel,
                        start_line=n.start_point[0] + 1,
                        end_line=n.end_point[0] + 1,
                        semantic_type="method",
                        metadata={
                            "package": package,
                            "owner": owner,
                            "language": "go",
                        },
                    )
                    local_fqns[fqn] = sid
                    local_fqns[mname] = sid
                    symbols_inserted += 1
                elif t == "type_spec":
                    tname = self._ts_field(src, n, "name")
                    if not tname:
                        continue
                    fqn = f"{package}.{tname}" if package else tname
                    body_kind = ""
                    for ch in n.children:
                        if ch.type == "struct_type":
                            body_kind = "struct"
                            break
                        elif ch.type == "interface_type":
                            body_kind = "interface"
                            break
                    sym_kind = "interface" if body_kind == "interface" else "class"
                    sid = self._insert_symbol(
                        repo_id, sym_kind, tname, fqn,
                        file_ref=rel,
                        start_line=n.start_point[0] + 1,
                        end_line=n.end_point[0] + 1,
                        semantic_type=body_kind or "type",
                        metadata={"package": package, "language": "go"},
                    )
                    local_fqns[fqn] = sid
                    local_fqns[tname] = sid
                    symbols_inserted += 1

        for _fp, rel, src, tree, _pkg in parsed:
            for n in self._ts_walk(tree.root_node):
                t = n.type
                if t == "call_expression":
                    fn_node = n.child_by_field_name("function")
                    target = self._ts_text(src, fn_node) if fn_node else ""
                    if target:
                        # short_name is rightmost identifier
                        short = target.rsplit(".", 1)[-1]
                        self._insert_reference(
                            repo_id, "call",
                            target_symbol_id=local_fqns.get(short, ""),
                            target_fqn=target,
                            file_ref=rel,
                            line_number=n.start_point[0] + 1,
                        )
                        refs_inserted += 1
                elif t == "import_spec":
                    p_node = n.child_by_field_name("path")
                    if p_node is None:
                        # path is interpreted_string_literal child
                        for ch in n.children:
                            if ch.type == "interpreted_string_literal":
                                p_node = ch
                                break
                    if p_node is not None:
                        path = self._ts_text(src, p_node).strip('"')
                        if path:
                            self._insert_reference(
                                repo_id, "import",
                                target_fqn=path,
                                file_ref=rel,
                                line_number=n.start_point[0] + 1,
                            )
                            refs_inserted += 1

        self._update_repo_meta(repo_id, parser_used="tree_sitter_go")
        self._emit_event(repo_id, "semantic_parsed_go")
        return {
            "repo_id": repo_id,
            "files_scanned": files_scanned,
            "symbols_inserted": symbols_inserted,
            "references_inserted": refs_inserted,
        }

    # ------------------------------------------------------------------
    # Drizzle ORM schema parser (TypeScript files using drizzle-orm)
    # ------------------------------------------------------------------

    def parse_drizzle_schema(
        self, repo_id: str, root_path: str
    ) -> Dict[str, Any]:
        """Parse Drizzle ORM TypeScript schema files. Detects pgTable/mysqlTable/
        sqliteTable declarations and extracts model name + field list."""
        if not _TS_AVAILABLE or "typescript" not in _TS_PARSERS:
            raise NotImplementedError(
                "parse_drizzle_schema requires tree-sitter-typescript bundle"
            )

        root = Path(root_path)
        if not root.exists():
            raise ValueError(f"root_path does not exist: {root_path}")

        models_inserted = 0
        files_scanned = 0
        table_helpers = {"pgTable", "mysqlTable", "sqliteTable"}

        # If root_path is itself a file, parse just that file.
        if root.is_file():
            files = [root]
        else:
            files = self._ts_collect_files(root, (".ts", ".tsx", ".mts", ".cts"))

        for fp in files:
            parser_key = "tsx" if fp.suffix == ".tsx" else "typescript"
            res = self._ts_parse_file(parser_key, fp)
            if res is None:
                continue
            src, tree = res
            files_scanned += 1
            rel = (
                str(fp.relative_to(root))
                if not root.is_file() and fp.is_absolute()
                else fp.name
            )

            for n in self._ts_walk(tree.root_node):
                if n.type != "variable_declarator":
                    continue
                model_name = self._ts_field(src, n, "name")
                value = n.child_by_field_name("value")
                if not model_name or value is None or value.type != "call_expression":
                    continue
                fn_node = value.child_by_field_name("function")
                fn_text = self._ts_text(src, fn_node) if fn_node else ""
                # Allow `pgTable(...)` or `drizzle.pgTable(...)`.
                fn_short = fn_text.rsplit(".", 1)[-1]
                if fn_short not in table_helpers:
                    continue

                args_node = value.child_by_field_name("arguments")
                if args_node is None:
                    continue

                table_name = ""
                fields_obj = None
                non_punct = [
                    c for c in args_node.children
                    if c.type not in ("(", ")", ",")
                ]
                if non_punct:
                    a0 = non_punct[0]
                    if a0.type == "string":
                        table_name = self._ts_text(src, a0).strip("'\"")
                if len(non_punct) >= 2:
                    fields_obj = non_punct[1]

                fields: List[Dict[str, Any]] = []
                relationships: List[Dict[str, Any]] = []

                if fields_obj is not None and fields_obj.type == "object":
                    for pair in fields_obj.children:
                        if pair.type != "pair":
                            continue
                        k = pair.child_by_field_name("key")
                        v = pair.child_by_field_name("value")
                        if k is None or v is None:
                            continue
                        fname = self._ts_text(src, k).strip("'\"")
                        vtxt = self._ts_text(src, v)
                        # Determine column type from leftmost call's function name.
                        ftype = ""
                        # walk down call_expressions until we find the leftmost
                        # call function identifier.
                        for sub in self._ts_walk(v):
                            if sub.type == "call_expression":
                                fn2 = sub.child_by_field_name("function")
                                fn2t = self._ts_text(src, fn2) if fn2 else ""
                                if fn2t and "." not in fn2t:
                                    ftype = fn2t
                                    break
                                # nested member like `x.references` - skip references markers
                                short = fn2t.rsplit(".", 1)[-1]
                                if short not in (
                                    "primaryKey", "notNull", "default",
                                    "unique", "references", "defaultNow",
                                ):
                                    ftype = short
                                    break
                        entry: Dict[str, Any] = {"name": fname, "type": ftype}
                        if "primaryKey" in vtxt:
                            entry["primary_key"] = True
                        if "notNull" in vtxt:
                            entry["not_null"] = True
                        if ".references(" in vtxt:
                            relationships.append(
                                {"name": fname, "target": "", "kind": "fk"}
                            )
                        fields.append(entry)

                self._insert_orm_model(
                    repo_id, "drizzle", table_name or model_name,
                    file_ref=rel,
                    fields=fields,
                    relationships=relationships,
                )
                models_inserted += 1

        self._update_repo_meta(repo_id, parser_used="tree_sitter_drizzle")
        self._emit_event(repo_id, "semantic_parsed_drizzle")
        return {
            "repo_id": repo_id,
            "orm_framework": "drizzle",
            "models_inserted": models_inserted,
            "files_scanned": files_scanned,
        }

    # ------------------------------------------------------------------
    # SQLAlchemy detector (stdlib ast)
    # ------------------------------------------------------------------

    def parse_sqlalchemy_schema(
        self, repo_id: str, root_path: str
    ) -> Dict[str, Any]:
        """Detect SQLAlchemy models: classes whose base list includes Base or
        declarative_base() or uses ``__tablename__`` / ``Column`` attributes."""
        root = Path(root_path)
        if not root.exists():
            raise ValueError(f"root_path does not exist: {root_path}")
        models_inserted = 0
        files_scanned = 0

        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
            for fn in filenames:
                if not fn.endswith(".py"):
                    continue
                p = Path(dirpath) / fn
                try:
                    src = p.read_text(encoding="utf-8", errors="replace")
                    tree = ast.parse(src, filename=str(p))
                except (SyntaxError, OSError, ValueError):
                    continue
                files_scanned += 1
                rel = str(p.relative_to(root)) if p.is_absolute() else str(p)
                for node in tree.body:
                    if not isinstance(node, ast.ClassDef):
                        continue
                    base_names = [self._ast_name(b) for b in node.bases]
                    is_sa = any(
                        bn and bn in ("Base", "DeclarativeBase")
                        or (bn and bn.endswith(".Base"))
                        for bn in base_names
                    )
                    has_tablename = any(
                        isinstance(n, ast.Assign)
                        and any(
                            isinstance(t, ast.Name) and t.id == "__tablename__"
                            for t in n.targets
                        )
                        for n in node.body
                    )
                    has_column = any(
                        isinstance(n, ast.Assign)
                        and isinstance(n.value, ast.Call)
                        and self._ast_name(n.value.func) in ("Column", "sqlalchemy.Column")
                        for n in node.body
                    )
                    if not (is_sa or has_tablename or has_column):
                        continue

                    fields: List[Dict[str, Any]] = []
                    relationships: List[Dict[str, Any]] = []
                    for stmt in node.body:
                        if not (
                            isinstance(stmt, ast.Assign)
                            and isinstance(stmt.value, ast.Call)
                        ):
                            continue
                        callee = self._ast_name(stmt.value.func) or ""
                        field_name = None
                        for t in stmt.targets:
                            if isinstance(t, ast.Name):
                                field_name = t.id
                                break
                        if not field_name:
                            continue
                        if callee.endswith("Column") or callee == "Column":
                            type_expr = ""
                            if stmt.value.args:
                                type_expr = self._ast_name(stmt.value.args[0]) or ""
                            fields.append(
                                {
                                    "name": field_name,
                                    "type": type_expr,
                                }
                            )
                        elif callee.endswith("relationship") or callee == "relationship":
                            tgt = ""
                            if stmt.value.args:
                                a0 = stmt.value.args[0]
                                if isinstance(a0, ast.Constant):
                                    tgt = str(a0.value)
                                else:
                                    tgt = self._ast_name(a0) or ""
                            relationships.append(
                                {
                                    "name": field_name,
                                    "target": tgt,
                                }
                            )
                    self._insert_orm_model(
                        repo_id,
                        "sqlalchemy",
                        node.name,
                        file_ref=rel,
                        fields=fields,
                        relationships=relationships,
                    )
                    models_inserted += 1

        self._update_repo_meta(repo_id, parser_used="sqlalchemy_ast")
        return {
            "repo_id": repo_id,
            "orm_framework": "sqlalchemy",
            "models_inserted": models_inserted,
            "files_scanned": files_scanned,
        }

    # ------------------------------------------------------------------
    # Django ORM detector (stdlib ast)
    # ------------------------------------------------------------------

    def parse_django_orm_schema(
        self, repo_id: str, root_path: str
    ) -> Dict[str, Any]:
        """Detect Django models: classes whose bases include models.Model."""
        root = Path(root_path)
        if not root.exists():
            raise ValueError(f"root_path does not exist: {root_path}")
        models_inserted = 0
        files_scanned = 0

        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
            for fn in filenames:
                if not fn.endswith(".py"):
                    continue
                p = Path(dirpath) / fn
                try:
                    src = p.read_text(encoding="utf-8", errors="replace")
                    tree = ast.parse(src, filename=str(p))
                except (SyntaxError, OSError, ValueError):
                    continue
                files_scanned += 1
                rel = str(p.relative_to(root)) if p.is_absolute() else str(p)

                for node in tree.body:
                    if not isinstance(node, ast.ClassDef):
                        continue
                    base_names = [self._ast_name(b) for b in node.bases]
                    is_django = any(
                        (bn or "").endswith("models.Model") or (bn or "") == "Model"
                        for bn in base_names
                    )
                    if not is_django:
                        continue

                    fields: List[Dict[str, Any]] = []
                    relationships: List[Dict[str, Any]] = []
                    for stmt in node.body:
                        if not (
                            isinstance(stmt, ast.Assign)
                            and isinstance(stmt.value, ast.Call)
                        ):
                            continue
                        field_name = None
                        for t in stmt.targets:
                            if isinstance(t, ast.Name):
                                field_name = t.id
                                break
                        if not field_name:
                            continue
                        callee = self._ast_name(stmt.value.func) or ""
                        # relationship field types
                        if callee.endswith(
                            ("ForeignKey", "OneToOneField", "ManyToManyField")
                        ):
                            tgt = ""
                            if stmt.value.args:
                                a0 = stmt.value.args[0]
                                if isinstance(a0, ast.Constant):
                                    tgt = str(a0.value)
                                else:
                                    tgt = self._ast_name(a0) or ""
                            relationships.append(
                                {
                                    "name": field_name,
                                    "target": tgt,
                                    "kind": callee.rsplit(".", 1)[-1],
                                }
                            )
                        elif callee:
                            fields.append(
                                {
                                    "name": field_name,
                                    "type": callee.rsplit(".", 1)[-1],
                                }
                            )
                    self._insert_orm_model(
                        repo_id,
                        "django_orm",
                        node.name,
                        file_ref=rel,
                        fields=fields,
                        relationships=relationships,
                    )
                    models_inserted += 1

        self._update_repo_meta(repo_id, parser_used="django_ast")
        return {
            "repo_id": repo_id,
            "orm_framework": "django_orm",
            "models_inserted": models_inserted,
            "files_scanned": files_scanned,
        }

    # ------------------------------------------------------------------
    # Prisma (tiny DSL parser)
    # ------------------------------------------------------------------

    _PRISMA_MODEL_RE = re.compile(
        r"^\s*model\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{([^}]*)\}",
        re.MULTILINE | re.DOTALL,
    )
    _PRISMA_FIELD_RE = re.compile(
        r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s+([A-Za-z_][A-Za-z0-9_\[\]\?]*)(?:\s+(@[^\n]+))?\s*$",
        re.MULTILINE,
    )
    _PRISMA_RELATION_RE = re.compile(r"@relation\(")

    def parse_prisma_schema(
        self, repo_id: str, schema_file_path: str
    ) -> Dict[str, Any]:
        """Parse a ``schema.prisma`` file — just the ``model X { ... }`` blocks.
        We DON'T depend on prisma CLI. Enough to extract model + field + types."""
        p = Path(schema_file_path)
        if not p.exists():
            raise ValueError(f"schema file does not exist: {schema_file_path}")
        text = p.read_text(encoding="utf-8", errors="replace")
        models_inserted = 0

        for m in self._PRISMA_MODEL_RE.finditer(text):
            name = m.group(1)
            body = m.group(2)
            fields: List[Dict[str, Any]] = []
            relationships: List[Dict[str, Any]] = []
            for fm in self._PRISMA_FIELD_RE.finditer(body):
                fname = fm.group(1)
                ftype = fm.group(2)
                attrs = fm.group(3) or ""
                # reserved block markers → skip
                if fname in ("@@id", "@@unique", "@@index", "@@map"):
                    continue
                entry = {"name": fname, "type": ftype}
                if attrs:
                    entry["attrs"] = attrs.strip()
                # @relation → relationship
                base_type = ftype.rstrip("[]?")
                # Heuristic: capitalized base_type that isn't a Prisma scalar is a model ref.
                scalar_types = {
                    "String", "Int", "BigInt", "Float", "Decimal", "Boolean",
                    "DateTime", "Json", "Bytes",
                }
                if (
                    self._PRISMA_RELATION_RE.search(attrs or "")
                    or (
                        base_type not in scalar_types
                        and base_type
                        and base_type[0].isupper()
                    )
                ):
                    relationships.append(
                        {
                            "name": fname,
                            "target": base_type,
                            "list": ftype.endswith("[]"),
                            "optional": ftype.endswith("?"),
                        }
                    )
                else:
                    fields.append(entry)
            self._insert_orm_model(
                repo_id,
                "prisma",
                name,
                file_ref=str(p.name),
                fields=fields,
                relationships=relationships,
            )
            models_inserted += 1

        self._update_repo_meta(repo_id, parser_used="prisma_dsl")
        return {
            "repo_id": repo_id,
            "orm_framework": "prisma",
            "models_inserted": models_inserted,
            "schema_file": str(p),
        }

    # ------------------------------------------------------------------
    # ORM insertion shared
    # ------------------------------------------------------------------

    def _insert_orm_model(
        self,
        repo_id: str,
        orm_framework: str,
        model_name: str,
        file_ref: str = "",
        fields: Optional[List[Dict[str, Any]]] = None,
        relationships: Optional[List[Dict[str, Any]]] = None,
    ) -> str:
        if orm_framework not in _VALID_ORM_FRAMEWORKS:
            raise ValueError(f"invalid orm_framework: {orm_framework}")
        mid = str(uuid.uuid4())
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO semantic_orm_schemas
                        (id, repo_id, orm_framework, model_name, file_ref,
                         fields_json, relationships_json, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        mid, repo_id, orm_framework, model_name, file_ref,
                        json.dumps(fields or [], sort_keys=True),
                        json.dumps(relationships or [], sort_keys=True),
                        _now_iso(),
                    ),
                )
        return mid

    # ------------------------------------------------------------------
    # Query API
    # ------------------------------------------------------------------

    def get_type_info(self, repo_id: str, fqn: str) -> Optional[Dict[str, Any]]:
        with self._conn() as conn:
            row = conn.execute(
                """
                SELECT id, symbol_type, symbol_name, fqn, semantic_type,
                       file_ref, start_line, end_line, metadata_json
                  FROM semantic_symbols
                 WHERE repo_id = ? AND fqn = ?
                 LIMIT 1
                """,
                (repo_id, fqn),
            ).fetchone()
        if not row:
            return None
        out = dict(row)
        out["metadata"] = json.loads(out.pop("metadata_json") or "{}")
        return out

    def find_references(
        self, repo_id: str, fqn: str
    ) -> List[Dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT id, source_symbol_id, target_symbol_id, target_fqn,
                       reference_kind, file_ref, line_number, created_at
                  FROM semantic_references
                 WHERE repo_id = ? AND target_fqn = ?
                 ORDER BY line_number ASC
                """,
                (repo_id, fqn),
            ).fetchall()
        return [dict(r) for r in rows]

    def list_symbols(
        self,
        repo_id: str,
        symbol_type: Optional[str] = None,
        limit: int = 500,
    ) -> List[Dict[str, Any]]:
        if symbol_type and symbol_type not in _VALID_SYMBOL_TYPES:
            raise ValueError(f"invalid symbol_type: {symbol_type}")
        with self._conn() as conn:
            if symbol_type:
                rows = conn.execute(
                    """
                    SELECT id, symbol_type, symbol_name, fqn, file_ref,
                           start_line, end_line, semantic_type
                      FROM semantic_symbols
                     WHERE repo_id = ? AND symbol_type = ?
                     ORDER BY symbol_name ASC
                     LIMIT ?
                    """,
                    (repo_id, symbol_type, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT id, symbol_type, symbol_name, fqn, file_ref,
                           start_line, end_line, semantic_type
                      FROM semantic_symbols
                     WHERE repo_id = ?
                     ORDER BY symbol_name ASC
                     LIMIT ?
                    """,
                    (repo_id, limit),
                ).fetchall()
        return [dict(r) for r in rows]

    def generate_erd(self, repo_id: str) -> Dict[str, Any]:
        """Produce ``{models: [...], relationships: [...]}`` from orm schemas."""
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT id, orm_framework, model_name, file_ref,
                       fields_json, relationships_json
                  FROM semantic_orm_schemas
                 WHERE repo_id = ?
                 ORDER BY orm_framework, model_name ASC
                """,
                (repo_id,),
            ).fetchall()
        models: List[Dict[str, Any]] = []
        relationships: List[Dict[str, Any]] = []
        for r in rows:
            row = dict(r)
            fields = json.loads(row.pop("fields_json") or "[]")
            rels = json.loads(row.pop("relationships_json") or "[]")
            models.append(
                {
                    "id": row["id"],
                    "framework": row["orm_framework"],
                    "name": row["model_name"],
                    "file_ref": row["file_ref"],
                    "fields": fields,
                }
            )
            for rel in rels:
                relationships.append(
                    {
                        "from": row["model_name"],
                        "to": rel.get("target", ""),
                        "name": rel.get("name", ""),
                        "list": rel.get("list", False),
                        "optional": rel.get("optional", False),
                        "framework": row["orm_framework"],
                    }
                )
        return {
            "repo_id": repo_id,
            "models": models,
            "relationships": relationships,
        }

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def stats(self, org_id: str) -> Dict[str, Any]:
        with self._conn() as conn:
            repos = conn.execute(
                "SELECT id FROM semantic_repos WHERE org_id = ?",
                (org_id,),
            ).fetchall()
            repo_ids = [r["id"] for r in repos]
            if not repo_ids:
                return {
                    "org_id": org_id,
                    "repos": 0,
                    "symbols": 0,
                    "references": 0,
                    "orm_models": 0,
                    "by_symbol_type": {},
                    "by_reference_kind": {},
                    "by_orm_framework": {},
                }
            q_in = ",".join(["?"] * len(repo_ids))

            symbols = conn.execute(
                f"SELECT COUNT(*) AS n FROM semantic_symbols WHERE repo_id IN ({q_in})",
                repo_ids,
            ).fetchone()["n"]
            refs = conn.execute(
                f"SELECT COUNT(*) AS n FROM semantic_references WHERE repo_id IN ({q_in})",
                repo_ids,
            ).fetchone()["n"]
            orms = conn.execute(
                f"SELECT COUNT(*) AS n FROM semantic_orm_schemas WHERE repo_id IN ({q_in})",
                repo_ids,
            ).fetchone()["n"]

            by_sym = {
                r["symbol_type"]: r["n"]
                for r in conn.execute(
                    f"""
                    SELECT symbol_type, COUNT(*) AS n
                      FROM semantic_symbols
                     WHERE repo_id IN ({q_in})
                     GROUP BY symbol_type
                    """,
                    repo_ids,
                ).fetchall()
            }
            by_ref = {
                r["reference_kind"]: r["n"]
                for r in conn.execute(
                    f"""
                    SELECT reference_kind, COUNT(*) AS n
                      FROM semantic_references
                     WHERE repo_id IN ({q_in})
                     GROUP BY reference_kind
                    """,
                    repo_ids,
                ).fetchall()
            }
            by_orm = {
                r["orm_framework"]: r["n"]
                for r in conn.execute(
                    f"""
                    SELECT orm_framework, COUNT(*) AS n
                      FROM semantic_orm_schemas
                     WHERE repo_id IN ({q_in})
                     GROUP BY orm_framework
                    """,
                    repo_ids,
                ).fetchall()
            }

        return {
            "org_id": org_id,
            "repos": len(repo_ids),
            "symbols": symbols,
            "references": refs,
            "orm_models": orms,
            "by_symbol_type": by_sym,
            "by_reference_kind": by_ref,
            "by_orm_framework": by_orm,
        }

    # ------------------------------------------------------------------
    # Public facade helpers for router
    # ------------------------------------------------------------------

    def parse_repo(
        self,
        org_id: str,
        repo_ref: str,
        root_path: str,
        language: str,
    ) -> Dict[str, Any]:
        repo = self._get_or_create_repo(org_id, repo_ref)
        repo_id = repo["id"]
        langs = self.detect_languages(root_path)
        self._update_repo_meta(repo_id, languages=langs["languages"])
        language = (language or "").lower()
        if language == "python":
            result = self.parse_python_semantic(repo_id, root_path)
        elif language == "typescript":
            result = self.parse_typescript_semantic(repo_id, root_path)
        elif language == "java":
            result = self.parse_java_semantic(repo_id, root_path)
        elif language == "go":
            result = self.parse_go_semantic(repo_id, root_path)
        else:
            raise ValueError(f"unsupported language: {language}")
        result["repo_ref"] = repo_ref
        result["languages"] = langs["languages"]
        return result

    def parse_orm(
        self,
        org_id: str,
        repo_ref: str,
        root_path: str,
        orm_framework: str,
    ) -> Dict[str, Any]:
        if orm_framework not in _VALID_ORM_FRAMEWORKS:
            raise ValueError(f"invalid orm_framework: {orm_framework}")
        repo = self._get_or_create_repo(org_id, repo_ref)
        repo_id = repo["id"]
        if orm_framework == "sqlalchemy":
            return self.parse_sqlalchemy_schema(repo_id, root_path)
        if orm_framework == "django_orm":
            return self.parse_django_orm_schema(repo_id, root_path)
        if orm_framework == "prisma":
            # root_path is the schema file here for prisma
            return self.parse_prisma_schema(repo_id, root_path)
        if orm_framework == "drizzle":
            return self.parse_drizzle_schema(repo_id, root_path)
        raise ValueError(f"unsupported orm_framework: {orm_framework}")

    def get_repo(
        self, org_id: str, repo_ref: str
    ) -> Optional[Dict[str, Any]]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM semantic_repos WHERE org_id = ? AND repo_ref = ?",
                (org_id, repo_ref),
            ).fetchone()
        if not row:
            return None
        out = dict(row)
        out["languages_detected"] = json.loads(out.pop("languages_detected_json") or "{}")
        out["parsers_used"] = json.loads(out.pop("parsers_used_json") or "[]")
        return out

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    @staticmethod
    def _ast_name(node: Any) -> str:
        """Flatten ast.Name / ast.Attribute into a dotted name."""
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            parts: List[str] = []
            cur: Any = node
            while isinstance(cur, ast.Attribute):
                parts.append(cur.attr)
                cur = cur.value
            if isinstance(cur, ast.Name):
                parts.append(cur.id)
            return ".".join(reversed(parts))
        if isinstance(node, ast.Call):
            return SemanticAnalyzerEngine._ast_name(node.func)
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        return ""

    def _emit_event(self, repo_id: str, kind: str) -> None:
        if _get_tg_bus is None:
            return
        try:
            bus = _get_tg_bus()
            if bus:
                bus.emit(
                    "SEMANTIC_REPO_UPDATED",
                    {
                        "entity_type": "semantic_repo",
                        "entity_id": str(repo_id),
                        "source_engine": "semantic_analyzer_engine",
                        "kind": kind,
                    },
                )
        except Exception:
            pass  # event emission should never break the main operation


__all__ = ["SemanticAnalyzerEngine"]
