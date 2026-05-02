"""Deep Code Analysis Engine — ALDECI (GAP-012, Apiiro DCA parity).

Walks a repo and extracts symbols, API endpoints, and data models using the
Python stdlib `ast` module. Seeds the API Discovery and Data Classification
engines with discovered artefacts.

Scope (v0):
  - Python (.py) — full AST extraction: classes, functions, FastAPI routes,
    Flask routes, Django URL hints, ORM data models, sensitive-field heuristics.
  - TypeScript / JavaScript / Java — STUBS that raise NotImplementedError.
    Tracking: NEW-G070.

Compliance: NIST SSDF PW.4.1, OWASP ASVS V1 (architecture, design, review).
"""

from __future__ import annotations

import ast
import json
import logging
import re
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Tree-sitter TypeScript — optional, imported lazily so the engine still
# works in environments where the native extension is unavailable.
# ---------------------------------------------------------------------------
try:
    import tree_sitter_typescript as _tst
    from tree_sitter import Language as _TSLanguage
    from tree_sitter import Parser as _TSParser

    _TS_LANGUAGE: Optional[Any] = _TSLanguage(_tst.language_typescript())
    _TSX_LANGUAGE: Optional[Any] = _TSLanguage(_tst.language_tsx())
except Exception:  # pragma: no cover — fallback when C extension missing
    _TS_LANGUAGE = None
    _TSX_LANGUAGE = None

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except ImportError:  # pragma: no cover - bus optional
    _get_tg_bus = None

_logger = logging.getLogger(__name__)

_DEFAULT_DATA_DIR = str(Path(__file__).resolve().parents[2] / ".fixops_data")

_HTTP_METHOD_DECORATORS = {"get", "post", "put", "patch", "delete", "head", "options"}
_ORM_BASE_HINTS = {
    "Base",
    "BaseModel",
    "Model",
    "declarative_base",
    "DeclarativeBase",
    "SQLModel",
    "TimestampedModel",
}

# Regex patterns for sensitive field detection
_SENSITIVE_FIELD_PATTERNS: Dict[str, re.Pattern[str]] = {
    "email": re.compile(r"(?i)(e[-_]?mail|email_address)"),
    "ssn": re.compile(r"(?i)(ssn|social_security|social_sec_num)"),
    "phone": re.compile(r"(?i)(phone|mobile|telephone|cell_number)"),
    "credit_card": re.compile(r"(?i)(credit_card|cc_number|card_number|cvv)"),
    "dob": re.compile(r"(?i)(dob|date_of_birth|birth_date|birthday)"),
    "passport": re.compile(r"(?i)(passport|national_id|id_number)"),
    "address": re.compile(r"(?i)(address|street|zip_code|postal_code)"),
    "name": re.compile(r"(?i)(first_name|last_name|full_name|given_name|surname)"),
    "api_key": re.compile(r"(?i)(api_key|secret_key|access_token|private_key)"),
    "password": re.compile(r"(?i)(password|passwd|hashed_password)"),
}

_SUPPORTED_EXTS_PY = {".py"}
_STUB_EXTS: Dict[str, str] = {
    ".ts": "typescript",
    ".tsx": "typescript",
    ".js": "javascript",
    ".jsx": "javascript",
    ".java": "java",
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def detect_sensitive_types(field_name: str) -> List[str]:
    """Return list of sensitive PII types matched by field name."""
    hits: List[str] = []
    for pii_type, pattern in _SENSITIVE_FIELD_PATTERNS.items():
        if pattern.search(field_name):
            hits.append(pii_type)
    return hits


class DeepCodeAnalysisEngine:
    """SQLite WAL-backed Deep Code Analysis engine.

    Thread-safe via RLock. Multi-tenant via org_id. Stdlib only.
    """

    def __init__(self, data_dir: Optional[str] = None) -> None:
        self._data_dir = Path(data_dir) if data_dir else Path(_DEFAULT_DATA_DIR)
        self._data_dir.mkdir(parents=True, exist_ok=True)
        self._db_path = str(self._data_dir / "dca.db")
        self._lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._lock, self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS dca_analyses (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    repo_ref        TEXT NOT NULL,
                    commit_sha      TEXT NOT NULL DEFAULT '',
                    analyzed_at     TEXT NOT NULL,
                    languages_json  TEXT NOT NULL DEFAULT '{}',
                    total_files     INTEGER NOT NULL DEFAULT 0,
                    total_symbols   INTEGER NOT NULL DEFAULT 0
                );

                CREATE INDEX IF NOT EXISTS idx_dca_analyses_org
                    ON dca_analyses (org_id, repo_ref, analyzed_at DESC);

                CREATE TABLE IF NOT EXISTS dca_symbols (
                    id              TEXT PRIMARY KEY,
                    analysis_id     TEXT NOT NULL,
                    symbol_type     TEXT NOT NULL,
                    symbol_name     TEXT NOT NULL,
                    file_ref        TEXT NOT NULL,
                    start_line      INTEGER NOT NULL DEFAULT 0,
                    end_line        INTEGER NOT NULL DEFAULT 0,
                    metadata_json   TEXT NOT NULL DEFAULT '{}'
                );

                CREATE INDEX IF NOT EXISTS idx_dca_symbols_analysis
                    ON dca_symbols (analysis_id, symbol_type);

                CREATE TABLE IF NOT EXISTS dca_api_endpoints (
                    id                  TEXT PRIMARY KEY,
                    analysis_id         TEXT NOT NULL,
                    method              TEXT NOT NULL,
                    path                TEXT NOT NULL,
                    handler_file        TEXT NOT NULL,
                    handler_line        INTEGER NOT NULL DEFAULT 0,
                    authenticated_bool  INTEGER NOT NULL DEFAULT 0,
                    metadata_json       TEXT NOT NULL DEFAULT '{}'
                );

                CREATE INDEX IF NOT EXISTS idx_dca_ep_analysis
                    ON dca_api_endpoints (analysis_id, method, path);

                CREATE TABLE IF NOT EXISTS dca_data_models (
                    id                  TEXT PRIMARY KEY,
                    analysis_id         TEXT NOT NULL,
                    model_name          TEXT NOT NULL,
                    file_ref            TEXT NOT NULL,
                    fields_json         TEXT NOT NULL DEFAULT '[]',
                    is_sensitive_bool   INTEGER NOT NULL DEFAULT 0
                );

                CREATE INDEX IF NOT EXISTS idx_dca_models_analysis
                    ON dca_data_models (analysis_id, is_sensitive_bool);
                """
            )

    # ------------------------------------------------------------------
    # TypeScript / JavaScript AST analysis (tree-sitter)
    # ------------------------------------------------------------------

    # --- taint sources and sinks -----------------------------------------
    _TS_TAINT_SOURCES: Dict[str, str] = {
        # Express / Node request object properties
        "req.body": "user-controlled HTTP body",
        "req.query": "user-controlled query string",
        "req.params": "user-controlled URL parameters",
        "req.headers": "user-controlled HTTP headers",
        "req.cookies": "user-controlled cookies",
        # process.env reads — treated as taint source (secrets/config leak)
        "process.env": "environment variable (potential secret)",
    }

    _TS_SINK_PATTERNS: List[Dict[str, Any]] = [
        {
            "id": "eval",
            "label": "eval() call",
            "severity": "HIGH",
            "cwe": "CWE-95",
            "match_call": re.compile(r"^eval$"),
        },
        {
            "id": "function_constructor",
            "label": "Function() constructor (indirect eval)",
            "severity": "HIGH",
            "cwe": "CWE-95",
            "match_call": re.compile(r"^Function$"),
        },
        {
            "id": "child_process_exec",
            "label": "child_process.exec — OS command injection",
            "severity": "CRITICAL",
            "cwe": "CWE-78",
            "match_call": re.compile(r"^exec$"),
        },
        {
            "id": "child_process_spawn",
            "label": "child_process.spawn — OS command injection",
            "severity": "HIGH",
            "cwe": "CWE-78",
            "match_call": re.compile(r"^spawn$"),
        },
        {
            "id": "innerHTML",
            "label": "innerHTML assignment — XSS",
            "severity": "HIGH",
            "cwe": "CWE-79",
            "match_call": None,  # detected via assignment pattern
            "match_text": re.compile(r"\.innerHTML\s*="),
        },
        {
            "id": "raw_sql_concat",
            "label": "Raw SQL string concatenation — SQLi",
            "severity": "HIGH",
            "cwe": "CWE-89",
            "match_call": None,
            "match_text": re.compile(
                r'(["\'`])\s*(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE)\b.+\+',
                re.IGNORECASE,
            ),
        },
    ]

    def _ts_node_text(self, node: Any, source: bytes) -> str:
        """Return UTF-8 text for a tree-sitter node."""
        return source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")

    def _ts_walk_findings(
        self, node: Any, source: bytes, rel_path: str
    ) -> List[Dict[str, Any]]:
        """Recursively walk the AST and collect security findings."""
        findings: List[Dict[str, Any]] = []
        raw_text = self._ts_node_text(node, source)

        # --- sink detection via call_expression nodes -------------------
        if node.type == "call_expression":
            func_node = node.child_by_field_name("function")
            if func_node is not None:
                func_text = self._ts_node_text(func_node, source)
                for sink in self._TS_SINK_PATTERNS:
                    if sink.get("match_call") and sink["match_call"].match(
                        func_text.split(".")[-1]
                    ):
                        findings.append(
                            {
                                "id": str(uuid.uuid4()),
                                "file": rel_path,
                                "line": node.start_point[0] + 1,
                                "severity": sink["severity"],
                                "type": "security",
                                "rule_id": sink["id"],
                                "message": f"{sink['label']} at line "
                                f"{node.start_point[0] + 1} in {rel_path}",
                                "cwe": sink.get("cwe", ""),
                                "sink": func_text,
                                "taint_flow": None,
                            }
                        )

        # --- innerHTML assignment and SQL concat (text-pattern sinks) ---
        if node.type in ("assignment_expression", "augmented_assignment_expression"):
            node_text = raw_text
            for sink in self._TS_SINK_PATTERNS:
                if sink.get("match_text") and sink["match_text"].search(node_text):
                    findings.append(
                        {
                            "id": str(uuid.uuid4()),
                            "file": rel_path,
                            "line": node.start_point[0] + 1,
                            "severity": sink["severity"],
                            "type": "security",
                            "rule_id": sink["id"],
                            "message": f"{sink['label']} at line "
                            f"{node.start_point[0] + 1} in {rel_path}",
                            "cwe": sink.get("cwe", ""),
                            "sink": node_text[:120],
                            "taint_flow": None,
                        }
                    )

        # --- taint flow: source → sink in same call argument ------------
        if node.type == "call_expression":
            func_node = node.child_by_field_name("function")
            args_node = node.child_by_field_name("arguments")
            if func_node is not None and args_node is not None:
                func_text = self._ts_node_text(func_node, source)
                args_text = self._ts_node_text(args_node, source)
                sink_match = None
                for sink in self._TS_SINK_PATTERNS:
                    if sink.get("match_call") and sink["match_call"].match(
                        func_text.split(".")[-1]
                    ):
                        sink_match = sink
                        break
                if sink_match:
                    for src_key, src_desc in self._TS_TAINT_SOURCES.items():
                        if src_key in args_text:
                            # Remove the generic finding already added and
                            # replace it with the taint-flow enriched one.
                            findings = [
                                f
                                for f in findings
                                if not (
                                    f["rule_id"] == sink_match["id"]
                                    and f["line"] == node.start_point[0] + 1
                                    and f.get("taint_flow") is None
                                )
                            ]
                            findings.append(
                                {
                                    "id": str(uuid.uuid4()),
                                    "file": rel_path,
                                    "line": node.start_point[0] + 1,
                                    "severity": sink_match["severity"],
                                    "type": "taint_flow",
                                    "rule_id": f"taint_{sink_match['id']}",
                                    "message": (
                                        f"Taint flow: {src_desc} ({src_key}) "
                                        f"flows into {sink_match['label']} at "
                                        f"line {node.start_point[0] + 1} in {rel_path}"
                                    ),
                                    "cwe": sink_match.get("cwe", ""),
                                    "sink": func_text,
                                    "taint_flow": {
                                        "source": src_key,
                                        "source_desc": src_desc,
                                        "sink": func_text,
                                    },
                                }
                            )

        # Recurse into all children
        for child in node.children:
            findings.extend(self._ts_walk_findings(child, source, rel_path))

        return findings

    def _ts_extract_symbols(
        self, node: Any, source: bytes, rel_path: str
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Extract functions, classes, imports, exports from the AST."""
        symbols: List[Dict[str, Any]] = []
        imports: List[Dict[str, Any]] = []
        exports: List[Dict[str, Any]] = []

        def _walk(n: Any) -> None:
            t = n.type

            # --- function declarations -----------------------------------
            if t in ("function_declaration", "function", "arrow_function",
                     "method_definition"):
                name_node = n.child_by_field_name("name")
                name = (
                    self._ts_node_text(name_node, source) if name_node else "<anonymous>"
                )
                # parameters
                params_node = n.child_by_field_name("parameters")
                params: List[str] = []
                if params_node:
                    for p in params_node.children:
                        if p.type not in (",", "(", ")", "comment"):
                            params.append(
                                self._ts_node_text(p, source).strip()
                            )
                # return type (TS-specific)
                ret_node = n.child_by_field_name("return_type")
                return_type = (
                    self._ts_node_text(ret_node, source).lstrip(":").strip()
                    if ret_node
                    else ""
                )
                symbols.append(
                    {
                        "symbol_type": "function",
                        "symbol_name": name,
                        "file_ref": rel_path,
                        "start_line": n.start_point[0] + 1,
                        "end_line": n.end_point[0] + 1,
                        "metadata": {
                            "params": [p for p in params if p],
                            "return_type": return_type,
                            "language": "typescript",
                        },
                    }
                )

            # --- class declarations --------------------------------------
            elif t == "class_declaration":
                name_node = n.child_by_field_name("name")
                class_name = (
                    self._ts_node_text(name_node, source) if name_node else "<anon>"
                )
                body_node = n.child_by_field_name("body")
                methods: List[str] = []
                fields: List[str] = []
                if body_node:
                    for child in body_node.children:
                        if child.type == "method_definition":
                            mn = child.child_by_field_name("name")
                            if mn:
                                methods.append(self._ts_node_text(mn, source))
                        elif child.type in (
                            "public_field_definition",
                            "field_definition",
                        ):
                            fn = child.child_by_field_name("name")
                            if fn:
                                fields.append(self._ts_node_text(fn, source))
                symbols.append(
                    {
                        "symbol_type": "class",
                        "symbol_name": class_name,
                        "file_ref": rel_path,
                        "start_line": n.start_point[0] + 1,
                        "end_line": n.end_point[0] + 1,
                        "metadata": {
                            "methods": methods,
                            "fields": fields,
                            "language": "typescript",
                        },
                    }
                )

            # --- import statements ---------------------------------------
            elif t == "import_statement":
                from_clause = ""
                named: List[str] = []
                for child in n.children:
                    if child.type == "string":
                        from_clause = (
                            self._ts_node_text(child, source).strip("'\"` ")
                        )
                    elif child.type == "import_clause":
                        for ic in child.children:
                            if ic.type == "named_imports":
                                for ni in ic.children:
                                    if ni.type == "import_specifier":
                                        nn = ni.child_by_field_name("name")
                                        if nn:
                                            named.append(
                                                self._ts_node_text(nn, source)
                                            )
                imports.append(
                    {
                        "from": from_clause,
                        "named": named,
                        "line": n.start_point[0] + 1,
                        "file_ref": rel_path,
                    }
                )

            # --- export statements ---------------------------------------
            elif t in ("export_statement", "export_default_declaration"):
                decl_node = n.child_by_field_name("declaration")
                exported_name = ""
                if decl_node:
                    nn = decl_node.child_by_field_name("name")
                    if nn:
                        exported_name = self._ts_node_text(nn, source)
                exports.append(
                    {
                        "name": exported_name or "<default>",
                        "line": n.start_point[0] + 1,
                        "file_ref": rel_path,
                    }
                )

            for child in n.children:
                _walk(child)

        _walk(node)
        return {"symbols": symbols, "imports": imports, "exports": exports}

    def _analyze_typescript_source(
        self, source: str, rel_path: str, is_tsx: bool = False
    ) -> Dict[str, Any]:
        """Parse TypeScript/TSX source and return symbols + security findings.

        Returns a dict with keys:
          symbols   — list of symbol dicts (compatible with _analyze_python_file)
          findings  — list of security finding dicts
          imports   — list of import dicts
          exports   — list of export dicts
          endpoints — always [] (TS route extraction is heuristic-only for now)
          models    — always [] (Pydantic-style models not common in TS)
        """
        if _TS_LANGUAGE is None:
            raise RuntimeError(
                "tree-sitter-typescript native extension not available"
            )

        lang = _TSX_LANGUAGE if is_tsx else _TS_LANGUAGE
        parser = _TSParser(lang)  # type: ignore[arg-type]
        encoded = source.encode("utf-8", errors="replace")
        tree = parser.parse(encoded)

        sym_data = self._ts_extract_symbols(tree.root_node, encoded, rel_path)
        findings = self._ts_walk_findings(tree.root_node, encoded, rel_path)

        return {
            "symbols": sym_data["symbols"],
            "findings": findings,
            "imports": sym_data["imports"],
            "exports": sym_data["exports"],
            "endpoints": [],
            "models": [],
        }

    def _analyze_typescript(self, file_path: Path) -> Dict[str, Any]:
        """Public entry-point: parse a .ts/.tsx file from disk."""
        is_tsx = file_path.suffix.lower() == ".tsx"
        source = file_path.read_text(encoding="utf-8", errors="replace")
        return self._analyze_typescript_source(source, str(file_path), is_tsx=is_tsx)

    # ------------------------------------------------------------------
    # JavaScript AST analysis — esprima (pure-Python, no Node required)
    # Works air-gapped, independent of tree-sitter C extension.
    # ------------------------------------------------------------------

    _JS_TAINT_SOURCE_OBJECTS: frozenset = frozenset({"req", "request"})
    _JS_TAINT_SOURCE_PROPS: frozenset = frozenset(
        {"body", "query", "params", "headers", "cookies"}
    )
    _JS_PROCESS_ENV_OBJECTS: frozenset = frozenset(
        {"process", "localStorage", "sessionStorage"}
    )
    _JS_CP_DANGEROUS: frozenset = frozenset(
        {"exec", "execSync", "spawn", "spawnSync", "execFile", "execFileSync", "fork"}
    )

    # rule_id → CWE
    _JS_RULE_CWE: Dict[str, str] = {
        "JS001": "CWE-95",   # eval
        "JS002": "CWE-95",   # new Function
        "JS003": "CWE-78",   # child_process
        "JS004": "CWE-79",   # document.write
        "JS005": "CWE-95",   # setTimeout string
        "JS006": "CWE-79",   # innerHTML
        "JS007": "CWE-1321", # prototype pollution
    }

    def _js_finding(
        self,
        severity: str,
        rule_id: str,
        message: str,
        node: Any,
        file_ref: str,
        evidence: str = "",
    ) -> Dict[str, Any]:
        loc = getattr(node, "loc", None)
        return {
            "id": str(uuid.uuid4()),
            "severity": severity,
            "rule_id": rule_id,
            "message": message,
            "file": file_ref,
            "file_ref": file_ref,
            "line": loc.start.line if loc else 0,
            "col": loc.start.column if loc else 0,
            "cwe": self._JS_RULE_CWE.get(rule_id, ""),
            "evidence": evidence,
            "taint_flow": None,
            "type": "security",
        }

    def _js_is_taint_source(self, node: Any) -> bool:
        if not hasattr(node, "type") or node.type != "MemberExpression":
            return False
        obj = node.object
        prop = node.property
        obj_name = getattr(obj, "name", None)
        prop_name = getattr(prop, "name", None)
        if obj_name in self._JS_TAINT_SOURCE_OBJECTS and prop_name in self._JS_TAINT_SOURCE_PROPS:
            return True
        if obj_name in self._JS_PROCESS_ENV_OBJECTS:
            return True
        if obj_name == "document" and prop_name == "cookie":
            return True
        # process.env.KEY (nested MemberExpression)
        if getattr(obj, "type", "") == "MemberExpression":
            inner_obj = getattr(obj.object, "name", None)
            inner_prop = getattr(obj.property, "name", None)
            if inner_obj == "process" and inner_prop == "env":
                return True
        return False

    def _js_walk(  # noqa: C901
        self,
        node: Any,
        symbols: List[Dict[str, Any]],
        imports: List[Dict[str, Any]],
        findings: List[Dict[str, Any]],
        file_ref: str,
    ) -> None:
        """Recursively walk an esprima AST node, collecting symbols and findings."""
        if node is None or not hasattr(node, "type"):
            return
        ntype = node.type

        # --- Symbol extraction -------------------------------------------
        if ntype == "FunctionDeclaration":
            name = getattr(node.id, "name", "<anonymous>") if node.id else "<anonymous>"
            loc = getattr(node, "loc", None)
            symbols.append({
                "symbol_type": "function",
                "symbol_name": name,
                "file_ref": file_ref,
                "start_line": loc.start.line if loc else 0,
                "end_line": loc.end.line if loc else 0,
                "metadata": {
                    "async": getattr(node, "async", False),
                    "generator": getattr(node, "generator", False),
                    "language": "javascript",
                },
            })

        elif ntype == "ClassDeclaration":
            name = getattr(node.id, "name", "<anonymous>") if node.id else "<anonymous>"
            loc = getattr(node, "loc", None)
            super_name = getattr(node.superClass, "name", "") if node.superClass else ""
            symbols.append({
                "symbol_type": "class",
                "symbol_name": name,
                "file_ref": file_ref,
                "start_line": loc.start.line if loc else 0,
                "end_line": loc.end.line if loc else 0,
                "metadata": {"superClass": super_name, "language": "javascript"},
            })

        elif ntype == "VariableDeclaration":
            for decl in (getattr(node, "declarations", None) or []):
                init = getattr(decl, "init", None)
                id_node = getattr(decl, "id", None)
                var_name = getattr(id_node, "name", "") if id_node else ""
                if init is None:
                    continue
                init_type = getattr(init, "type", "")
                # CommonJS: const x = require("mod")
                if init_type == "CallExpression":
                    callee = getattr(init, "callee", None)
                    if getattr(callee, "name", "") == "require":
                        args = getattr(init, "arguments", []) or []
                        mod = getattr(args[0], "value", "") if args else ""
                        loc = getattr(node, "loc", None)
                        imports.append({
                            "import_type": "commonjs",
                            "module": mod,
                            "binding": var_name,
                            "file_ref": file_ref,
                            "line": loc.start.line if loc else 0,
                        })
                elif init_type == "FunctionExpression" and var_name:
                    loc = getattr(node, "loc", None)
                    symbols.append({
                        "symbol_type": "function",
                        "symbol_name": var_name,
                        "file_ref": file_ref,
                        "start_line": loc.start.line if loc else 0,
                        "end_line": loc.end.line if loc else 0,
                        "metadata": {
                            "async": getattr(init, "async", False),
                            "expression": True,
                            "language": "javascript",
                        },
                    })
                elif init_type == "ArrowFunctionExpression" and var_name:
                    loc = getattr(node, "loc", None)
                    symbols.append({
                        "symbol_type": "function",
                        "symbol_name": var_name,
                        "file_ref": file_ref,
                        "start_line": loc.start.line if loc else 0,
                        "end_line": loc.end.line if loc else 0,
                        "metadata": {
                            "async": getattr(init, "async", False),
                            "arrow": True,
                            "language": "javascript",
                        },
                    })

        elif ntype == "ImportDeclaration":
            mod = getattr(node.source, "value", "")
            loc = getattr(node, "loc", None)
            specifiers: List[Dict[str, Any]] = []
            for sp in (getattr(node, "specifiers", None) or []):
                sp_type = getattr(sp, "type", "")
                local_name = getattr(getattr(sp, "local", None), "name", "")
                imported_name = getattr(getattr(sp, "imported", None), "name", local_name)
                specifiers.append({
                    "type": (
                        "default" if sp_type == "ImportDefaultSpecifier"
                        else "namespace" if sp_type == "ImportNamespaceSpecifier"
                        else "named"
                    ),
                    "local": local_name,
                    "imported": imported_name,
                })
            imports.append({
                "import_type": "es6",
                "module": mod,
                "specifiers": specifiers,
                "file_ref": file_ref,
                "line": loc.start.line if loc else 0,
            })

        elif ntype == "ExportDefaultDeclaration":
            decl = getattr(node, "declaration", None)
            loc = getattr(node, "loc", None)
            name = "<default>"
            if decl and getattr(decl, "type", "") in ("FunctionDeclaration", "ClassDeclaration"):
                name = getattr(getattr(decl, "id", None), "name", "<default>") or "<default>"
            symbols.append({
                "symbol_type": "export_default",
                "symbol_name": name,
                "file_ref": file_ref,
                "start_line": loc.start.line if loc else 0,
                "end_line": loc.end.line if loc else 0,
                "metadata": {"language": "javascript"},
            })

        elif ntype == "ExportNamedDeclaration":
            loc = getattr(node, "loc", None)
            decl = getattr(node, "declaration", None)
            if decl and getattr(decl, "type", "") == "FunctionDeclaration":
                fn_name = getattr(getattr(decl, "id", None), "name", "") or ""
                if fn_name:
                    symbols.append({
                        "symbol_type": "export_named",
                        "symbol_name": fn_name,
                        "file_ref": file_ref,
                        "start_line": loc.start.line if loc else 0,
                        "end_line": loc.end.line if loc else 0,
                        "metadata": {"language": "javascript"},
                    })
            for sp in (getattr(node, "specifiers", None) or []):
                local_name = getattr(getattr(sp, "local", None), "name", "")
                if local_name:
                    symbols.append({
                        "symbol_type": "export_named",
                        "symbol_name": local_name,
                        "file_ref": file_ref,
                        "start_line": loc.start.line if loc else 0,
                        "end_line": loc.end.line if loc else 0,
                        "metadata": {"language": "javascript"},
                    })

        # --- Security sink detection -------------------------------------
        elif ntype == "CallExpression":
            callee = getattr(node, "callee", None)
            args = getattr(node, "arguments", []) or []
            callee_type = getattr(callee, "type", "")
            callee_name = getattr(callee, "name", "")

            if callee_type == "Identifier" and callee_name == "eval":
                findings.append(self._js_finding(
                    "HIGH", "JS001", "eval() call — code injection sink",
                    node, file_ref, evidence="eval()"
                ))
            elif callee_type == "Identifier" and callee_name == "Function":
                findings.append(self._js_finding(
                    "HIGH", "JS002", "Function() call — indirect eval sink",
                    node, file_ref, evidence="Function()"
                ))
            elif callee_type == "MemberExpression":
                obj_name = getattr(callee.object, "name", "")
                method_name = getattr(callee.property, "name", "")

                if obj_name == "child_process" and method_name in self._JS_CP_DANGEROUS:
                    findings.append(self._js_finding(
                        "CRITICAL", "JS003",
                        f"child_process.{method_name}() — OS command injection",
                        node, file_ref, evidence=f"child_process.{method_name}()"
                    ))

                # require('child_process').exec(...)
                obj_node = callee.object
                if getattr(obj_node, "type", "") == "CallExpression":
                    inner_callee = getattr(obj_node, "callee", None)
                    if getattr(inner_callee, "name", "") == "require":
                        req_args = getattr(obj_node, "arguments", []) or []
                        if req_args and getattr(req_args[0], "value", "") == "child_process":
                            if method_name in self._JS_CP_DANGEROUS:
                                findings.append(self._js_finding(
                                    "CRITICAL", "JS003",
                                    f"child_process.{method_name}() — OS command injection",
                                    node, file_ref,
                                    evidence=f"require('child_process').{method_name}()"
                                ))

                if obj_name == "document" and method_name == "write":
                    findings.append(self._js_finding(
                        "HIGH", "JS004", "document.write() — XSS sink",
                        node, file_ref, evidence="document.write()"
                    ))

                if obj_name == "Object" and method_name == "assign":
                    if len(args) >= 2 and self._js_is_taint_source(args[1]):
                        findings.append(self._js_finding(
                            "HIGH", "JS007",
                            "Object.assign() with tainted arg — prototype pollution risk",
                            node, file_ref, evidence="Object.assign(target, userInput)"
                        ))

            # setTimeout/setInterval with string literal
            bare_name = (
                callee_name if callee_type == "Identifier"
                else getattr(getattr(callee, "property", None), "name", "")
            )
            if bare_name in ("setTimeout", "setInterval") and args:
                first = args[0]
                if getattr(first, "type", "") == "Literal" and isinstance(
                    getattr(first, "value", None), str
                ):
                    val = first.value
                    ev = val[:40] + "..." if len(val) > 40 else val
                    findings.append(self._js_finding(
                        "MEDIUM", "JS005",
                        f"{bare_name}() with string arg — eval-like sink",
                        node, file_ref, evidence=f"{bare_name}('{ev}')"
                    ))

        elif ntype == "NewExpression":
            callee = getattr(node, "callee", None)
            if getattr(callee, "type", "") == "Identifier" and getattr(callee, "name", "") == "Function":
                findings.append(self._js_finding(
                    "HIGH", "JS002", "new Function() — code injection sink",
                    node, file_ref, evidence="new Function()"
                ))

        elif ntype == "AssignmentExpression":
            left = getattr(node, "left", None)
            if left and getattr(left, "type", "") == "MemberExpression":
                prop_name = getattr(left.property, "name", "")
                if prop_name == "innerHTML":
                    findings.append(self._js_finding(
                        "HIGH", "JS006", ".innerHTML assignment — XSS sink",
                        node, file_ref, evidence=".innerHTML ="
                    ))
                elif prop_name == "outerHTML":
                    findings.append(self._js_finding(
                        "MEDIUM", "JS006", ".outerHTML assignment — XSS sink",
                        node, file_ref, evidence=".outerHTML ="
                    ))
                elif prop_name == "__proto__":
                    findings.append(self._js_finding(
                        "HIGH", "JS007", "__proto__ assignment — prototype pollution",
                        node, file_ref, evidence="obj.__proto__ ="
                    ))

        # --- Recurse -----------------------------------------------------
        if hasattr(node, "__dict__"):
            for child in vars(node).values():
                if child is None:
                    continue
                if hasattr(child, "type"):
                    self._js_walk(child, symbols, imports, findings, file_ref)
                elif isinstance(child, list):
                    for item in child:
                        if item is not None and hasattr(item, "type"):
                            self._js_walk(item, symbols, imports, findings, file_ref)

    def _analyze_javascript_source(
        self, source: str, rel_path: str
    ) -> Dict[str, Any]:
        """Parse JS/JSX source with esprima, return symbols + security findings.

        Return shape is consistent with Python and TypeScript analyzers:
          symbols[]  — functions, classes, exports
          imports[]  — ES6 import + CommonJS require
          findings[] — security issues with severity/rule_id/line/cwe
          endpoints  — always [] (JS route extraction is heuristic-only)
          models     — always []
        """
        try:
            import esprima  # type: ignore[import]
        except ImportError:
            _logger.warning("esprima not installed — JS analysis skipped for %s", rel_path)
            return {"symbols": [], "imports": [], "findings": [], "endpoints": [], "models": []}

        symbols: List[Dict[str, Any]] = []
        imports: List[Dict[str, Any]] = []
        findings: List[Dict[str, Any]] = []

        parse_kwargs: Dict[str, Any] = dict(tolerant=True, loc=True, range=False)
        tree = None
        for parse_fn in (esprima.parseScript, esprima.parseModule):
            try:
                tree = parse_fn(source, **parse_kwargs)
                break
            except Exception:
                continue

        if tree is None:
            _logger.debug("DCA JS parse failure (script+module both failed): %s", rel_path)
            return {"symbols": [], "imports": [], "findings": [], "endpoints": [], "models": []}

        self._js_walk(tree, symbols, imports, findings, rel_path)
        return {
            "symbols": symbols,
            "imports": imports,
            "findings": findings,
            "endpoints": [],
            "models": [],
        }

    def _analyze_javascript(self, file_path: Path) -> Dict[str, Any]:
        """Public entry-point: parse a .js/.jsx file from disk using esprima."""
        source = file_path.read_text(encoding="utf-8", errors="replace")
        return self._analyze_javascript_source(source, str(file_path))

    def _analyze_java(self, file_path: Path) -> Dict[str, Any]:  # noqa: C901
        """Parse a Java source file with javalang and extract security-relevant artefacts.

        Returns a dict with keys:
          - symbols:  list of class/method/field dicts
          - findings: list of taint/sink vulnerability dicts
          - package:  str
          - imports:  list[str]

        Taint sources: request.getParameter(), request.getHeader(),
          System.getenv(), request.getInputStream().

        Sinks:
          - SQL injection: executeQuery/executeUpdate with string concatenation
          - Command injection: Runtime.getRuntime().exec(), ProcessBuilder
          - XXE: DocumentBuilderFactory without disallow-doctype-decl setFeature
          - Path traversal: new File(userInput), Files.newInputStream(Paths.get(...))
        """
        try:
            import javalang  # type: ignore
        except ImportError as exc:
            raise ImportError(
                "javalang is required for Java analysis: pip install javalang"
            ) from exc

        rel_path = str(file_path)
        result: Dict[str, Any] = {
            "symbols": [],
            "findings": [],
            "package": "",
            "imports": [],
        }

        try:
            source = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            _logger.debug("DCA Java read failure %s: %s", rel_path, exc)
            return result

        try:
            tree = javalang.parse.parse(source)
        except Exception as exc:  # javalang.parser.JavaSyntaxError and friends
            _logger.debug("DCA Java parse failure %s: %s", rel_path, exc)
            return result

        # ---- Package & imports ----------------------------------------
        if tree.package:
            result["package"] = tree.package.name
        result["imports"] = [imp.path for imp in (tree.imports or [])]

        # ---- Taint source patterns ------------------------------------
        _TAINT_SOURCE_PATTERNS = [
            re.compile(r"request\.getParameter\s*\("),
            re.compile(r"request\.getHeader\s*\("),
            re.compile(r"System\.getenv\s*\("),
            re.compile(r"request\.getInputStream\s*\("),
        ]

        # ---- Sink patterns --------------------------------------------
        _SQL_SINK = re.compile(
            r"\.(executeQuery|executeUpdate|execute)\s*\([^)]*\+[^)]*\)"
        )
        _CMD_SINK = re.compile(
            r"(Runtime\.getRuntime\(\)\s*\.exec|new\s+ProcessBuilder)\s*\("
        )
        _XXE_FACTORY = re.compile(r"DocumentBuilderFactory\s*\.\s*newInstance\s*\(")
        _XXE_SAFE_FEATURE = re.compile(
            r'setFeature\s*\(\s*"http://apache\.org/xml/features/disallow-doctype-decl"'
        )
        _PATH_SINK = re.compile(
            r"(new\s+File\s*\(|Files\s*\.\s*newInputStream\s*\(\s*Paths\s*\.\s*get\s*\()"
        )

        lines = source.splitlines()

        def _line_has_taint(line: str) -> bool:
            return any(p.search(line) for p in _TAINT_SOURCE_PATTERNS)

        file_has_taint = any(_line_has_taint(ln) for ln in lines)

        # ---- XXE: DocumentBuilderFactory without safe setFeature -----
        if _XXE_FACTORY.search(source) and not _XXE_SAFE_FEATURE.search(source):
            for i, ln in enumerate(lines, 1):
                if _XXE_FACTORY.search(ln):
                    result["findings"].append({
                        "type": "XXE",
                        "severity": "MEDIUM",
                        "file_ref": rel_path,
                        "line": i,
                        "detail": (
                            "DocumentBuilderFactory.newInstance() without "
                            "setFeature(disallow-doctype-decl, true) — XXE risk"
                        ),
                        "cwe": "CWE-611",
                    })
                    break

        # ---- Line-level sink scanning ---------------------------------
        for i, ln in enumerate(lines, 1):
            if _SQL_SINK.search(ln):
                result["findings"].append({
                    "type": "SQL_INJECTION",
                    "severity": "HIGH",
                    "file_ref": rel_path,
                    "line": i,
                    "detail": (
                        "String concatenation inside SQL execute call — "
                        "potential SQL injection"
                    ),
                    "cwe": "CWE-89",
                })

            if _CMD_SINK.search(ln) and file_has_taint:
                result["findings"].append({
                    "type": "COMMAND_INJECTION",
                    "severity": "HIGH",
                    "file_ref": rel_path,
                    "line": i,
                    "detail": (
                        "Runtime.exec() or ProcessBuilder in file with taint "
                        "sources — potential command injection"
                    ),
                    "cwe": "CWE-78",
                })

            if _PATH_SINK.search(ln) and file_has_taint:
                result["findings"].append({
                    "type": "PATH_TRAVERSAL",
                    "severity": "HIGH",
                    "file_ref": rel_path,
                    "line": i,
                    "detail": (
                        "File/Paths.get() in file with taint sources — "
                        "potential path traversal"
                    ),
                    "cwe": "CWE-22",
                })

        # ---- Symbol extraction via javalang AST ----------------------
        for _path_node, node in tree:
            if isinstance(node, javalang.tree.ClassDeclaration):
                extends = node.extends.name if node.extends else None
                implements = [iface.name for iface in (node.implements or [])]
                result["symbols"].append({
                    "symbol_type": "class",
                    "symbol_name": node.name,
                    "file_ref": rel_path,
                    "start_line": node.position.line if node.position else 0,
                    "end_line": node.position.line if node.position else 0,
                    "metadata": {
                        "extends": extends,
                        "implements": implements,
                        "modifiers": list(node.modifiers or []),
                    },
                })

            elif isinstance(node, javalang.tree.MethodDeclaration):
                annotations = [a.name for a in (node.annotations or [])]
                params = []
                for p in (node.parameters or []):
                    type_name = p.type.name if hasattr(p.type, "name") else str(p.type)
                    params.append(f"{type_name} {p.name}")
                result["symbols"].append({
                    "symbol_type": "method",
                    "symbol_name": node.name,
                    "file_ref": rel_path,
                    "start_line": node.position.line if node.position else 0,
                    "end_line": node.position.line if node.position else 0,
                    "metadata": {
                        "return_type": (
                            node.return_type.name if node.return_type else "void"
                        ),
                        "parameters": params,
                        "annotations": annotations,
                        "modifiers": list(node.modifiers or []),
                    },
                })

            elif isinstance(node, javalang.tree.FieldDeclaration):
                for decl in (node.declarators or []):
                    result["symbols"].append({
                        "symbol_type": "field",
                        "symbol_name": decl.name,
                        "file_ref": rel_path,
                        "start_line": node.position.line if node.position else 0,
                        "end_line": node.position.line if node.position else 0,
                        "metadata": {
                            "field_type": (
                                node.type.name if node.type else "unknown"
                            ),
                            "modifiers": list(node.modifiers or []),
                        },
                    })

        return result

    # ------------------------------------------------------------------
    # Python AST analysis
    # ------------------------------------------------------------------

    def _extract_decorator_info(
        self, decorator: ast.expr
    ) -> Optional[Tuple[str, str, str, Dict[str, Any]]]:
        """If decorator is a route decorator, return (framework, method, path, meta).

        Supports:
          @router.get("/x") or @app.post("/x")        → ("fastapi", "GET", "/x", ...)
          @app.route("/x", methods=["POST"])          → ("flask", "POST", "/x", ...)
        """
        if not isinstance(decorator, ast.Call):
            return None

        # Matches X.Y(...) where Y is a method like get/post/etc.
        func = decorator.func
        if isinstance(func, ast.Attribute):
            attr = func.attr.lower()
            # FastAPI-style @router.get("/x"), @app.post("/x")
            if attr in _HTTP_METHOD_DECORATORS:
                method = attr.upper()
                path = ""
                if decorator.args and isinstance(decorator.args[0], ast.Constant):
                    if isinstance(decorator.args[0].value, str):
                        path = decorator.args[0].value
                meta: Dict[str, Any] = {"framework": "fastapi"}
                # Check for auth via dependencies kwarg
                for kw in decorator.keywords:
                    if kw.arg == "dependencies":
                        meta["has_dependencies"] = True
                return ("fastapi", method, path, meta)

            # Flask-style @app.route("/x", methods=["POST"])
            if attr == "route":
                path = ""
                methods = ["GET"]
                if decorator.args and isinstance(decorator.args[0], ast.Constant):
                    if isinstance(decorator.args[0].value, str):
                        path = decorator.args[0].value
                for kw in decorator.keywords:
                    if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple)):
                        methods = [
                            el.value.upper()
                            for el in kw.value.elts
                            if isinstance(el, ast.Constant) and isinstance(el.value, str)
                        ] or ["GET"]
                return ("flask", methods[0], path, {"framework": "flask", "methods": methods})

        return None

    def _has_auth_decorator(self, node: ast.FunctionDef) -> bool:
        """Return True if function has an auth-indicating decorator."""
        auth_hints = {"login_required", "requires_auth", "authenticated", "jwt_required"}
        for dec in node.decorator_list:
            # @login_required
            if isinstance(dec, ast.Name) and dec.id in auth_hints:
                return True
            # @requires_auth(...)
            if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Name):
                if dec.func.id in auth_hints:
                    return True
            # Depends(api_key_auth) via dependencies kwarg handled separately
        return False

    def _is_model_class(self, node: ast.ClassDef) -> bool:
        """Return True if class inherits from a known ORM/model base."""
        for base in node.bases:
            if isinstance(base, ast.Name) and base.id in _ORM_BASE_HINTS:
                return True
            if isinstance(base, ast.Attribute):
                # e.g. models.Model, sqlalchemy.Base
                if base.attr in _ORM_BASE_HINTS:
                    return True
                # e.g. django.db.models.Model
                if base.attr == "Model":
                    return True
            if isinstance(base, ast.Call) and isinstance(base.func, ast.Name):
                if base.func.id in _ORM_BASE_HINTS:
                    return True
        return False

    def _extract_model_fields(self, node: ast.ClassDef) -> List[Dict[str, Any]]:
        """Extract field names from a model class body (type annotations & assignments)."""
        fields: List[Dict[str, Any]] = []
        for stmt in node.body:
            name: Optional[str] = None
            if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                name = stmt.target.id
            elif isinstance(stmt, ast.Assign):
                for target in stmt.targets:
                    if isinstance(target, ast.Name):
                        name = target.id
                        break
            if name and not name.startswith("_"):
                sensitive_types = detect_sensitive_types(name)
                fields.append(
                    {
                        "name": name,
                        "line": stmt.lineno,
                        "sensitive_types": sensitive_types,
                    }
                )
        return fields

    def _has_urlpatterns(self, tree: ast.AST) -> bool:
        """Django hint: presence of top-level urlpatterns = [...] assignment."""
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for t in node.targets:
                    if isinstance(t, ast.Name) and t.id == "urlpatterns":
                        return True
        return False

    def _analyze_python_file(
        self, source: str, rel_path: str
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Parse a single Python file and return extracted artefacts."""
        result: Dict[str, List[Dict[str, Any]]] = {
            "symbols": [],
            "endpoints": [],
            "models": [],
        }
        try:
            tree = ast.parse(source)
        except SyntaxError as exc:
            _logger.debug("DCA skip %s: %s", rel_path, exc)
            return result

        django_urlpatterns = self._has_urlpatterns(tree)
        if django_urlpatterns:
            result["symbols"].append(
                {
                    "symbol_type": "django_urlpatterns_hint",
                    "symbol_name": "urlpatterns",
                    "file_ref": rel_path,
                    "start_line": 1,
                    "end_line": 1,
                    "metadata": {"framework": "django"},
                }
            )

        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                end_line = getattr(node, "end_lineno", node.lineno) or node.lineno
                is_model = self._is_model_class(node)
                result["symbols"].append(
                    {
                        "symbol_type": "model_class" if is_model else "class",
                        "symbol_name": node.name,
                        "file_ref": rel_path,
                        "start_line": node.lineno,
                        "end_line": end_line,
                        "metadata": {
                            "bases": [
                                b.id if isinstance(b, ast.Name) else getattr(b, "attr", "")
                                for b in node.bases
                            ]
                        },
                    }
                )
                if is_model:
                    fields = self._extract_model_fields(node)
                    is_sensitive = any(f["sensitive_types"] for f in fields)
                    result["models"].append(
                        {
                            "model_name": node.name,
                            "file_ref": rel_path,
                            "fields": fields,
                            "is_sensitive": is_sensitive,
                        }
                    )

            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                end_line = getattr(node, "end_lineno", node.lineno) or node.lineno
                has_auth = self._has_auth_decorator(node)  # type: ignore[arg-type]

                # Extract API routes from decorators
                route_found = False
                for dec in node.decorator_list:
                    info = self._extract_decorator_info(dec)
                    if info is None:
                        continue
                    framework, method, path, meta = info
                    route_found = True
                    authenticated = has_auth or meta.get("has_dependencies", False)
                    meta.update({"handler": node.name})
                    result["endpoints"].append(
                        {
                            "method": method,
                            "path": path,
                            "handler_file": rel_path,
                            "handler_line": node.lineno,
                            "authenticated": authenticated,
                            "metadata": meta,
                        }
                    )

                result["symbols"].append(
                    {
                        "symbol_type": "route_handler" if route_found else "function",
                        "symbol_name": node.name,
                        "file_ref": rel_path,
                        "start_line": node.lineno,
                        "end_line": end_line,
                        "metadata": {
                            "is_async": isinstance(node, ast.AsyncFunctionDef),
                            "has_auth": has_auth,
                        },
                    }
                )

        return result

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze_repo(
        self,
        org_id: str,
        repo_ref: str,
        commit_sha: str,
        root_path: str,
    ) -> Dict[str, Any]:
        """Walk a filesystem tree and extract symbols, endpoints, models.

        Non-Python source files contribute only to language counts; their
        analyzers are stubs (NotImplementedError is trapped and logged).
        """
        root = Path(root_path)
        if not root.exists() or not root.is_dir():
            raise ValueError(f"root_path not a directory: {root_path}")

        analysis_id = str(uuid.uuid4())
        languages: Dict[str, int] = {}
        total_files = 0
        all_symbols: List[Dict[str, Any]] = []
        all_endpoints: List[Dict[str, Any]] = []
        all_models: List[Dict[str, Any]] = []

        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            ext = path.suffix.lower()
            rel = str(path.relative_to(root))

            if ext in _SUPPORTED_EXTS_PY:
                total_files += 1
                languages["python"] = languages.get("python", 0) + 1
                try:
                    source = path.read_text(encoding="utf-8", errors="replace")
                except OSError as exc:
                    _logger.debug("DCA read failure %s: %s", rel, exc)
                    continue
                extracted = self._analyze_python_file(source, rel)
                all_symbols.extend(extracted["symbols"])
                all_endpoints.extend(extracted["endpoints"])
                all_models.extend(extracted["models"])

            elif ext in _STUB_EXTS:
                total_files += 1
                lang = _STUB_EXTS[ext]
                languages[lang] = languages.get(lang, 0) + 1
                # TypeScript / JavaScript: real AST extraction via tree-sitter.
                if ext in (".ts", ".tsx", ".js", ".jsx") and _TS_LANGUAGE is not None:
                    try:
                        source = path.read_text(encoding="utf-8", errors="replace")
                        is_tsx = ext in (".tsx", ".jsx")
                        extracted_ts = self._analyze_typescript_source(
                            source, rel, is_tsx=is_tsx
                        )
                        all_symbols.extend(extracted_ts["symbols"])
                        all_endpoints.extend(extracted_ts["endpoints"])
                        all_models.extend(extracted_ts["models"])
                        # Security findings are stored in symbols table as
                        # symbol_type="security_finding" for cross-engine access.
                        for finding in extracted_ts.get("findings", []):
                            all_symbols.append(
                                {
                                    "symbol_type": "security_finding",
                                    "symbol_name": finding["rule_id"],
                                    "file_ref": finding["file"],
                                    "start_line": finding["line"],
                                    "end_line": finding["line"],
                                    "metadata": {
                                        "severity": finding["severity"],
                                        "message": finding["message"],
                                        "cwe": finding.get("cwe", ""),
                                        "type": finding.get("type", "security"),
                                        "taint_flow": finding.get("taint_flow"),
                                    },
                                }
                            )
                    except OSError as exc:
                        _logger.debug("DCA read failure %s: %s", rel, exc)
                    except Exception as exc:  # pragma: no cover
                        _logger.warning("DCA TS analysis failed %s: %s", rel, exc)

                # Java: real AST extraction via javalang.
                elif ext == ".java":
                    try:
                        extracted_java = self._analyze_java(path)
                        all_symbols.extend(extracted_java["symbols"])
                        # Java findings stored as security_finding symbols
                        for finding in extracted_java.get("findings", []):
                            all_symbols.append(
                                {
                                    "symbol_type": "security_finding",
                                    "symbol_name": finding["type"],
                                    "file_ref": finding["file_ref"],
                                    "start_line": finding["line"],
                                    "end_line": finding["line"],
                                    "metadata": {
                                        "severity": finding["severity"],
                                        "message": finding["detail"],
                                        "cwe": finding.get("cwe", ""),
                                        "type": finding["type"],
                                    },
                                }
                            )
                    except ImportError:
                        _logger.debug("javalang not available; skipping Java file %s", rel)
                    except Exception as exc:
                        _logger.warning("DCA Java analysis failed %s: %s", rel, exc)

        # Persist
        with self._lock, self._conn() as conn:
            conn.execute(
                """INSERT INTO dca_analyses
                   (id, org_id, repo_ref, commit_sha, analyzed_at, languages_json,
                    total_files, total_symbols)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    analysis_id,
                    org_id,
                    repo_ref,
                    commit_sha,
                    _now_iso(),
                    json.dumps(languages),
                    total_files,
                    len(all_symbols),
                ),
            )

            for sym in all_symbols:
                conn.execute(
                    """INSERT INTO dca_symbols
                       (id, analysis_id, symbol_type, symbol_name, file_ref,
                        start_line, end_line, metadata_json)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        str(uuid.uuid4()),
                        analysis_id,
                        sym["symbol_type"],
                        sym["symbol_name"],
                        sym["file_ref"],
                        sym["start_line"],
                        sym["end_line"],
                        json.dumps(sym.get("metadata", {})),
                    ),
                )

            for ep in all_endpoints:
                conn.execute(
                    """INSERT INTO dca_api_endpoints
                       (id, analysis_id, method, path, handler_file, handler_line,
                        authenticated_bool, metadata_json)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        str(uuid.uuid4()),
                        analysis_id,
                        ep["method"],
                        ep["path"],
                        ep["handler_file"],
                        ep["handler_line"],
                        1 if ep["authenticated"] else 0,
                        json.dumps(ep.get("metadata", {})),
                    ),
                )

            for m in all_models:
                conn.execute(
                    """INSERT INTO dca_data_models
                       (id, analysis_id, model_name, file_ref, fields_json,
                        is_sensitive_bool)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (
                        str(uuid.uuid4()),
                        analysis_id,
                        m["model_name"],
                        m["file_ref"],
                        json.dumps(m["fields"]),
                        1 if m["is_sensitive"] else 0,
                    ),
                )

            conn.commit()

        result = {
            "id": analysis_id,
            "org_id": org_id,
            "repo_ref": repo_ref,
            "commit_sha": commit_sha,
            "languages": languages,
            "total_files": total_files,
            "total_symbols": len(all_symbols),
            "total_endpoints": len(all_endpoints),
            "total_models": len(all_models),
            "sensitive_models": sum(1 for m in all_models if m["is_sensitive"]),
        }
        self._emit_event("dca.analysis.completed", result)
        return result

    def list_analyses(
        self, org_id: str, repo_ref: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List analyses for an org, optionally filtered by repo_ref."""
        with self._lock, self._conn() as conn:
            if repo_ref:
                rows = conn.execute(
                    """SELECT * FROM dca_analyses
                       WHERE org_id = ? AND repo_ref = ?
                       ORDER BY analyzed_at DESC""",
                    (org_id, repo_ref),
                ).fetchall()
            else:
                rows = conn.execute(
                    """SELECT * FROM dca_analyses
                       WHERE org_id = ?
                       ORDER BY analyzed_at DESC""",
                    (org_id,),
                ).fetchall()
        result: List[Dict[str, Any]] = []
        for r in rows:
            d = dict(r)
            try:
                d["languages"] = json.loads(d.pop("languages_json", "{}"))
            except (TypeError, ValueError):
                d["languages"] = {}
            result.append(d)
        return result

    def get_analysis_summary(self, analysis_id: str) -> Dict[str, Any]:
        """Return summary counts for a given analysis_id."""
        with self._lock, self._conn() as conn:
            analysis = conn.execute(
                "SELECT * FROM dca_analyses WHERE id = ?", (analysis_id,)
            ).fetchone()
            if not analysis:
                raise LookupError(f"analysis not found: {analysis_id}")

            symbol_rows = conn.execute(
                """SELECT symbol_type, COUNT(*) AS n
                   FROM dca_symbols WHERE analysis_id = ?
                   GROUP BY symbol_type""",
                (analysis_id,),
            ).fetchall()

            ep_count = conn.execute(
                "SELECT COUNT(*) AS n FROM dca_api_endpoints WHERE analysis_id = ?",
                (analysis_id,),
            ).fetchone()["n"]

            sensitive_count = conn.execute(
                """SELECT COUNT(*) AS n FROM dca_data_models
                   WHERE analysis_id = ? AND is_sensitive_bool = 1""",
                (analysis_id,),
            ).fetchone()["n"]

            total_model_count = conn.execute(
                "SELECT COUNT(*) AS n FROM dca_data_models WHERE analysis_id = ?",
                (analysis_id,),
            ).fetchone()["n"]

        return {
            "analysis_id": analysis_id,
            "org_id": analysis["org_id"],
            "repo_ref": analysis["repo_ref"],
            "commit_sha": analysis["commit_sha"],
            "analyzed_at": analysis["analyzed_at"],
            "total_files": analysis["total_files"],
            "total_symbols": analysis["total_symbols"],
            "counts_by_symbol_type": {row["symbol_type"]: row["n"] for row in symbol_rows},
            "api_endpoint_count": ep_count,
            "total_model_count": total_model_count,
            "sensitive_model_count": sensitive_count,
        }

    # ------------------------------------------------------------------
    # Cross-engine feed helpers — direct SQL to avoid import cycles
    # ------------------------------------------------------------------

    def _api_discovery_db_path(self) -> str:
        return str(self._data_dir / "api_discovery.db")

    def _data_classification_db_path(self, org_id: str) -> str:
        return str(self._data_dir / f"{org_id}_data_classification.db")

    def feed_api_discovery(self, analysis_id: str) -> Dict[str, Any]:
        """Write endpoints discovered by this analysis into api_discovery.db.

        Uses direct SQL (no Python import) to avoid cycles.
        """
        with self._lock, self._conn() as conn:
            analysis = conn.execute(
                "SELECT * FROM dca_analyses WHERE id = ?", (analysis_id,)
            ).fetchone()
            if not analysis:
                raise LookupError(f"analysis not found: {analysis_id}")
            rows = conn.execute(
                """SELECT method, path, handler_file, handler_line,
                          authenticated_bool, metadata_json
                   FROM dca_api_endpoints WHERE analysis_id = ?""",
                (analysis_id,),
            ).fetchall()

        org_id = analysis["org_id"]
        repo_ref = analysis["repo_ref"]
        target_db = self._api_discovery_db_path()
        Path(target_db).parent.mkdir(parents=True, exist_ok=True)

        with sqlite3.connect(target_db, timeout=10) as tgt:
            tgt.execute("PRAGMA journal_mode=WAL")
            # Match api_discovery_engine schema
            tgt.executescript(
                """
                CREATE TABLE IF NOT EXISTS api_endpoints (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    service_name    TEXT NOT NULL,
                    endpoint_path   TEXT NOT NULL,
                    http_method     TEXT NOT NULL,
                    version         TEXT NOT NULL DEFAULT '',
                    api_type        TEXT NOT NULL DEFAULT 'rest',
                    auth_required   INTEGER NOT NULL DEFAULT 1,
                    is_documented   INTEGER NOT NULL DEFAULT 0,
                    is_shadow       INTEGER NOT NULL DEFAULT 0,
                    risk_level      TEXT NOT NULL DEFAULT 'none',
                    last_observed   TEXT NOT NULL,
                    discovered_at   TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_ep_org
                    ON api_endpoints (org_id, service_name, is_shadow, risk_level, api_type);
                """
            )
            now = _now_iso()
            written = 0
            for r in rows:
                tgt.execute(
                    """INSERT INTO api_endpoints
                       (id, org_id, service_name, endpoint_path, http_method,
                        version, api_type, auth_required, is_documented,
                        is_shadow, risk_level, last_observed, discovered_at)
                       VALUES (?, ?, ?, ?, ?, '', 'rest', ?, 1, 0, 'none', ?, ?)""",
                    (
                        str(uuid.uuid4()),
                        org_id,
                        repo_ref,
                        r["path"],
                        r["method"],
                        1 if r["authenticated_bool"] else 0,
                        now,
                        now,
                    ),
                )
                written += 1
            tgt.commit()

        return {"analysis_id": analysis_id, "endpoints_written": written}

    def feed_data_classification(self, analysis_id: str) -> Dict[str, Any]:
        """Write sensitive models into data_classification's data_assets table.

        Uses direct SQL to avoid import cycles. One row per sensitive model.
        """
        with self._lock, self._conn() as conn:
            analysis = conn.execute(
                "SELECT * FROM dca_analyses WHERE id = ?", (analysis_id,)
            ).fetchone()
            if not analysis:
                raise LookupError(f"analysis not found: {analysis_id}")
            rows = conn.execute(
                """SELECT model_name, file_ref, fields_json
                   FROM dca_data_models
                   WHERE analysis_id = ? AND is_sensitive_bool = 1""",
                (analysis_id,),
            ).fetchall()

        org_id = analysis["org_id"]
        target_db = self._data_classification_db_path(org_id)
        Path(target_db).parent.mkdir(parents=True, exist_ok=True)

        with sqlite3.connect(target_db, timeout=10) as tgt:
            tgt.execute("PRAGMA journal_mode=WAL")
            tgt.executescript(
                """
                CREATE TABLE IF NOT EXISTS data_assets (
                    id                      TEXT PRIMARY KEY,
                    org_id                  TEXT NOT NULL,
                    name                    TEXT NOT NULL,
                    asset_type              TEXT NOT NULL DEFAULT 'database',
                    location                TEXT NOT NULL DEFAULT '',
                    owner_team              TEXT NOT NULL DEFAULT '',
                    classification_level    TEXT NOT NULL DEFAULT 'internal',
                    auto_classification_level TEXT NOT NULL DEFAULT '',
                    classification_method   TEXT NOT NULL DEFAULT 'manual',
                    pii_detected            INTEGER NOT NULL DEFAULT 0,
                    pii_types               TEXT NOT NULL DEFAULT '[]',
                    sensitivity_score       REAL NOT NULL DEFAULT 0.0,
                    last_scanned_at         DATETIME,
                    record_count            INTEGER NOT NULL DEFAULT 0,
                    data_residency          TEXT NOT NULL DEFAULT 'us',
                    created_at              DATETIME NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_da_org_level
                    ON data_assets (org_id, classification_level);
                CREATE INDEX IF NOT EXISTS idx_da_org_pii
                    ON data_assets (org_id, pii_detected);
                """
            )
            now = _now_iso()
            written = 0
            for r in rows:
                try:
                    fields = json.loads(r["fields_json"])
                except (TypeError, ValueError):
                    fields = []
                pii_types: List[str] = []
                for f in fields:
                    for pt in f.get("sensitive_types", []):
                        if pt not in pii_types:
                            pii_types.append(pt)
                tgt.execute(
                    """INSERT INTO data_assets
                       (id, org_id, name, asset_type, location, owner_team,
                        classification_level, auto_classification_level,
                        classification_method, pii_detected, pii_types,
                        sensitivity_score, last_scanned_at, record_count,
                        data_residency, created_at)
                       VALUES (?, ?, ?, 'code_repo', ?, '', 'confidential', 'confidential',
                               'auto', 1, ?, 70.0, ?, 0, 'us', ?)""",
                    (
                        str(uuid.uuid4()),
                        org_id,
                        r["model_name"],
                        r["file_ref"],
                        json.dumps(pii_types),
                        now,
                        now,
                    ),
                )
                written += 1
            tgt.commit()

        return {"analysis_id": analysis_id, "sensitive_models_written": written}

    def stats(self, org_id: str) -> Dict[str, Any]:
        """Aggregate per-org stats across all analyses."""
        with self._lock, self._conn() as conn:
            analyses = conn.execute(
                "SELECT COUNT(*) AS n, COALESCE(SUM(total_symbols), 0) AS s, "
                "COALESCE(SUM(total_files), 0) AS f FROM dca_analyses WHERE org_id = ?",
                (org_id,),
            ).fetchone()
            endpoint_row = conn.execute(
                """SELECT COUNT(*) AS n FROM dca_api_endpoints e
                   INNER JOIN dca_analyses a ON e.analysis_id = a.id
                   WHERE a.org_id = ?""",
                (org_id,),
            ).fetchone()
            sensitive_row = conn.execute(
                """SELECT COUNT(*) AS n FROM dca_data_models m
                   INNER JOIN dca_analyses a ON m.analysis_id = a.id
                   WHERE a.org_id = ? AND m.is_sensitive_bool = 1""",
                (org_id,),
            ).fetchone()
            total_models_row = conn.execute(
                """SELECT COUNT(*) AS n FROM dca_data_models m
                   INNER JOIN dca_analyses a ON m.analysis_id = a.id
                   WHERE a.org_id = ?""",
                (org_id,),
            ).fetchone()

        return {
            "org_id": org_id,
            "analysis_count": analyses["n"],
            "total_files": analyses["f"],
            "total_symbols": analyses["s"],
            "total_api_endpoints": endpoint_row["n"],
            "total_data_models": total_models_row["n"],
            "sensitive_data_models": sensitive_row["n"],
        }

    # ------------------------------------------------------------------
    # TrustGraph event emission (best-effort, non-blocking)
    # ------------------------------------------------------------------

    def _emit_event(self, event_type: str, payload: "dict[str, Any]") -> None:
        """Emit an event to the TrustGraph event bus. Never raises."""
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
                import asyncio
                import inspect
                if inspect.iscoroutine(result):
                    try:
                        loop = asyncio.get_running_loop()
                        loop.create_task(result)
                    except RuntimeError:
                        result.close()
            except Exception:  # pragma: no cover
                pass
        except Exception:  # pragma: no cover - best-effort telemetry
            pass




_singleton: Optional[DeepCodeAnalysisEngine] = None
_singleton_lock = threading.Lock()


def get_engine() -> DeepCodeAnalysisEngine:
    """Process-global singleton (for router use)."""
    global _singleton
    if _singleton is None:
        with _singleton_lock:
            if _singleton is None:
                _singleton = DeepCodeAnalysisEngine()
    return _singleton
