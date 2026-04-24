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
    # Stubs for non-Python languages
    # ------------------------------------------------------------------

    def _analyze_typescript(self, file_path: Path) -> Dict[str, Any]:
        # TODO(NEW-G070): implement TS/TSX AST extraction via tree-sitter
        raise NotImplementedError(
            "TypeScript analysis is a stub — tracked under NEW-G070"
        )

    def _analyze_javascript(self, file_path: Path) -> Dict[str, Any]:
        # TODO(NEW-G070): implement JS/JSX AST extraction via esprima / tree-sitter
        raise NotImplementedError(
            "JavaScript analysis is a stub — tracked under NEW-G070"
        )

    def _analyze_java(self, file_path: Path) -> Dict[str, Any]:
        # TODO(NEW-G070): implement Java AST extraction via javalang / tree-sitter
        raise NotImplementedError(
            "Java analysis is a stub — tracked under NEW-G070"
        )

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
                # Analyzers are stubs — do not call, just count. When called
                # directly via _analyze_typescript/_javascript/_java they raise.

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

        return {
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
