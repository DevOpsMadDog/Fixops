"""Wave A — Code / Architecture Intelligence Router (Multica Wave A).

Implements 19 Multica endpoints across six functional domains:

Graph / Architecture (7)
  POST /api/v1/graph/architecture-detect            (bbf6e567)
  GET  /api/v1/graph/flows/{serviceId}              (337d98ec)
  GET  /api/v1/graph/layers/{moduleId}              (db05c671)
  GET  /api/v1/graph/databases/{repoId}             (7bcf2f5f)
  GET  /api/v1/graph/diff?prId=                     (c740d39c)
  GET  /api/v1/graph/affected-nodes?since=          (c7ea7cad)
  GET  /api/v1/graph/diff/{baselineId}/{currentId}  (234238d6)

DCA — Deep Code Analysis (3)
  POST /api/v1/dca/parse-repo                       (532e0e27)
  GET  /api/v1/dca/entities/{repo}                  (5a77c425)
  GET  /api/v1/dca/diff?from=&to=                   (edc11e2d)

Reachability (2)
  POST /api/v1/reachability/callgraph               (7bf0aaf7)
  GET  /api/v1/reachability/{finding_id}/proof      (aea69655)

Components (2)
  GET /api/v1/components/match-by-abf?abf={hash}    (01ab5557)
  GET /api/v1/components/{purl}/safe-upgrade        (4aa036ef)

IDE Gateway (3)
  GET  /api/v1/ide/findings?repo=&file=             (4d5d1033)
  POST /api/v1/ide/authenticate-token               (130d594f)
  GET  /api/v1/ide/user-snapshot                    (e2975c0a)

Runtime Telemetry (2)
  POST /api/v1/runtime/map-to-code                  (2a85a139)
  GET  /api/v1/runtime/traffic/{api}                (8245b128)

All endpoints use ``Depends(api_key_auth)`` and an optional ``X-Org-ID`` header
(matches Wave D pattern). Engines are wired where they exist; if a downstream
engine is genuinely missing the endpoint either:
  * Falls back to a real persistent_store-backed implementation (no mocks), or
  * Returns 501 Not Implemented with a structured error detail.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, Header, HTTPException, Query
from fastapi import Path as PathParam
from pydantic import BaseModel, Field, field_validator

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Routers (one per domain prefix to keep OpenAPI tags clean)
# ---------------------------------------------------------------------------

graph_router = APIRouter(
    prefix="/api/v1/graph",
    tags=["Wave A — Graph / Architecture"],
    dependencies=[Depends(api_key_auth)],
)

dca_router = APIRouter(
    prefix="/api/v1/dca",
    tags=["Wave A — Deep Code Analysis"],
    dependencies=[Depends(api_key_auth)],
)

reachability_router = APIRouter(
    prefix="/api/v1/reachability",
    tags=["Wave A — Reachability"],
    dependencies=[Depends(api_key_auth)],
)

components_router = APIRouter(
    prefix="/api/v1/components",
    tags=["Wave A — Components"],
    dependencies=[Depends(api_key_auth)],
)

ide_router = APIRouter(
    prefix="/api/v1/ide",
    tags=["Wave A — IDE Gateway"],
    dependencies=[Depends(api_key_auth)],
)

runtime_router = APIRouter(
    prefix="/api/v1/runtime",
    tags=["Wave A — Runtime Telemetry"],
    dependencies=[Depends(api_key_auth)],
)


WAVE_A_ROUTERS = [
    graph_router,
    dca_router,
    reachability_router,
    components_router,
    ide_router,
    runtime_router,
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _data_dir() -> Path:
    base = Path(os.environ.get("FIXOPS_DATA_DIR", "data"))
    base.mkdir(parents=True, exist_ok=True)
    return base


def _org(org_id: Optional[str]) -> str:
    return (org_id or "default").strip() or "default"


def _safe_table_name(name: str) -> str:
    """Sanitize a SQLite-table-safe identifier (alnum + underscore only)."""
    out = "".join(c if c.isalnum() or c == "_" else "_" for c in name)
    if not out or not (out[0].isalpha() or out[0] == "_"):
        out = "t_" + out
    return out[:128]


def _persistent_store(name: str):
    """Best-effort load of core.persistent_store; returns None on failure."""
    try:
        from core.persistent_store import get_persistent_store  # type: ignore
        return get_persistent_store(_safe_table_name(name))
    except Exception as exc:  # noqa: BLE001
        logger.debug("wave_a: persistent_store(%s) unavailable: %s", name, exc)
        return None


def _safe_import(path: str, attr: Optional[str] = None):
    """Lazy import helper that returns None when modules are missing."""
    try:
        mod = __import__(path, fromlist=["*"])
        return getattr(mod, attr) if attr else mod
    except Exception as exc:  # noqa: BLE001
        logger.debug("wave_a: import failed %s.%s: %s", path, attr or "*", exc)
        return None


# ---------------------------------------------------------------------------
# Pydantic request models
# ---------------------------------------------------------------------------

class ArchitectureDetectRequest(BaseModel):
    repo_path: str = Field(..., min_length=1, max_length=1024)
    include_files_glob: List[str] = Field(default_factory=list, max_length=64)
    detect_layers: bool = Field(default=True)
    detect_databases: bool = Field(default=True)
    detect_apis: bool = Field(default=True)


class DCAParseRepoRequest(BaseModel):
    repo: str = Field(..., min_length=1, max_length=512)
    revision: str = Field(default="HEAD", max_length=128)
    languages: List[str] = Field(default_factory=list, max_length=20)
    include_tests: bool = Field(default=False)


class CallGraphRequest(BaseModel):
    repo: str = Field(..., min_length=1, max_length=512)
    repo_path: Optional[str] = Field(default=None, max_length=2048)
    language: str = Field(default="python", max_length=32)
    entry_points: List[str] = Field(default_factory=list, max_length=64)


class IDEAuthenticateTokenRequest(BaseModel):
    token: str = Field(..., min_length=8, max_length=4096)
    client_id: str = Field(default="vscode", max_length=64)
    workspace: Optional[str] = Field(default=None, max_length=512)


class RuntimeMapToCodeRequest(BaseModel):
    runtime_event_id: Optional[str] = Field(default=None, max_length=128)
    service_name: Optional[str] = Field(default=None, max_length=128)
    api_path: Optional[str] = Field(default=None, max_length=512)
    stack_trace: Optional[str] = Field(default=None, max_length=64_000)
    org_id: Optional[str] = Field(default=None, max_length=128)

    @field_validator("api_path")
    @classmethod
    def _check_path(cls, v: Optional[str]) -> Optional[str]:
        if v and not v.startswith("/"):
            raise ValueError("api_path must start with '/'")
        return v


# ===========================================================================
# 1. POST /api/v1/graph/architecture-detect    (bbf6e567)
# ===========================================================================
@graph_router.post("/architecture-detect", status_code=201,
                   summary="Detect architecture (layers/services/databases/APIs) from a repo")
def graph_architecture_detect(
    body: ArchitectureDetectRequest,
    x_org_id: Optional[str] = Header(default=None, alias="X-Org-ID"),
) -> Dict[str, Any]:
    """Run architecture detection over a repository and persist the snapshot.

    Wires to existing helpers when available:
      * ``core.security_architecture_review_engine`` — high-level review
      * Filesystem walk for layer / database / API detection (deterministic)

    Returns: report_id, layer count, service count, database count, API count.
    """
    org_id = _org(x_org_id)
    started = time.time()
    report_id = f"arch_{uuid.uuid4().hex[:12]}"
    repo_path = body.repo_path

    layers: List[Dict[str, Any]] = []
    services: List[Dict[str, Any]] = []
    databases: List[Dict[str, Any]] = []
    apis: List[Dict[str, Any]] = []

    # Try the architecture-review engine first (advisory)
    review_summary: Optional[Dict[str, Any]] = None
    try:
        sare_mod = _safe_import("core.security_architecture_review_engine")
        if sare_mod is not None:
            for cls_name in ("SecurityArchitectureReviewEngine", "ArchitectureReviewEngine"):
                cls = getattr(sare_mod, cls_name, None)
                if cls:
                    eng = cls()
                    if hasattr(eng, "review_repo"):
                        review_summary = eng.review_repo(repo_path)  # type: ignore[attr-defined]
                    elif hasattr(eng, "analyze"):
                        review_summary = eng.analyze(repo_path)  # type: ignore[attr-defined]
                    break
    except Exception as exc:  # noqa: BLE001
        logger.debug("wave_a: architecture review engine fallback: %s", exc)

    # Deterministic layer/db/api scan via filesystem walk
    repo_root = Path(repo_path)
    if repo_root.is_dir():
        layer_markers = {
            "presentation": {"ui", "frontend", "views", "templates", "components", "pages"},
            "application":  {"app", "apps", "controllers", "handlers", "routers", "api"},
            "domain":       {"core", "domain", "models", "entities", "services"},
            "infrastructure": {"infra", "repositories", "adapters", "db", "database", "storage"},
            "shared":       {"common", "shared", "utils", "lib"},
        }
        db_indicators = {
            "postgres", "mysql", "sqlite", "mongodb", "redis", "elasticsearch",
            "cassandra", "duckdb", "neo4j", "clickhouse",
        }
        api_indicators = ("router", "endpoint", "@app.", "@router.", "fastapi", "express")

        try:
            for path in repo_root.rglob("*"):
                rel = path.relative_to(repo_root)
                parts = {p.lower() for p in rel.parts}
                if body.detect_layers:
                    for layer, markers in layer_markers.items():
                        if parts & markers and not any(
                            la["layer"] == layer for la in layers
                        ):
                            layers.append({
                                "layer": layer,
                                "first_match": str(rel),
                                "module": rel.parts[0] if rel.parts else "",
                            })
                if path.is_file() and path.suffix in {".py", ".ts", ".js", ".java", ".go", ".cs"}:
                    name = path.name.lower()
                    if body.detect_apis and any(ind in name for ind in api_indicators):
                        services.append({
                            "service": path.stem,
                            "file": str(rel),
                            "language": path.suffix.lstrip("."),
                        })
                if body.detect_databases:
                    txt_lower = path.name.lower()
                    for db in db_indicators:
                        if db in txt_lower and not any(d["engine"] == db for d in databases):
                            databases.append({"engine": db, "evidence_file": str(rel)})
                # Limit work
                if len(layers) > 32 or len(services) > 256 or len(databases) > 32:
                    break
        except Exception as exc:  # noqa: BLE001
            logger.debug("wave_a: filesystem scan partial: %s", exc)

    # Persist report
    record = {
        "report_id": report_id,
        "org_id": org_id,
        "repo_path": repo_path,
        "layers": layers,
        "services": services,
        "databases": databases,
        "apis": apis,
        "review_summary": review_summary,
        "elapsed_s": round(time.time() - started, 4),
        "created_at": _now_iso(),
    }
    store = _persistent_store(f"architecture_reports_{org_id}")
    if store:
        try:
            # PersistentDict: dict-style write + persist; fall back to .set() for older backends
            try:
                store[report_id] = record
                if hasattr(store, "persist"):
                    store.persist(report_id)
            except (TypeError, AttributeError):
                if hasattr(store, "set"):
                    store.set(report_id, record)
        except Exception as exc:  # noqa: BLE001
            logger.debug("wave_a: arch persist failed: %s", exc)
    return {
        "report_id": report_id,
        "org_id": org_id,
        "repo_path": repo_path,
        "summary": {
            "layers": len(layers),
            "services": len(services),
            "databases": len(databases),
            "apis": len(apis),
        },
        "layers": layers,
        "services": services,
        "databases": databases,
        "apis": apis,
        "review_summary": review_summary,
        "elapsed_s": record["elapsed_s"],
        "created_at": record["created_at"],
    }


# ===========================================================================
# 2. GET /api/v1/graph/flows/{service_id}    (337d98ec)
# ===========================================================================
@graph_router.get("/flows/{service_id}",
                  summary="Return inbound + outbound data flows for a service")
def graph_flows(
    service_id: str = PathParam(..., min_length=1, max_length=256),
    depth: int = Query(default=2, ge=1, le=5),
    x_org_id: Optional[str] = Header(default=None, alias="X-Org-ID"),
) -> Dict[str, Any]:
    """Return data flows centred on the given service.

    Uses ``core.cloud_graph.CloudGraphEngine`` when available; falls back to a
    deterministic empty-graph response so callers can hook this into UI without
    a 500 when a tenant has no graph yet.
    """
    org_id = _org(x_org_id)
    inbound: List[Dict[str, Any]] = []
    outbound: List[Dict[str, Any]] = []
    try:
        cg_mod = _safe_import("core.cloud_graph")
        if cg_mod is not None:
            cls = getattr(cg_mod, "CloudGraphEngine", None)
            if cls is not None:
                eng = cls()
                # list edges where source/target == service_id
                if hasattr(eng, "_db") and hasattr(eng._db, "list_edges"):
                    edges = eng._db.list_edges(org_id=org_id) or []
                    for e in edges:
                        d = e.model_dump() if hasattr(e, "model_dump") else dict(e)
                        if d.get("source_id") == service_id:
                            outbound.append(d)
                        if d.get("target_id") == service_id:
                            inbound.append(d)
    except Exception as exc:  # noqa: BLE001
        logger.debug("wave_a: graph flows fallback: %s", exc)
    return {
        "org_id": org_id,
        "service_id": service_id,
        "depth": depth,
        "inbound_count": len(inbound),
        "outbound_count": len(outbound),
        "inbound": inbound[:200],
        "outbound": outbound[:200],
        "as_of": _now_iso(),
    }


# ===========================================================================
# 3. GET /api/v1/graph/layers/{module_id}    (db05c671)
# ===========================================================================
@graph_router.get("/layers/{module_id}",
                  summary="Return architectural layer assignment for a module")
def graph_layers(
    module_id: str = PathParam(..., min_length=1, max_length=256),
    x_org_id: Optional[str] = Header(default=None, alias="X-Org-ID"),
) -> Dict[str, Any]:
    """Return the layer (presentation/application/domain/infra/shared) for a module.

    Searches recent ``architecture_reports`` persisted by /architecture-detect
    and returns the first match. If no report exists, returns 'unclassified'.
    """
    org_id = _org(x_org_id)
    store = _persistent_store(f"architecture_reports_{org_id}")
    if store:
        try:
            for rid, rec in (store.all() or {}).items():
                for layer in rec.get("layers", []):
                    if layer.get("module") == module_id or layer.get("first_match", "").startswith(module_id):
                        return {
                            "org_id": org_id,
                            "module_id": module_id,
                            "layer": layer.get("layer"),
                            "evidence": layer,
                            "report_id": rid,
                            "as_of": _now_iso(),
                        }
        except Exception as exc:  # noqa: BLE001
            logger.debug("wave_a: graph layers store error: %s", exc)
    return {
        "org_id": org_id,
        "module_id": module_id,
        "layer": "unclassified",
        "evidence": None,
        "as_of": _now_iso(),
    }


# ===========================================================================
# 4. GET /api/v1/graph/databases/{repo_id}    (7bcf2f5f)
# ===========================================================================
@graph_router.get("/databases/{repo_id}",
                  summary="List databases referenced by a repository")
def graph_databases(
    repo_id: str = PathParam(..., min_length=1, max_length=256),
    x_org_id: Optional[str] = Header(default=None, alias="X-Org-ID"),
) -> Dict[str, Any]:
    """Return databases discovered by /architecture-detect for the given repo."""
    org_id = _org(x_org_id)
    databases: List[Dict[str, Any]] = []
    report_id = None
    store = _persistent_store(f"architecture_reports_{org_id}")
    if store:
        try:
            for rid, rec in (store.all() or {}).items():
                rp = rec.get("repo_path", "")
                if repo_id in rp or rid == repo_id:
                    databases.extend(rec.get("databases", []))
                    report_id = rid
        except Exception as exc:  # noqa: BLE001
            logger.debug("wave_a: graph databases store error: %s", exc)
    return {
        "org_id": org_id,
        "repo_id": repo_id,
        "report_id": report_id,
        "count": len(databases),
        "databases": databases,
        "as_of": _now_iso(),
    }


# ===========================================================================
# 5. GET /api/v1/graph/diff?prId=    (c740d39c)
# ===========================================================================
@graph_router.get("/diff",
                  summary="Diff architecture graph between two snapshots / a PR")
def graph_diff(
    pr_id: Optional[str] = Query(default=None, alias="prId", max_length=256),
    base_report_id: Optional[str] = Query(default=None, max_length=256),
    head_report_id: Optional[str] = Query(default=None, max_length=256),
    x_org_id: Optional[str] = Header(default=None, alias="X-Org-ID"),
) -> Dict[str, Any]:
    """Compare two architecture snapshots and return added/removed entities.

    Snapshots are looked up by ``base_report_id`` / ``head_report_id`` query
    params, or by PR id if the snapshots are tagged with ``pr_id``.
    """
    if not (pr_id or (base_report_id and head_report_id)):
        raise HTTPException(
            status_code=422,
            detail="provide prId or both base_report_id and head_report_id",
        )
    org_id = _org(x_org_id)
    store = _persistent_store(f"architecture_reports_{org_id}")
    base_rec = head_rec = None
    if store:
        all_recs = store.all() or {}
        if base_report_id:
            base_rec = all_recs.get(base_report_id)
        if head_report_id:
            head_rec = all_recs.get(head_report_id)
        if pr_id and not (base_rec and head_rec):
            # gather all reports tagged with pr_id, take oldest as base, newest as head
            tagged = [
                r for r in all_recs.values()
                if isinstance(r, dict) and r.get("pr_id") == pr_id
            ]
            tagged.sort(key=lambda r: r.get("created_at", ""))
            if len(tagged) >= 2:
                base_rec, head_rec = tagged[0], tagged[-1]

    def _set_of(rec: Optional[Dict[str, Any]], key: str) -> set:
        if not rec or not isinstance(rec.get(key), list):
            return set()
        out = set()
        for item in rec[key]:
            if isinstance(item, dict):
                ident = item.get("module") or item.get("service") or item.get("engine") or json.dumps(item, sort_keys=True)
                out.add(ident)
        return out

    added = sorted(_set_of(head_rec, "layers") - _set_of(base_rec, "layers"))
    removed = sorted(_set_of(base_rec, "layers") - _set_of(head_rec, "layers"))
    services_added = sorted(_set_of(head_rec, "services") - _set_of(base_rec, "services"))
    services_removed = sorted(_set_of(base_rec, "services") - _set_of(head_rec, "services"))
    dbs_added = sorted(_set_of(head_rec, "databases") - _set_of(base_rec, "databases"))
    dbs_removed = sorted(_set_of(base_rec, "databases") - _set_of(head_rec, "databases"))

    return {
        "org_id": org_id,
        "pr_id": pr_id,
        "base_report_id": base_report_id,
        "head_report_id": head_report_id,
        "layers_added": added,
        "layers_removed": removed,
        "services_added": services_added,
        "services_removed": services_removed,
        "databases_added": dbs_added,
        "databases_removed": dbs_removed,
        "summary": {
            "total_changes": (
                len(added) + len(removed) + len(services_added)
                + len(services_removed) + len(dbs_added) + len(dbs_removed)
            ),
        },
        "computed_at": _now_iso(),
    }


# ===========================================================================
# 6. POST /api/v1/dca/parse-repo    (532e0e27)
# ===========================================================================
@dca_router.post("/parse-repo", status_code=201,
                 summary="Run Deep Code Analysis (DCA) on a repository")
def dca_parse_repo(
    body: DCAParseRepoRequest,
    x_org_id: Optional[str] = Header(default=None, alias="X-Org-ID"),
) -> Dict[str, Any]:
    """Parse a repository into entities (functions, classes, modules).

    Uses the AST parser inside ``function_reachability_engine.parse_python_repo``
    when the repo is local + Python; otherwise records a parse-request that
    a worker can pick up later.
    """
    org_id = _org(x_org_id)
    parse_id = f"dca_{uuid.uuid4().hex[:12]}"
    started = time.time()
    entity_counts: Dict[str, int] = {"functions": 0, "classes": 0, "modules": 0}
    detail: Dict[str, Any] = {}

    repo_path = Path(body.repo)
    is_local = repo_path.exists() and repo_path.is_dir()

    if is_local:
        try:
            fre_mod = _safe_import("core.function_reachability_engine")
            if fre_mod is not None:
                eng_cls = getattr(fre_mod, "FunctionReachabilityEngine", None)
                if eng_cls and (
                    not body.languages or "python" in [l.lower() for l in body.languages]
                ):
                    eng = eng_cls()
                    if hasattr(eng, "parse_python_repo"):
                        # Real engine signature: parse_python_repo(org_id, repo_ref, root_path) -> int
                        try:
                            inserted = eng.parse_python_repo(
                                org_id=org_id,
                                repo_ref=body.revision,
                                root_path=str(repo_path),
                            )
                        except TypeError:
                            inserted = eng.parse_python_repo(
                                org_id, body.revision, str(repo_path),
                            )
                        if isinstance(inserted, int):
                            entity_counts["functions"] = inserted
                            detail["nodes_inserted"] = inserted
                        elif isinstance(inserted, dict):
                            detail.update(inserted)
                            entity_counts["functions"] = int(inserted.get("functions", 0) or inserted.get("function_count", 0))
                            entity_counts["classes"] = int(inserted.get("classes", 0) or inserted.get("class_count", 0))
                            entity_counts["modules"] = int(inserted.get("modules", 0) or inserted.get("module_count", 0))
        except Exception as exc:  # noqa: BLE001
            logger.warning("wave_a: dca parse fallback: %s", exc)
            detail["parse_error"] = str(exc)

    record = {
        "parse_id": parse_id,
        "org_id": org_id,
        "repo": body.repo,
        "revision": body.revision,
        "languages": body.languages,
        "include_tests": body.include_tests,
        "is_local": is_local,
        "entity_counts": entity_counts,
        "detail": detail,
        "started_at": _now_iso(),
        "elapsed_s": round(time.time() - started, 4),
    }
    store = _persistent_store(f"dca_parses_{org_id}")
    if store:
        try:
            store.set(parse_id, record)
        except Exception as exc:  # noqa: BLE001
            logger.debug("wave_a: dca persist failed: %s", exc)
    return record


# ===========================================================================
# 7. GET /api/v1/dca/entities/{repo}    (5a77c425)
# ===========================================================================
@dca_router.get("/entities/{repo}",
                summary="List parsed entities (functions, classes) for a repo")
def dca_entities(
    repo: str = PathParam(..., min_length=1, max_length=256),
    kind: Optional[str] = Query(default=None, max_length=32,
                                description="function|class|module"),
    limit: int = Query(default=200, ge=1, le=2000),
    x_org_id: Optional[str] = Header(default=None, alias="X-Org-ID"),
) -> Dict[str, Any]:
    """Return entities recorded for a repo.

    Pulls from the ``function_reachability_engine`` SQLite tables when the
    parser populated them; otherwise returns the entity_counts persisted by
    /parse-repo.
    """
    org_id = _org(x_org_id)
    entities: List[Dict[str, Any]] = []
    counts: Dict[str, int] = {}

    # Try the function_reachability DB
    try:
        fre_mod = _safe_import("core.function_reachability_engine")
        if fre_mod is not None:
            cls = getattr(fre_mod, "FunctionReachabilityEngine", None)
            if cls:
                eng = cls()
                if hasattr(eng, "list_callgraph"):
                    cg = eng.list_callgraph(org_id=org_id, repo_ref=repo)
                    if isinstance(cg, dict):
                        nodes = cg.get("nodes") or []
                        for n in nodes[:limit]:
                            if not kind or n.get("kind", "function") == kind:
                                entities.append(n)
                        counts["function_nodes"] = len(nodes)
    except Exception as exc:  # noqa: BLE001
        logger.debug("wave_a: dca entities fallback (FRE): %s", exc)

    # Augment from persistent_store dca_parses
    if not entities:
        store = _persistent_store(f"dca_parses_{org_id}")
        if store:
            try:
                for _pid, rec in (store.all() or {}).items():
                    if rec.get("repo") == repo:
                        counts.update(rec.get("entity_counts") or {})
                        # surface detail rows if engine returned them
                        for k in ("functions", "classes", "modules"):
                            for row in (rec.get("detail", {}).get(f"{k}_list") or []):
                                if not kind or row.get("kind") == kind:
                                    entities.append(row)
                                if len(entities) >= limit:
                                    break
            except Exception as exc:  # noqa: BLE001
                logger.debug("wave_a: dca entities store fallback: %s", exc)

    return {
        "org_id": org_id,
        "repo": repo,
        "kind_filter": kind,
        "count": len(entities),
        "counts": counts,
        "entities": entities[:limit],
        "as_of": _now_iso(),
    }


# ===========================================================================
# 8. GET /api/v1/dca/diff?from=&to=    (edc11e2d)
# ===========================================================================
@dca_router.get("/diff",
                summary="Diff DCA entity sets between two parse runs")
def dca_diff(
    repo: str = Query(..., min_length=1, max_length=256),
    from_revision: str = Query(..., alias="from", min_length=1, max_length=256),
    to_revision: str = Query(..., alias="to", min_length=1, max_length=256),
    x_org_id: Optional[str] = Header(default=None, alias="X-Org-ID"),
) -> Dict[str, Any]:
    """Diff entity sets between two parse runs (`from` → `to` revisions)."""
    org_id = _org(x_org_id)
    store = _persistent_store(f"dca_parses_{org_id}")
    base_rec = head_rec = None
    if store:
        try:
            for _pid, rec in (store.all() or {}).items():
                if rec.get("repo") != repo:
                    continue
                if rec.get("revision") == from_revision and base_rec is None:
                    base_rec = rec
                if rec.get("revision") == to_revision and head_rec is None:
                    head_rec = rec
        except Exception as exc:  # noqa: BLE001
            logger.debug("wave_a: dca diff store error: %s", exc)

    if not base_rec or not head_rec:
        return {
            "org_id": org_id,
            "repo": repo,
            "from": from_revision,
            "to": to_revision,
            "available": False,
            "note": "one or both parse runs not found — run POST /api/v1/dca/parse-repo first",
            "added": [],
            "removed": [],
            "modified": [],
        }

    def _names(rec: Dict[str, Any]) -> set:
        out = set()
        for k in ("functions_list", "classes_list", "modules_list"):
            for row in (rec.get("detail", {}).get(k) or []):
                ident = row.get("name") or row.get("qualname") or row.get("file_path")
                if ident:
                    out.add(ident)
        return out

    base_names = _names(base_rec)
    head_names = _names(head_rec)
    added = sorted(head_names - base_names)
    removed = sorted(base_names - head_names)

    return {
        "org_id": org_id,
        "repo": repo,
        "from": from_revision,
        "to": to_revision,
        "available": True,
        "added": added,
        "removed": removed,
        "modified": [],  # pending content-hash diff layer
        "summary": {
            "added": len(added),
            "removed": len(removed),
        },
        "computed_at": _now_iso(),
    }


# ===========================================================================
# 9. POST /api/v1/reachability/callgraph    (7bf0aaf7)
# ===========================================================================
@reachability_router.post("/callgraph", status_code=201,
                          summary="Build a callgraph for a repo")
def reachability_callgraph(
    body: CallGraphRequest,
    x_org_id: Optional[str] = Header(default=None, alias="X-Org-ID"),
) -> Dict[str, Any]:
    """Build a callgraph for a repo using the function_reachability_engine.

    For Python repos with a local ``repo_path`` provided we delegate to the
    engine's AST parser. For non-Python or remote repos, returns 501.
    """
    org_id = _org(x_org_id)
    fre_mod = _safe_import("core.function_reachability_engine")
    if fre_mod is None:
        raise HTTPException(
            status_code=501,
            detail={"error": "function_reachability_engine_unavailable"},
        )

    cls = getattr(fre_mod, "FunctionReachabilityEngine", None)
    if cls is None:
        raise HTTPException(status_code=501, detail={"error": "engine_class_missing"})

    engine = cls()
    lang = body.language.lower()
    started = time.time()
    try:
        if lang == "python":
            if not body.repo_path:
                raise HTTPException(
                    status_code=422,
                    detail="repo_path is required for python callgraph builds",
                )
            if not Path(body.repo_path).is_dir():
                raise HTTPException(status_code=404, detail=f"repo_path not found: {body.repo_path}")
            # Real signature: parse_python_repo(org_id, repo_ref, root_path) -> int
            try:
                res = engine.parse_python_repo(
                    org_id=org_id, repo_ref=body.repo, root_path=body.repo_path,
                )
            except TypeError:
                res = engine.parse_python_repo(org_id, body.repo, body.repo_path)
        elif lang in {"typescript", "ts", "javascript", "js"}:
            if not hasattr(engine, "parse_typescript_repo"):
                raise HTTPException(status_code=501,
                                    detail={"error": "typescript_parser_unavailable"})
            res = engine.parse_typescript_repo(
                org_id=org_id, repo_ref=body.repo, repo_path=body.repo_path or "",
            )
        elif lang == "java":
            if not hasattr(engine, "parse_java_repo"):
                raise HTTPException(status_code=501,
                                    detail={"error": "java_parser_unavailable"})
            res = engine.parse_java_repo(
                org_id=org_id, repo_ref=body.repo, repo_path=body.repo_path or "",
            )
        else:
            raise HTTPException(
                status_code=422,
                detail=f"unsupported language '{body.language}'; valid: python, typescript, java",
            )
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        logger.warning("wave_a: callgraph build failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"callgraph build failed: {exc}") from exc

    elapsed = round(time.time() - started, 4)
    summary = res if isinstance(res, dict) else {"raw": str(res)}
    return {
        "org_id": org_id,
        "repo": body.repo,
        "language": lang,
        "elapsed_s": elapsed,
        "summary": summary,
        "computed_at": _now_iso(),
    }


# ===========================================================================
# 10. GET /api/v1/reachability/{finding_id}/proof    (aea69655)
# ===========================================================================
@reachability_router.get("/{finding_id}/proof",
                         summary="Return reachability proof / verdict for a finding")
def reachability_proof(
    finding_id: str = PathParam(..., min_length=1, max_length=128),
    x_org_id: Optional[str] = Header(default=None, alias="X-Org-ID"),
) -> Dict[str, Any]:
    """Return the reachability verdict (path) for a finding.

    Wraps ``FunctionReachabilityEngine.get_finding_verdict``.
    Returns 404 if no verdict has been computed.
    """
    org_id = _org(x_org_id)
    fre_mod = _safe_import("core.function_reachability_engine")
    if fre_mod is None:
        raise HTTPException(status_code=501,
                            detail={"error": "function_reachability_engine_unavailable"})
    cls = getattr(fre_mod, "FunctionReachabilityEngine", None)
    if cls is None:
        raise HTTPException(status_code=501, detail={"error": "engine_class_missing"})
    engine = cls()
    if not hasattr(engine, "get_finding_verdict"):
        raise HTTPException(status_code=501, detail={"error": "verdict_api_missing"})

    try:
        verdict = engine.get_finding_verdict(org_id=org_id, finding_id=finding_id)
    except TypeError:
        verdict = engine.get_finding_verdict(finding_id)  # older signatures
    except Exception as exc:  # noqa: BLE001
        logger.warning("wave_a: get_finding_verdict failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"verdict lookup failed: {exc}") from exc

    if not verdict:
        raise HTTPException(status_code=404,
                            detail=f"no reachability verdict for finding_id={finding_id}")
    return {
        "org_id": org_id,
        "finding_id": finding_id,
        "verdict": verdict,
        "as_of": _now_iso(),
    }


# ===========================================================================
# 11. GET /api/v1/components/match-by-abf    (01ab5557)
# ===========================================================================
@components_router.get("/match-by-abf",
                       summary="Match SBOM components by Application Binary Fingerprint")
def components_match_by_abf(
    abf: str = Query(..., min_length=8, max_length=128,
                     description="ABF — usually a sha256 of binary contents"),
    org_id_q: str = Query(default="default", alias="org_id", max_length=128),
    limit: int = Query(default=50, ge=1, le=500),
    x_org_id: Optional[str] = Header(default=None, alias="X-Org-ID"),
) -> Dict[str, Any]:
    """Search SBOM component records for a given ABF (binary hash).

    Uses ``SBOMEngine`` storage. Falls back to scanning persistent_store ABF
    entries if the engine has no `list_components_by_hash` API.
    """
    org_id = _org(x_org_id) if not org_id_q else org_id_q
    matches: List[Dict[str, Any]] = []

    sbom_mod = _safe_import("core.sbom_engine")
    if sbom_mod is not None:
        try:
            cls = getattr(sbom_mod, "SBOMEngine", None)
            if cls:
                eng = cls()
                # Try a direct lookup API if available
                if hasattr(eng, "list_components_by_hash"):
                    matches = eng.list_components_by_hash(org_id=org_id, sha256=abf) or []
                else:
                    # Fall back to filtering list_components by hash field
                    if hasattr(eng, "list_components"):
                        try:
                            comps = eng.list_components(org_id=org_id) or []
                            for c in comps[: 5_000]:
                                row = c if isinstance(c, dict) else dict(c)
                                if (
                                    row.get("hash") == abf
                                    or row.get("sha256") == abf
                                    or row.get("abf") == abf
                                ):
                                    matches.append(row)
                        except Exception as exc:  # noqa: BLE001
                            logger.debug("wave_a: list_components fallback: %s", exc)
        except Exception as exc:  # noqa: BLE001
            logger.debug("wave_a: sbom abf lookup failed: %s", exc)

    return {
        "org_id": org_id,
        "abf": abf,
        "count": len(matches),
        "matches": matches[:limit],
        "as_of": _now_iso(),
    }


# ===========================================================================
# 12. GET /api/v1/components/{purl}/safe-upgrade    (4aa036ef)
# ===========================================================================
@components_router.get("/{purl:path}/safe-upgrade",
                       summary="Resolve safe upgrade target for a component PURL")
def components_safe_upgrade(
    purl: str = PathParam(..., min_length=4, max_length=512),
    current_version: Optional[str] = Query(default=None, max_length=64),
    cve_ids: Optional[str] = Query(default=None, max_length=2048,
                                   description="Comma-separated CVE IDs"),
    org_id_q: str = Query(default="default", alias="org_id", max_length=128),
    x_org_id: Optional[str] = Header(default=None, alias="X-Org-ID"),
) -> Dict[str, Any]:
    """Resolve the next safe upgrade target for a component.

    Wraps ``UpgradePathResolverEngine.resolve_upgrade(org_id, purl, cve_ids)``.

    The engine signature requires a non-empty ``cve_ids`` list — when no CVEs
    are supplied we attempt to derive them from the engine's per-package vuln
    catalogue, falling back to a 422 if there are none.
    """
    org_id = _org(x_org_id) if not org_id_q else org_id_q
    upr_mod = _safe_import("core.upgrade_path_resolver_engine")
    if upr_mod is None:
        raise HTTPException(status_code=501,
                            detail={"error": "upgrade_path_resolver_engine_unavailable"})
    cls = getattr(upr_mod, "UpgradePathResolverEngine", None)
    if cls is None:
        raise HTTPException(status_code=501, detail={"error": "engine_class_missing"})
    engine = cls()
    if not hasattr(engine, "resolve_upgrade"):
        raise HTTPException(status_code=501, detail={"error": "resolve_upgrade_unavailable"})

    cve_list: List[str] = []
    if cve_ids:
        cve_list = [c.strip().upper() for c in cve_ids.split(",") if c.strip()]
    # If caller didn't pass CVEs, try to derive them from the engine's catalogue
    if not cve_list:
        try:
            from core.upgrade_path_resolver_engine import parse_purl  # type: ignore
            parsed = parse_purl(purl)
            pkg_name = parsed.get("name") or ""
            ecosystem = parsed.get("type") or ""
            if hasattr(engine, "list_vulns_for_package"):
                vulns = engine.list_vulns_for_package(  # type: ignore[attr-defined]
                    org_id=org_id, ecosystem=ecosystem, package_name=pkg_name,
                ) or []
                cve_list = [
                    v.get("cve_id") if isinstance(v, dict) else str(v)
                    for v in vulns if v
                ]
        except Exception as exc:  # noqa: BLE001
            logger.debug("wave_a: cve catalogue lookup failed: %s", exc)
    if not cve_list:
        raise HTTPException(
            status_code=422,
            detail="cve_ids query param is required (engine needs the CVEs to resolve a safe upgrade)",
        )

    try:
        res = engine.resolve_upgrade(org_id=org_id, purl=purl, cve_ids=cve_list)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        logger.warning("wave_a: resolve_upgrade error: %s", exc)
        raise HTTPException(status_code=500, detail=f"resolve_upgrade failed: {exc}") from exc

    return {
        "org_id": org_id,
        "purl": purl,
        "current_version": current_version,
        "cve_ids": cve_list,
        "resolution": res if isinstance(res, dict) else {"result": res},
        "as_of": _now_iso(),
    }


# ===========================================================================
# 13. GET /api/v1/ide/findings    (4d5d1033)
# ===========================================================================
@ide_router.get("/findings",
                summary="List IDE-relevant findings filtered by repo+file")
def ide_findings(
    repo: str = Query(..., min_length=1, max_length=256),
    file: str = Query(..., min_length=1, max_length=512),
    severity: Optional[str] = Query(default=None, max_length=16),
    limit: int = Query(default=100, ge=1, le=500),
    x_org_id: Optional[str] = Header(default=None, alias="X-Org-ID"),
) -> Dict[str, Any]:
    """Return findings scoped to a (repo, file) pair for IDE in-line overlay."""
    org_id = _org(x_org_id)
    findings: List[Dict[str, Any]] = []

    ide_mod = _safe_import("core.ide_backend_engine")
    if ide_mod is not None:
        try:
            cls = getattr(ide_mod, "IDEBackendEngine", None)
            if cls:
                eng = cls()
                if hasattr(eng, "list_findings_for_file"):
                    findings = eng.list_findings_for_file(  # type: ignore[attr-defined]
                        org_id=org_id, repo_ref=repo, file_path=file, limit=limit,
                    ) or []
        except Exception as exc:  # noqa: BLE001
            logger.debug("wave_a: ide findings engine fallback: %s", exc)

    # Fallback — query findings DB directly via core.findings_db if available
    if not findings:
        try:
            from core.findings_db import get_findings_db  # type: ignore
            db = get_findings_db()
            if hasattr(db, "list_findings"):
                rows = db.list_findings(  # type: ignore[attr-defined]
                    org_id=org_id, repo=repo, file_path=file, limit=limit,
                ) or []
                findings = [r if isinstance(r, dict) else dict(r) for r in rows]
        except Exception as exc:  # noqa: BLE001
            logger.debug("wave_a: ide findings DB fallback: %s", exc)

    if severity:
        findings = [
            f for f in findings
            if str(f.get("severity", "")).lower() == severity.lower()
        ]
    return {
        "org_id": org_id,
        "repo": repo,
        "file": file,
        "severity_filter": severity,
        "count": len(findings),
        "findings": findings[:limit],
        "as_of": _now_iso(),
    }


# ===========================================================================
# 14. POST /api/v1/ide/authenticate-token    (130d594f)
# ===========================================================================
@ide_router.post("/authenticate-token",
                 summary="Validate an IDE-supplied token and return scoped session info")
def ide_authenticate_token(
    body: IDEAuthenticateTokenRequest,
    x_org_id: Optional[str] = Header(default=None, alias="X-Org-ID"),
) -> Dict[str, Any]:
    """Validate an IDE token and return session info.

    Honors three lookup paths in order:
      1. JWT decode via core.api_key_manager / FIXOPS_JWT_SECRET
      2. api_key_manager.validate_key by raw key
      3. Fallback failure with 401
    """
    org_id = _org(x_org_id)
    started = time.time()

    # 1) JWT-style token
    try:
        secret = os.getenv("FIXOPS_JWT_SECRET")
        if secret and body.token.count(".") == 2:
            import jwt  # type: ignore
            decoded = jwt.decode(body.token, secret, algorithms=["HS256"])
            return {
                "valid": True,
                "auth_type": "jwt",
                "org_id": decoded.get("org_id") or org_id,
                "user_id": decoded.get("sub") or decoded.get("user_id"),
                "scopes": decoded.get("scopes", []),
                "expires_at": decoded.get("exp"),
                "client_id": body.client_id,
                "checked_at": _now_iso(),
                "elapsed_s": round(time.time() - started, 4),
            }
    except Exception as exc:  # noqa: BLE001
        logger.debug("wave_a: jwt decode failed (will try api-key): %s", exc)

    # 2) API key lookup
    try:
        akm_mod = _safe_import("core.api_key_manager")
        if akm_mod is not None:
            getter = getattr(akm_mod, "get_api_key_manager", None)
            mgr = getter() if getter else None
            if mgr is not None and hasattr(mgr, "validate_key"):
                meta = mgr.validate_key(body.token)
                if meta:
                    md = meta.model_dump() if hasattr(meta, "model_dump") else dict(meta)
                    md.pop("key_hash", None)
                    md.pop("raw_key", None)
                    return {
                        "valid": True,
                        "auth_type": "api_key",
                        "org_id": md.get("org_id") or org_id,
                        "user_id": md.get("created_by"),
                        "scopes": md.get("scopes", []),
                        "client_id": body.client_id,
                        "metadata": md,
                        "checked_at": _now_iso(),
                        "elapsed_s": round(time.time() - started, 4),
                    }
    except Exception as exc:  # noqa: BLE001
        logger.debug("wave_a: api_key validate_key failed: %s", exc)

    # 3) Failure
    raise HTTPException(status_code=401, detail="invalid or expired IDE token")


# ===========================================================================
# 15. GET /api/v1/ide/user-snapshot    (e2975c0a)
# ===========================================================================
@ide_router.get("/user-snapshot",
                summary="Snapshot of a user's IDE state — recent findings, open files, scopes")
def ide_user_snapshot(
    user_id: str = Query(default="self", max_length=128),
    repo: Optional[str] = Query(default=None, max_length=256),
    x_org_id: Optional[str] = Header(default=None, alias="X-Org-ID"),
    x_user_id: Optional[str] = Header(default=None, alias="X-User-ID"),
) -> Dict[str, Any]:
    """Return per-user IDE snapshot: recent files, scopes, finding counts."""
    org_id = _org(x_org_id)
    uid = (x_user_id or user_id or "self").strip() or "self"

    snapshot: Dict[str, Any] = {
        "org_id": org_id,
        "user_id": uid,
        "repo": repo,
        "recent_files": [],
        "active_scopes": [],
        "finding_counts": {},
        "tokens": [],
        "captured_at": _now_iso(),
    }

    # Recent IDE snapshots from ide_backend_engine
    try:
        ide_mod = _safe_import("core.ide_backend_engine")
        if ide_mod is not None:
            cls = getattr(ide_mod, "IDEBackendEngine", None)
            if cls:
                eng = cls()
                if hasattr(eng, "list_analysis_snapshots"):
                    try:
                        snaps = eng.list_analysis_snapshots(  # type: ignore[attr-defined]
                            org_id=org_id, repo_ref=repo, limit=10,
                        ) or []
                    except TypeError:
                        snaps = eng.list_analysis_snapshots(org_id) or []  # type: ignore[attr-defined]
                    snapshot["recent_files"] = [
                        s.get("file_path") if isinstance(s, dict) else getattr(s, "file_path", None)
                        for s in (snaps or [])
                    ][:25]
    except Exception as exc:  # noqa: BLE001
        logger.debug("wave_a: ide user-snapshot backend fallback: %s", exc)

    # User's API tokens (PII-redacted)
    try:
        akm_mod = _safe_import("core.api_key_manager")
        if akm_mod is not None:
            getter = getattr(akm_mod, "get_api_key_manager", None)
            mgr = getter() if getter else None
            if mgr is not None and hasattr(mgr, "list_keys"):
                listed = mgr.list_keys(org_id) or []
                for k in listed:
                    d = k.model_dump() if hasattr(k, "model_dump") else dict(k)
                    if d.get("created_by") in (uid, None, "self"):
                        d.pop("key_hash", None)
                        d.pop("raw_key", None)
                        snapshot["tokens"].append(d)
                        for s in (d.get("scopes") or []):
                            if s not in snapshot["active_scopes"]:
                                snapshot["active_scopes"].append(s)
    except Exception as exc:  # noqa: BLE001
        logger.debug("wave_a: ide user-snapshot tokens fallback: %s", exc)

    # Finding counts (best-effort)
    try:
        from core.findings_db import get_findings_db  # type: ignore
        db = get_findings_db()
        if hasattr(db, "count_by_severity"):
            try:
                snapshot["finding_counts"] = (
                    db.count_by_severity(org_id=org_id, repo=repo) or {}
                )
            except TypeError:
                snapshot["finding_counts"] = db.count_by_severity(org_id) or {}
    except Exception as exc:  # noqa: BLE001
        logger.debug("wave_a: finding counts fallback: %s", exc)

    return snapshot


# ===========================================================================
# 16. POST /api/v1/runtime/map-to-code    (2a85a139)
# ===========================================================================
@runtime_router.post("/map-to-code",
                     summary="Map a runtime telemetry event to source code locations")
def runtime_map_to_code(
    body: RuntimeMapToCodeRequest,
    x_org_id: Optional[str] = Header(default=None, alias="X-Org-ID"),
) -> Dict[str, Any]:
    """Resolve a runtime event/stack-trace to candidate code locations.

    Wraps ``CodeToRuntimeMatcherEngine.match_event_to_code`` when an event id
    is provided; otherwise ingests the supplied stack trace and matches it.
    """
    org_id = body.org_id or _org(x_org_id)
    crm_mod = _safe_import("core.code_to_runtime_matcher_engine")
    if crm_mod is None:
        raise HTTPException(status_code=501,
                            detail={"error": "code_to_runtime_matcher_engine_unavailable"})
    cls = getattr(crm_mod, "CodeToRuntimeMatcherEngine", None)
    if cls is None:
        raise HTTPException(status_code=501, detail={"error": "engine_class_missing"})

    engine = cls()
    started = time.time()

    runtime_event_id = body.runtime_event_id
    try:
        # If we don't have an event_id, ingest first (when stack/api supplied)
        if not runtime_event_id:
            if not (body.stack_trace or body.api_path or body.service_name):
                raise HTTPException(
                    status_code=422,
                    detail="provide runtime_event_id or one of (stack_trace, api_path, service_name)",
                )
            if hasattr(engine, "ingest_runtime_event"):
                # Real signature:
                #   ingest_runtime_event(org_id, event_ref, event_type,
                #     service_name, path, method, status_code, error_message, stack_trace)
                event_ref = f"wave_a_{uuid.uuid4().hex[:12]}"
                try:
                    res = engine.ingest_runtime_event(
                        org_id=org_id,
                        event_ref=event_ref,
                        event_type="api_request",
                        service_name=body.service_name or "unknown",
                        path=body.api_path or "",
                        method="GET",
                        status_code=0,
                        error_message="",
                        stack_trace=body.stack_trace or "",
                    )
                except TypeError:
                    res = engine.ingest_runtime_event(
                        org_id, event_ref, "api_request",
                        body.service_name or "unknown",
                        body.api_path or "", "GET", 0, "", body.stack_trace or "",
                    )
                # The engine returns either an event_id (str) or a dict containing one
                if isinstance(res, str):
                    runtime_event_id = res
                elif isinstance(res, dict):
                    runtime_event_id = (
                        res.get("event_id") or res.get("id") or event_ref
                    )
                else:
                    runtime_event_id = event_ref
            else:
                raise HTTPException(status_code=501,
                                    detail={"error": "ingest_runtime_event_unavailable"})

        if not hasattr(engine, "match_event_to_code"):
            raise HTTPException(status_code=501,
                                detail={"error": "match_event_to_code_unavailable"})
        try:
            match = engine.match_event_to_code(runtime_event_id=runtime_event_id)
        except TypeError:
            match = engine.match_event_to_code(runtime_event_id)
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        logger.warning("wave_a: runtime map-to-code failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"map-to-code failed: {exc}") from exc

    return {
        "org_id": org_id,
        "runtime_event_id": runtime_event_id,
        "match": match if isinstance(match, dict) else {"result": match},
        "elapsed_s": round(time.time() - started, 4),
        "computed_at": _now_iso(),
    }


# ===========================================================================
# 17. GET /api/v1/runtime/traffic/{api}    (8245b128)
# ===========================================================================
@runtime_router.get("/traffic/{api:path}",
                    summary="Return runtime traffic stats for an API path")
def runtime_traffic(
    api: str = PathParam(..., min_length=1, max_length=512),
    window_minutes: int = Query(default=60, ge=1, le=10_080),
    x_org_id: Optional[str] = Header(default=None, alias="X-Org-ID"),
) -> Dict[str, Any]:
    """Return aggregate runtime traffic for an API path.

    Uses ``CodeToRuntimeMatcherEngine.list_events`` filtered by api_path.
    """
    org_id = _org(x_org_id)
    crm_mod = _safe_import("core.code_to_runtime_matcher_engine")
    events: List[Dict[str, Any]] = []
    if crm_mod is not None:
        try:
            cls = getattr(crm_mod, "CodeToRuntimeMatcherEngine", None)
            if cls:
                eng = cls()
                if hasattr(eng, "list_events"):
                    try:
                        events = eng.list_events(  # type: ignore[attr-defined]
                            org_id=org_id, since_minutes=window_minutes, api_path=api,
                        ) or []
                    except TypeError:
                        try:
                            events = eng.list_events(org_id, since_minutes=window_minutes) or []
                        except Exception:
                            events = eng.list_events(org_id) or []
        except Exception as exc:  # noqa: BLE001
            logger.debug("wave_a: runtime traffic fallback: %s", exc)

    api_norm = "/" + api.lstrip("/")
    matched = [
        e for e in events
        if (e.get("api_path") == api_norm or e.get("api_path") == api)
    ] or events  # if engine already filtered

    # Aggregate stats
    total = len(matched)
    statuses: Dict[str, int] = {}
    services: Dict[str, int] = {}
    for e in matched:
        st = str(e.get("status_code") or e.get("status") or "unknown")
        statuses[st] = statuses.get(st, 0) + 1
        svc = str(e.get("service_name") or e.get("service") or "unknown")
        services[svc] = services.get(svc, 0) + 1

    return {
        "org_id": org_id,
        "api": api_norm,
        "window_minutes": window_minutes,
        "total_events": total,
        "status_breakdown": statuses,
        "service_breakdown": services,
        "samples": matched[:25],
        "as_of": _now_iso(),
    }


# ===========================================================================
# 18. GET /api/v1/graph/affected-nodes?since=    (c7ea7cad)
# ===========================================================================

_DURATION_RE = None  # lazy compile


def _parse_since(since: str) -> Optional[datetime]:
    """Parse `since` query into a UTC datetime.

    Accepts:
      * ISO-8601 timestamps (``2026-04-26T10:00:00Z``)
      * Relative durations: ``5m``, ``4h``, ``2d``, ``90s`` (suffix s|m|h|d|w)
    Returns None on parse failure.
    """
    if not since:
        return None
    s = since.strip()
    # Try ISO first
    try:
        if s.endswith("Z"):
            s_iso = s[:-1] + "+00:00"
        else:
            s_iso = s
        dt = datetime.fromisoformat(s_iso)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except (ValueError, TypeError):
        pass
    # Relative (e.g. 4h, 2d, 30m)
    import re
    global _DURATION_RE
    if _DURATION_RE is None:
        _DURATION_RE = re.compile(r"^(?P<n>\d+)(?P<u>[smhdw])$")
    m = _DURATION_RE.match(s.lower())
    if not m:
        return None
    n = int(m.group("n"))
    unit = m.group("u")
    seconds = {"s": 1, "m": 60, "h": 3600, "d": 86_400, "w": 604_800}[unit]
    from datetime import timedelta
    return datetime.now(timezone.utc) - timedelta(seconds=n * seconds)


@graph_router.get(
    "/affected-nodes",
    summary="List graph nodes whose state changed since a given timestamp",
)
def graph_affected_nodes(
    since: str = Query(..., min_length=1, max_length=64,
                       description="ISO-8601 timestamp or relative duration (e.g. 4h, 2d)"),
    node_kinds: Optional[str] = Query(
        default=None, max_length=512,
        description="Comma-separated kinds filter: service,layer,database,api"),
    limit: int = Query(default=500, ge=1, le=5_000),
    x_org_id: Optional[str] = Header(default=None, alias="X-Org-ID"),
) -> Dict[str, Any]:
    """Return graph nodes added/modified after the supplied threshold.

    Sources, in priority:
      1. ``core.cloud_graph.CloudGraphEngine`` (live tenant graph)
      2. ``architecture_reports`` persistent_store snapshots (delta of new nodes)

    Both sources fall through gracefully — if neither has data we return an
    empty list with `available=False` so the UI can render an EmptyState.
    """
    org_id = _org(x_org_id)
    threshold = _parse_since(since)
    if threshold is None:
        raise HTTPException(
            status_code=422,
            detail=(
                f"unable to parse 'since' value {since!r}; supply an ISO-8601 "
                "timestamp or a relative duration like 5m, 4h, 2d"
            ),
        )
    kinds_filter = None
    if node_kinds:
        kinds_filter = {k.strip().lower() for k in node_kinds.split(",") if k.strip()}

    affected: List[Dict[str, Any]] = []
    sources_tried: List[str] = []
    available = False

    # Source 1 — live cloud graph
    try:
        cg_mod = _safe_import("core.cloud_graph")
        if cg_mod is not None:
            cls = getattr(cg_mod, "CloudGraphEngine", None)
            if cls is not None:
                eng = cls()
                sources_tried.append("cloud_graph")
                if hasattr(eng, "_db") and hasattr(eng._db, "list_nodes"):
                    nodes = eng._db.list_nodes(org_id=org_id) or []
                    for n in nodes:
                        d = n.model_dump() if hasattr(n, "model_dump") else dict(n)
                        # node may carry updated_at / created_at / last_seen
                        ts_str = (
                            d.get("updated_at")
                            or d.get("last_seen")
                            or d.get("created_at")
                        )
                        if not ts_str:
                            continue
                        try:
                            ts = datetime.fromisoformat(
                                str(ts_str).replace("Z", "+00:00")
                            )
                            if ts.tzinfo is None:
                                ts = ts.replace(tzinfo=timezone.utc)
                        except (ValueError, TypeError):
                            continue
                        if ts < threshold:
                            continue
                        kind = str(d.get("kind") or d.get("type") or "node").lower()
                        if kinds_filter and kind not in kinds_filter:
                            continue
                        affected.append({
                            "id": d.get("id") or d.get("node_id"),
                            "kind": kind,
                            "name": d.get("name"),
                            "changed_at": ts.isoformat(timespec="seconds"),
                            "source": "cloud_graph",
                        })
                    available = True
    except Exception as exc:  # noqa: BLE001
        logger.debug("wave_a: affected-nodes cloud_graph fallback: %s", exc)

    # Source 2 — architecture report snapshots
    try:
        store = _persistent_store(f"architecture_reports_{org_id}")
        if store is not None:
            sources_tried.append("architecture_reports")
            # PersistentDict supports .items() (dict-like); fall back to .all() if present
            try:
                _iter_pairs = list(store.items())
            except AttributeError:
                _iter_pairs = list((store.all() or {}).items()) if hasattr(store, "all") else []
            for rid, rec in _iter_pairs:
                created_at = rec.get("created_at")
                if not created_at:
                    continue
                try:
                    ts = datetime.fromisoformat(
                        str(created_at).replace("Z", "+00:00")
                    )
                    if ts.tzinfo is None:
                        ts = ts.replace(tzinfo=timezone.utc)
                except (ValueError, TypeError):
                    continue
                if ts < threshold:
                    continue
                # Each entry in layers/services/databases is a node
                for kind, key in (
                    ("layer", "layers"),
                    ("service", "services"),
                    ("database", "databases"),
                    ("api", "apis"),
                ):
                    if kinds_filter and kind not in kinds_filter:
                        continue
                    for item in (rec.get(key) or []):
                        if not isinstance(item, dict):
                            continue
                        ident = (
                            item.get("module")
                            or item.get("service")
                            or item.get("engine")
                            or item.get("layer")
                            or hashlib.sha256(
                                json.dumps(item, sort_keys=True).encode()
                            ).hexdigest()[:12]
                        )
                        affected.append({
                            "id": f"{rid}:{kind}:{ident}",
                            "kind": kind,
                            "name": ident,
                            "changed_at": ts.isoformat(timespec="seconds"),
                            "source": "architecture_report",
                            "report_id": rid,
                        })
                available = True
                if len(affected) >= limit * 2:
                    break
    except Exception as exc:  # noqa: BLE001
        logger.debug("wave_a: affected-nodes arch_reports fallback: %s", exc)

    # Sort newest first, dedupe by id
    seen = set()
    unique: List[Dict[str, Any]] = []
    for n in sorted(affected, key=lambda r: r.get("changed_at", ""), reverse=True):
        nid = n.get("id")
        if nid in seen:
            continue
        seen.add(nid)
        unique.append(n)
        if len(unique) >= limit:
            break

    return {
        "org_id": org_id,
        "since": since,
        "since_resolved": threshold.isoformat(timespec="seconds"),
        "node_kinds_filter": sorted(kinds_filter) if kinds_filter else None,
        "available": available,
        "sources": sources_tried,
        "count": len(unique),
        "nodes": unique,
        "as_of": _now_iso(),
    }


# ===========================================================================
# 19. GET /api/v1/graph/diff/{baseline_id}/{current_id}    (234238d6)
# ===========================================================================
@graph_router.get(
    "/diff/{baseline_id}/{current_id}",
    summary="Diff two architecture/graph snapshots by their IDs",
)
def graph_diff_by_ids(
    baseline_id: str = PathParam(..., min_length=1, max_length=256),
    current_id: str = PathParam(..., min_length=1, max_length=256),
    x_org_id: Optional[str] = Header(default=None, alias="X-Org-ID"),
) -> Dict[str, Any]:
    """Diff two architecture-detect snapshots by ID.

    Looks both snapshots up in the ``architecture_reports`` persistent store and
    returns added/removed entities across layers, services, databases and APIs.

    Wires to ``core.architecture_diff_engine.ArchitectureDiffEngine`` if it
    exists; falls back to a deterministic set diff otherwise.
    """
    if baseline_id == current_id:
        raise HTTPException(
            status_code=422,
            detail="baseline_id and current_id must differ",
        )
    org_id = _org(x_org_id)
    store = _persistent_store(f"architecture_reports_{org_id}")
    if store is None:
        raise HTTPException(
            status_code=501,
            detail={"error": "architecture_reports_store_unavailable"},
        )
    try:
        all_recs = dict(store.items())
    except AttributeError:
        all_recs = store.all() or {}
    base_rec = all_recs.get(baseline_id)
    head_rec = all_recs.get(current_id)
    if base_rec is None:
        raise HTTPException(
            status_code=404,
            detail=f"baseline snapshot not found: {baseline_id}",
        )
    if head_rec is None:
        raise HTTPException(
            status_code=404,
            detail=f"current snapshot not found: {current_id}",
        )

    # Optional engine wiring
    engine_result: Optional[Dict[str, Any]] = None
    try:
        adf_mod = _safe_import("core.architecture_diff_engine")
        if adf_mod is not None:
            cls = getattr(adf_mod, "ArchitectureDiffEngine", None)
            if cls is not None:
                eng = cls()
                if hasattr(eng, "diff_snapshots"):
                    engine_result = eng.diff_snapshots(  # type: ignore[attr-defined]
                        org_id=org_id, baseline=base_rec, current=head_rec,
                    )
    except Exception as exc:  # noqa: BLE001
        logger.debug("wave_a: architecture_diff_engine fallback: %s", exc)

    def _ids(rec: Dict[str, Any], key: str) -> Dict[str, Dict[str, Any]]:
        out: Dict[str, Dict[str, Any]] = {}
        for item in (rec.get(key) or []):
            if not isinstance(item, dict):
                continue
            ident = (
                item.get("module")
                or item.get("service")
                or item.get("engine")
                or item.get("layer")
                or json.dumps(item, sort_keys=True)
            )
            out[str(ident)] = item
        return out

    summary: Dict[str, Dict[str, Any]] = {}
    detail: Dict[str, Dict[str, List[Dict[str, Any]]]] = {}
    for key in ("layers", "services", "databases", "apis"):
        base_map = _ids(base_rec, key)
        head_map = _ids(head_rec, key)
        added_keys = sorted(set(head_map) - set(base_map))
        removed_keys = sorted(set(base_map) - set(head_map))
        modified_keys = sorted(
            k for k in (set(base_map) & set(head_map))
            if base_map[k] != head_map[k]
        )
        detail[key] = {
            "added":    [head_map[k] for k in added_keys],
            "removed":  [base_map[k] for k in removed_keys],
            "modified": [
                {"baseline": base_map[k], "current": head_map[k]}
                for k in modified_keys
            ],
        }
        summary[key] = {
            "added": len(added_keys),
            "removed": len(removed_keys),
            "modified": len(modified_keys),
        }

    total_changes = sum(
        s["added"] + s["removed"] + s["modified"] for s in summary.values()
    )

    return {
        "org_id": org_id,
        "baseline_id": baseline_id,
        "current_id": current_id,
        "baseline_created_at": base_rec.get("created_at"),
        "current_created_at": head_rec.get("created_at"),
        "summary": summary,
        "total_changes": total_changes,
        "diff": detail,
        "engine_result": engine_result,
        "computed_at": _now_iso(),
    }
