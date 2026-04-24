"""Security Dependency Mapping Engine — ALDECI.

Maps service-to-service dependencies and computes blast radius via BFS traversal
for security impact analysis during incidents and vulnerability management.

Features:
- Service registry with criticality and data classification
- Directed dependency graph with runtime/build/optional types
- BFS blast radius: downstream (who is affected if I go down) / upstream (what do I depend on)
- Critical path identification: most depended-upon critical services
- Summary with high_blast_radius_services (dependent_count >= 5)

Compliance: NIST SP 800-53 SA-9 (External System Services), ISO 27001 A.15,
            CIS Control 12 (Network Infrastructure Management)
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import uuid
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "security_dependency_mapping.db"
)

_VALID_SERVICE_TYPES = {
    "application", "database", "api", "queue", "cache",
    "auth", "monitoring", "storage", "network", "external",
}
_VALID_DEPENDENCY_TYPES = {"runtime", "build", "test", "optional", "fallback"}
_VALID_CRITICALITIES = {"critical", "high", "medium", "low"}
_VALID_ENVIRONMENTS = {"production", "staging", "development", "dr"}
_VALID_DATA_CLASSIFICATIONS = {"public", "internal", "confidential", "restricted"}

_MAX_BFS_DEPTH = 10


class SecurityDependencyMappingEngine:
    """Engine for mapping service dependencies and computing blast radius."""

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self.db_path = db_path
        self._lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------
    # DB INIT
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS layer_classifications (
                    id               TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    node_ref         TEXT NOT NULL,
                    layer            TEXT NOT NULL,
                    confidence       REAL NOT NULL DEFAULT 0.0,
                    signals_json     TEXT NOT NULL DEFAULT '[]',
                    classified_at    TEXT NOT NULL,
                    UNIQUE(org_id, node_ref)
                );

                CREATE INDEX IF NOT EXISTS idx_lc_org   ON layer_classifications(org_id);
                CREATE INDEX IF NOT EXISTS idx_lc_layer ON layer_classifications(org_id, layer);

                CREATE TABLE IF NOT EXISTS services (
                    id                  TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    service_name        TEXT NOT NULL,
                    service_type        TEXT NOT NULL DEFAULT 'application',
                    criticality         TEXT NOT NULL DEFAULT 'medium',
                    owner               TEXT NOT NULL DEFAULT '',
                    environment         TEXT NOT NULL DEFAULT 'production',
                    data_classification TEXT NOT NULL DEFAULT 'internal',
                    status              TEXT NOT NULL DEFAULT 'active',
                    dependency_count    INTEGER NOT NULL DEFAULT 0,
                    dependent_count     INTEGER NOT NULL DEFAULT 0,
                    created_at          TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_svc_org  ON services(org_id);
                CREATE INDEX IF NOT EXISTS idx_svc_crit ON services(org_id, criticality);
                CREATE INDEX IF NOT EXISTS idx_svc_type ON services(org_id, service_type);

                CREATE TABLE IF NOT EXISTS dependencies (
                    id                TEXT PRIMARY KEY,
                    org_id            TEXT NOT NULL,
                    source_service_id TEXT NOT NULL,
                    target_service_id TEXT NOT NULL,
                    dependency_type   TEXT NOT NULL DEFAULT 'runtime',
                    criticality       TEXT NOT NULL DEFAULT 'medium',
                    protocol          TEXT NOT NULL DEFAULT '',
                    port              INTEGER NOT NULL DEFAULT 0,
                    description       TEXT NOT NULL DEFAULT '',
                    created_at        TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_dep_org    ON dependencies(org_id);
                CREATE INDEX IF NOT EXISTS idx_dep_source ON dependencies(org_id, source_service_id);
                CREATE INDEX IF NOT EXISTS idx_dep_target ON dependencies(org_id, target_service_id);

                CREATE TABLE IF NOT EXISTS blast_radius_analyses (
                    id                TEXT PRIMARY KEY,
                    org_id            TEXT NOT NULL,
                    source_service_id TEXT NOT NULL,
                    affected_services TEXT NOT NULL DEFAULT '[]',
                    affected_count    INTEGER NOT NULL DEFAULT 0,
                    critical_count    INTEGER NOT NULL DEFAULT 0,
                    analysis_type     TEXT NOT NULL DEFAULT 'downstream',
                    created_at        TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_bra_org ON blast_radius_analyses(org_id);
            """)

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
    # SERVICE MANAGEMENT
    # ------------------------------------------------------------------

    def register_service(
        self,
        org_id: str,
        service_name: str,
        service_type: str = "application",
        criticality: str = "medium",
        owner: str = "",
        environment: str = "production",
        data_classification: str = "internal",
    ) -> Dict[str, Any]:
        """Register a new service in the dependency map."""
        if not service_name:
            raise ValueError("service_name is required")
        if service_type not in _VALID_SERVICE_TYPES:
            raise ValueError(
                f"Invalid service_type '{service_type}'. Must be one of {sorted(_VALID_SERVICE_TYPES)}"
            )
        if criticality not in _VALID_CRITICALITIES:
            raise ValueError(
                f"Invalid criticality '{criticality}'. Must be one of {sorted(_VALID_CRITICALITIES)}"
            )
        if environment not in _VALID_ENVIRONMENTS:
            raise ValueError(
                f"Invalid environment '{environment}'. Must be one of {sorted(_VALID_ENVIRONMENTS)}"
            )
        if data_classification not in _VALID_DATA_CLASSIFICATIONS:
            raise ValueError(
                f"Invalid data_classification '{data_classification}'. Must be one of {sorted(_VALID_DATA_CLASSIFICATIONS)}"
            )

        service_id = str(uuid.uuid4())
        now = self._now()

        with self._lock, self._conn() as conn:
            conn.execute(
                """INSERT INTO services
                   (id, org_id, service_name, service_type, criticality, owner,
                    environment, data_classification, status,
                    dependency_count, dependent_count, created_at)
                   VALUES (?,?,?,?,?,?,?,?,'active',0,0,?)""",
                (
                    service_id, org_id, service_name, service_type, criticality,
                    owner, environment, data_classification, now,
                ),
            )
        _logger.info("dep_map.service_registered org=%s service_id=%s name=%s", org_id, service_id, service_name)
        return self.get_service(service_id, org_id)

    # ------------------------------------------------------------------
    # DEPENDENCY MANAGEMENT
    # ------------------------------------------------------------------

    def add_dependency(
        self,
        org_id: str,
        source_service_id: str,
        target_service_id: str,
        dependency_type: str = "runtime",
        criticality: str = "medium",
        protocol: str = "",
        port: int = 0,
        description: str = "",
    ) -> Dict[str, Any]:
        """Add a directed dependency: source depends on target."""
        if dependency_type not in _VALID_DEPENDENCY_TYPES:
            raise ValueError(
                f"Invalid dependency_type '{dependency_type}'. Must be one of {sorted(_VALID_DEPENDENCY_TYPES)}"
            )
        if criticality not in _VALID_CRITICALITIES:
            raise ValueError(
                f"Invalid criticality '{criticality}'. Must be one of {sorted(_VALID_CRITICALITIES)}"
            )

        # Validate both services exist for this org
        with self._conn() as conn:
            src = conn.execute(
                "SELECT id FROM services WHERE id=? AND org_id=?", (source_service_id, org_id)
            ).fetchone()
            tgt = conn.execute(
                "SELECT id FROM services WHERE id=? AND org_id=?", (target_service_id, org_id)
            ).fetchone()

        if src is None:
            raise ValueError(f"Source service '{source_service_id}' not found for org '{org_id}'")
        if tgt is None:
            raise ValueError(f"Target service '{target_service_id}' not found for org '{org_id}'")

        dep_id = str(uuid.uuid4())
        now = self._now()

        with self._lock, self._conn() as conn:
            conn.execute(
                """INSERT INTO dependencies
                   (id, org_id, source_service_id, target_service_id,
                    dependency_type, criticality, protocol, port, description, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (dep_id, org_id, source_service_id, target_service_id,
                 dependency_type, criticality, protocol, port, description, now),
            )
            # source gains one outgoing dependency
            conn.execute(
                "UPDATE services SET dependency_count = dependency_count + 1 WHERE id=? AND org_id=?",
                (source_service_id, org_id),
            )
            # target gains one incoming dependent
            conn.execute(
                "UPDATE services SET dependent_count = dependent_count + 1 WHERE id=? AND org_id=?",
                (target_service_id, org_id),
            )

        _logger.info(
            "dep_map.dependency_added org=%s dep_id=%s src=%s tgt=%s",
            org_id, dep_id, source_service_id, target_service_id,
        )

        with self._conn() as conn:
            row = conn.execute("SELECT * FROM dependencies WHERE id=?", (dep_id,)).fetchone()
        return self._row(row)

    def remove_dependency(self, dependency_id: str, org_id: str) -> Dict[str, Any]:
        """Remove a dependency and decrement counters on both services."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM dependencies WHERE id=? AND org_id=?", (dependency_id, org_id)
            ).fetchone()
        if row is None:
            raise ValueError(f"Dependency '{dependency_id}' not found for org '{org_id}'")

        dep = self._row(row)
        src_id = dep["source_service_id"]
        tgt_id = dep["target_service_id"]

        with self._lock, self._conn() as conn:
            conn.execute(
                "DELETE FROM dependencies WHERE id=? AND org_id=?", (dependency_id, org_id)
            )
            conn.execute(
                """UPDATE services
                   SET dependency_count = MAX(0, dependency_count - 1)
                   WHERE id=? AND org_id=?""",
                (src_id, org_id),
            )
            conn.execute(
                """UPDATE services
                   SET dependent_count = MAX(0, dependent_count - 1)
                   WHERE id=? AND org_id=?""",
                (tgt_id, org_id),
            )

        _logger.info("dep_map.dependency_removed org=%s dep_id=%s", org_id, dependency_id)
        return dep

    # ------------------------------------------------------------------
    # BLAST RADIUS (BFS)
    # ------------------------------------------------------------------

    def compute_blast_radius(
        self,
        org_id: str,
        source_service_id: str,
        analysis_type: str = "downstream",
    ) -> Dict[str, Any]:
        """
        BFS blast radius computation.

        downstream: find all services that transitively depend ON source_service_id
                    (i.e., who breaks if source goes down)
        upstream:   find all services source_service_id transitively depends ON
                    (i.e., what must be up for source to work)
        """
        if analysis_type not in {"downstream", "upstream"}:
            raise ValueError("analysis_type must be 'downstream' or 'upstream'")

        # Verify source service exists for org
        with self._conn() as conn:
            src_row = conn.execute(
                "SELECT id FROM services WHERE id=? AND org_id=?", (source_service_id, org_id)
            ).fetchone()
        if src_row is None:
            raise ValueError(f"Service '{source_service_id}' not found for org '{org_id}'")

        visited: set = set()
        queue: deque = deque()
        queue.append((source_service_id, 0))
        visited.add(source_service_id)

        while queue:
            current_id, depth = queue.popleft()
            if depth >= _MAX_BFS_DEPTH:
                continue

            with self._conn() as conn:
                if analysis_type == "downstream":
                    # Find services that have current_id as their dependency (target)
                    neighbors = conn.execute(
                        """SELECT source_service_id FROM dependencies
                           WHERE org_id=? AND target_service_id=?""",
                        (org_id, current_id),
                    ).fetchall()
                    neighbor_ids = [r["source_service_id"] for r in neighbors]
                else:
                    # upstream: find what current_id depends on (targets)
                    neighbors = conn.execute(
                        """SELECT target_service_id FROM dependencies
                           WHERE org_id=? AND source_service_id=?""",
                        (org_id, current_id),
                    ).fetchall()
                    neighbor_ids = [r["target_service_id"] for r in neighbors]

            for nid in neighbor_ids:
                if nid not in visited:
                    visited.add(nid)
                    queue.append((nid, depth + 1))

        # Remove the source itself from affected list
        affected_ids = list(visited - {source_service_id})

        # Count critical services among affected
        critical_count = 0
        if affected_ids:
            placeholders = ",".join("?" * len(affected_ids))
            with self._conn() as conn:
                critical_count = conn.execute(
                    f"""SELECT COUNT(*) FROM services WHERE org_id=? AND id IN ({placeholders}) AND criticality='critical'""",  # nosec B608
                    [org_id] + affected_ids,
                ).fetchone()[0]

        analysis_id = str(uuid.uuid4())
        now = self._now()

        with self._lock, self._conn() as conn:
            conn.execute(
                """INSERT INTO blast_radius_analyses
                   (id, org_id, source_service_id, affected_services,
                    affected_count, critical_count, analysis_type, created_at)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (
                    analysis_id, org_id, source_service_id,
                    json.dumps(affected_ids),
                    len(affected_ids), critical_count,
                    analysis_type, now,
                ),
            )

        _logger.info(
            "dep_map.blast_radius org=%s src=%s type=%s affected=%d critical=%d",
            org_id, source_service_id, analysis_type, len(affected_ids), critical_count,
        )

        return {
            "analysis_id": analysis_id,
            "source_service_id": source_service_id,
            "analysis_type": analysis_type,
            "affected_services": affected_ids,
            "affected_count": len(affected_ids),
            "critical_count": critical_count,
            "created_at": now,
        }

    # ------------------------------------------------------------------
    # QUERIES
    # ------------------------------------------------------------------

    def get_service(self, service_id: str, org_id: str) -> Optional[Dict[str, Any]]:
        """Fetch service with its outgoing and incoming dependencies."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM services WHERE id=? AND org_id=?", (service_id, org_id)
            ).fetchone()
        if row is None:
            return None

        service = self._row(row)

        with self._conn() as conn:
            outgoing = conn.execute(
                "SELECT * FROM dependencies WHERE org_id=? AND source_service_id=? ORDER BY created_at DESC",
                (org_id, service_id),
            ).fetchall()
            incoming = conn.execute(
                "SELECT * FROM dependencies WHERE org_id=? AND target_service_id=? ORDER BY created_at DESC",
                (org_id, service_id),
            ).fetchall()

        service["outgoing_dependencies"] = [self._row(r) for r in outgoing]
        service["incoming_dependencies"] = [self._row(r) for r in incoming]
        return service

    def list_services(
        self,
        org_id: str,
        service_type: Optional[str] = None,
        criticality: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List services for org, optionally filtered."""
        query = "SELECT * FROM services WHERE org_id=?"
        params: List[Any] = [org_id]
        if service_type:
            query += " AND service_type=?"
            params.append(service_type)
        if criticality:
            query += " AND criticality=?"
            params.append(criticality)
        query += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    def get_critical_paths(self, org_id: str) -> List[Dict[str, Any]]:
        """Return critical services ordered by dependent_count DESC (most depended-upon first)."""
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT * FROM services
                   WHERE org_id=? AND criticality='critical' AND dependent_count > 0
                   ORDER BY dependent_count DESC""",
                (org_id,),
            ).fetchall()
        return [self._row(r) for r in rows]

    def get_source_trace(
        self, org_id: str, source_file: str
    ) -> Dict[str, Any]:
        """Map a source file path to deployed services via name-matching.

        Heuristic: the service name or owner field is checked against the
        stem of the source file path.  Returns matching services plus their
        BFS downstream blast radius so engineers know which cloud assets are
        affected when a given source file changes.

        Args:
            org_id:      Organisation identifier.
            source_file: Relative or absolute path to a source file,
                         e.g. "suite-core/core/siem_integration_engine.py".

        Returns a dict with:
            - source_file:  echoed back
            - matched_services: list of services whose name/owner contains
                                a keyword derived from the source file stem
            - blast_radius:  combined downstream blast radius across all
                             matched services (deduped)
            - total_affected: count of distinct affected services
        """
        import os as _os

        stem = _os.path.splitext(_os.path.basename(source_file))[0]
        # Derive keywords: strip common suffixes and split on underscores
        for suffix in ("_engine", "_router", "_v2", "_v3"):
            stem = stem.replace(suffix, "")
        keywords = [w for w in stem.split("_") if len(w) > 2]

        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM services WHERE org_id=?", (org_id,)
            ).fetchall()

        matched: List[Dict[str, Any]] = []
        for row in rows:
            svc = self._row(row)
            name_lower = svc.get("service_name", "").lower()
            owner_lower = svc.get("owner", "").lower()
            if any(kw in name_lower or kw in owner_lower for kw in keywords):
                matched.append(svc)

        # Collect combined blast radius (downstream).
        # compute_blast_radius returns affected_services as a list of UUID strings.
        affected_id_set: set = set()
        affected_service_details: List[Dict[str, Any]] = []
        for svc in matched:
            try:
                br = self.compute_blast_radius(org_id, svc["id"], "downstream")
                for sid in br.get("affected_services", []):
                    if isinstance(sid, dict):
                        sid = sid.get("id", "")
                    if sid and sid not in affected_id_set:
                        affected_id_set.add(sid)
                        # Fetch full service record
                        detail = self.get_service(sid, org_id)
                        if detail:
                            affected_service_details.append(detail)
            except (ValueError, KeyError):
                pass

        return {
            "source_file": source_file,
            "keywords_used": keywords,
            "matched_services": matched,
            "blast_radius": affected_service_details,
            "total_affected": len(affected_service_details),
        }

    # ------------------------------------------------------------------
    # GAP-010 — reachability enrichment
    # ------------------------------------------------------------------

    def enrich_with_reachability(
        self,
        org_id: str,
        finding_id: str,
        cve_id: str,
        dependency_fqn_pattern: str,
    ) -> Dict[str, Any]:
        """Delegate reachability analysis to function_reachability_engine.

        Writes the ``reachability_verdict`` (reachable | unreachable |
        unknown) to the reachability engine's own ``finding_reachability_verdicts``
        table — no schema change on this engine.

        This is the entry point called from vuln-finding pipelines: when a
        dependency CVE is created, we call this to annotate the finding with
        whether the customer's code can actually reach the vulnerable symbol.

        Fails-closed: any error inside the reachability engine produces a
        ``verdict: unknown`` record so the finding is never silently marked
        unreachable on an error path.
        """
        try:
            from core.function_reachability_engine import FunctionReachabilityEngine
        except ImportError:
            # Reachability engine unavailable -> emit an "unknown" verdict
            _logger.warning(
                "dep_map.enrich.fr_engine_missing org=%s finding=%s", org_id, finding_id
            )
            return {
                "finding_id": finding_id,
                "cve_id": cve_id,
                "dependency_fqn_pattern": dependency_fqn_pattern,
                "verdict": "unknown",
                "reachable_callers": [],
            }

        fr = FunctionReachabilityEngine()
        try:
            callers = fr.vulnerable_reachability(
                org_id=org_id,
                cve_id=cve_id,
                dependency_fqn_pattern=dependency_fqn_pattern,
            )
        except ValueError as exc:
            _logger.warning(
                "dep_map.enrich.fr_engine_error org=%s finding=%s err=%s",
                org_id, finding_id, exc,
            )
            verdict = "unknown"
            callers = []
        else:
            verdict = "reachable" if callers else "unreachable"

        record = fr.record_finding_verdict(
            org_id=org_id,
            finding_id=finding_id,
            cve_id=cve_id,
            dependency_fqn_pattern=dependency_fqn_pattern,
            verdict=verdict,
            reachable_callers=callers,
        )
        _logger.info(
            "dep_map.enrich_ok org=%s finding=%s verdict=%s callers=%d",
            org_id, finding_id, verdict, len(callers),
        )
        return record

    # ------------------------------------------------------------------
    # GAP-065 — Architecture-aware graph: layer classification
    # ------------------------------------------------------------------

    _DATA_KEYWORDS = ("db", "database", "migrations", "orm", "models", "schema")
    _API_KEYWORDS = ("api", "router", "controller", "endpoint", "handler")
    _UI_KEYWORDS = ("ui", "components", "pages", "views", "frontend")

    def classify_layer(
        self,
        node_ref: str,
        context: Optional[Dict[str, Any]] = None,
        org_id: str = "default",
    ) -> Dict[str, Any]:
        """Classify a node into one of: data | api | ui | service | standalone.

        Heuristics (in priority order):
          - path contains "db|database|migrations|orm" → "data"
          - path contains "api|router|controller"     → "api"
          - path contains "ui|components|pages|views" → "ui"
          - has imports but no importers (from context) → "standalone"
          - has both imports and importers            → "service"

        Args:
            node_ref: The node reference (usually file path or FQN).
            context: Optional dict with "imports" (list) and "importers" (list).
            org_id:  Organisation identifier for upsert into DB.

        Returns:
            {layer, confidence, signals: [...]}
        """
        if not node_ref:
            raise ValueError("node_ref is required")

        ctx = context or {}
        imports = ctx.get("imports") or []
        importers = ctx.get("importers") or []

        ref_lower = str(node_ref).lower()
        signals: List[str] = []
        layer: Optional[str] = None
        confidence: float = 0.0

        # Priority 1: data layer
        for kw in self._DATA_KEYWORDS:
            if kw in ref_lower:
                signals.append(f"path_keyword:{kw}")
                layer = "data"
                confidence = 0.85
                break

        # Priority 2: api layer
        if layer is None:
            for kw in self._API_KEYWORDS:
                if kw in ref_lower:
                    signals.append(f"path_keyword:{kw}")
                    layer = "api"
                    confidence = 0.80
                    break

        # Priority 3: ui layer
        if layer is None:
            for kw in self._UI_KEYWORDS:
                if kw in ref_lower:
                    signals.append(f"path_keyword:{kw}")
                    layer = "ui"
                    confidence = 0.80
                    break

        # Priority 4/5: import topology
        if layer is None:
            has_imports = bool(imports)
            has_importers = bool(importers)
            if has_imports and not has_importers:
                signals.append("topology:imports_no_importers")
                layer = "standalone"
                confidence = 0.60
            elif has_imports and has_importers:
                signals.append("topology:imports_and_importers")
                layer = "service"
                confidence = 0.70
            elif has_importers and not has_imports:
                signals.append("topology:importers_no_imports")
                layer = "service"
                confidence = 0.50
            else:
                signals.append("topology:isolated")
                layer = "standalone"
                confidence = 0.40

        # Boost confidence when both path keyword AND topology agree
        if imports or importers:
            if layer == "api" and importers:
                signals.append("topology_boost:has_importers")
                confidence = min(1.0, confidence + 0.10)
            if layer == "data" and importers:
                signals.append("topology_boost:has_importers")
                confidence = min(1.0, confidence + 0.10)

        # Clamp 0..1
        confidence = max(0.0, min(1.0, float(confidence)))

        now = self._now()
        record_id = str(uuid.uuid4())
        signals_json = json.dumps(signals)

        # Upsert on (org_id, node_ref)
        with self._lock, self._conn() as conn:
            conn.execute(
                """INSERT INTO layer_classifications
                   (id, org_id, node_ref, layer, confidence, signals_json, classified_at)
                   VALUES (?,?,?,?,?,?,?)
                   ON CONFLICT(org_id, node_ref) DO UPDATE SET
                       layer=excluded.layer,
                       confidence=excluded.confidence,
                       signals_json=excluded.signals_json,
                       classified_at=excluded.classified_at""",
                (record_id, org_id, node_ref, layer, confidence, signals_json, now),
            )

        _logger.info(
            "dep_map.classify_layer org=%s node=%s layer=%s confidence=%.2f",
            org_id, node_ref, layer, confidence,
        )

        return {
            "node_ref": node_ref,
            "layer": layer,
            "confidence": confidence,
            "signals": signals,
            "classified_at": now,
        }

    def get_layer(self, org_id: str, node_ref: str) -> Optional[Dict[str, Any]]:
        """Fetch a classification by (org_id, node_ref). Returns None if missing."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM layer_classifications WHERE org_id=? AND node_ref=?",
                (org_id, node_ref),
            ).fetchone()
        if row is None:
            return None
        rec = dict(row)
        try:
            rec["signals"] = json.loads(rec.get("signals_json") or "[]")
        except (json.JSONDecodeError, TypeError):
            rec["signals"] = []
        return rec

    def list_classifications(
        self,
        org_id: str,
        layer: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List layer classifications for an org, optionally filtered by layer."""
        query = "SELECT * FROM layer_classifications WHERE org_id=?"
        params: List[Any] = [org_id]
        if layer:
            query += " AND layer=?"
            params.append(layer)
        query += " ORDER BY classified_at DESC"
        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        out: List[Dict[str, Any]] = []
        for row in rows:
            rec = dict(row)
            try:
                rec["signals"] = json.loads(rec.get("signals_json") or "[]")
            except (json.JSONDecodeError, TypeError):
                rec["signals"] = []
            out.append(rec)
        return out

    def upsert_layer(
        self,
        org_id: str,
        node_ref: str,
        layer: str,
        confidence: float = 0.95,
        signals: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Directly write a layer classification (used by link_to_layer helpers).

        Bypasses heuristics — caller has explicit knowledge (e.g. API endpoint
        is known to be an 'api' layer node).
        """
        if not node_ref:
            raise ValueError("node_ref is required")
        if layer not in {"data", "api", "ui", "service", "standalone"}:
            raise ValueError(
                f"Invalid layer '{layer}'. Must be one of data|api|ui|service|standalone"
            )
        confidence = max(0.0, min(1.0, float(confidence)))
        sig = signals or ["explicit_link"]
        now = self._now()
        record_id = str(uuid.uuid4())
        with self._lock, self._conn() as conn:
            conn.execute(
                """INSERT INTO layer_classifications
                   (id, org_id, node_ref, layer, confidence, signals_json, classified_at)
                   VALUES (?,?,?,?,?,?,?)
                   ON CONFLICT(org_id, node_ref) DO UPDATE SET
                       layer=excluded.layer,
                       confidence=excluded.confidence,
                       signals_json=excluded.signals_json,
                       classified_at=excluded.classified_at""",
                (record_id, org_id, node_ref, layer, confidence, json.dumps(sig), now),
            )
        return {
            "node_ref": node_ref,
            "layer": layer,
            "confidence": confidence,
            "signals": sig,
            "classified_at": now,
        }

    def get_summary(self, org_id: str) -> Dict[str, Any]:
        """Return aggregate summary for org's dependency map."""
        with self._conn() as conn:
            total_services = conn.execute(
                "SELECT COUNT(*) FROM services WHERE org_id=?", (org_id,)
            ).fetchone()[0]

            total_dependencies = conn.execute(
                "SELECT COUNT(*) FROM dependencies WHERE org_id=?", (org_id,)
            ).fetchone()[0]

            by_type_rows = conn.execute(
                """SELECT service_type, COUNT(*) AS cnt
                   FROM services WHERE org_id=? GROUP BY service_type""",
                (org_id,),
            ).fetchall()

            by_crit_rows = conn.execute(
                """SELECT criticality, COUNT(*) AS cnt
                   FROM services WHERE org_id=? GROUP BY criticality""",
                (org_id,),
            ).fetchall()

            high_blast_rows = conn.execute(
                """SELECT * FROM services
                   WHERE org_id=? AND dependent_count >= 5
                   ORDER BY dependent_count DESC""",
                (org_id,),
            ).fetchall()

        return {
            "total_services": total_services,
            "total_dependencies": total_dependencies,
            "by_service_type": {r["service_type"]: r["cnt"] for r in by_type_rows},
            "by_criticality": {r["criticality"]: r["cnt"] for r in by_crit_rows},
            "high_blast_radius_services": [self._row(r) for r in high_blast_rows],
        }
