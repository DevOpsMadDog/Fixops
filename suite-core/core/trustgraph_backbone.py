"""
TrustGraph Backbone — Central nervous system connecting ALL ALDECI modules.

Every entity flows through TrustGraph. Every relationship is a graph edge.
Every AI query uses GraphRAG. This module wires the isolated modules into
ONE connected intelligence platform.

Knowledge Core mapping:
    1 = customer_env    — assets, services, infrastructure, zones
    2 = threat_intel    — CVEs, findings, threat actors, TTPs, campaigns
    3 = compliance      — controls, frameworks, evidence, assessments
    4 = decision_memory — incidents, LLM Council verdicts, past decisions
    5 = external        — vendors, components, competitive intel

Personas served: P01 CISO, P03 SOC T1, P04 SOC T2, P05 Security Engineer,
                 P07 Compliance Officer, P09 Risk Manager, P17 Threat Intel Analyst,
                 P20 Security Architect

Usage:
    backbone = TrustGraphBackbone()
    backbone.index_finding({"id": "f_001", "cve_id": "CVE-2024-1234", ...})
    backbone.link_entities("f_001", "asset_prod_api", "FINDING_AFFECTS_ASSET")

    graphrag = GraphRAGEnhanced()
    result = graphrag.query_impact("asset_prod_api")
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

__all__ = [
    "TrustGraphBackbone",
    "GraphRAGEnhanced",
    "RelationshipType",
    "KnowledgeBrainAdapter",
    "get_backbone",
    "get_graphrag_enhanced",
]

# ---------------------------------------------------------------------------
# Knowledge Core IDs
# ---------------------------------------------------------------------------

CORE_CUSTOMER_ENV = 1
CORE_THREAT_INTEL = 2
CORE_COMPLIANCE = 3
CORE_DECISION_MEMORY = 4
CORE_EXTERNAL = 5

# ---------------------------------------------------------------------------
# Relationship type constants
# ---------------------------------------------------------------------------


class RelationshipType:
    """Typed edge vocabulary for the ALDECI knowledge graph."""

    FINDING_AFFECTS_ASSET = "FINDING_AFFECTS_ASSET"
    FINDING_EXPLOITS_CVE = "FINDING_EXPLOITS_CVE"
    ASSET_BELONGS_TO_ZONE = "ASSET_BELONGS_TO_ZONE"
    INCIDENT_INVOLVES_FINDING = "INCIDENT_INVOLVES_FINDING"
    INCIDENT_IMPACTS_ASSET = "INCIDENT_IMPACTS_ASSET"
    CONTROL_MITIGATES_FINDING = "CONTROL_MITIGATES_FINDING"
    VENDOR_PROVIDES_COMPONENT = "VENDOR_PROVIDES_COMPONENT"
    COMPONENT_HAS_VULNERABILITY = "COMPONENT_HAS_VULNERABILITY"
    ACTOR_USES_TTP = "ACTOR_USES_TTP"
    ACTOR_TARGETS_ASSET = "ACTOR_TARGETS_ASSET"

    ALL = {
        "FINDING_AFFECTS_ASSET",
        "FINDING_EXPLOITS_CVE",
        "ASSET_BELONGS_TO_ZONE",
        "INCIDENT_INVOLVES_FINDING",
        "INCIDENT_IMPACTS_ASSET",
        "CONTROL_MITIGATES_FINDING",
        "VENDOR_PROVIDES_COMPONENT",
        "COMPONENT_HAS_VULNERABILITY",
        "ACTOR_USES_TTP",
        "ACTOR_TARGETS_ASSET",
    }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _rel_id() -> str:
    return f"rel_{uuid.uuid4().hex[:12]}"


# ---------------------------------------------------------------------------
# KnowledgeBrainAdapter — fallback store when external `trustgraph` is missing
# ---------------------------------------------------------------------------


class KnowledgeBrainAdapter:
    """Adapter that exposes the ``KnowledgeStore`` API on top of ``KnowledgeBrain``.

    Why this exists:
        Production deployments may not ship the external ``trustgraph`` PyPI
        package (air-gapped installs, OSS-only customers, dev laptops without
        the optional dep). Without this adapter, ``TrustGraphBackbone`` would
        silently no-op every emit — guaranteeing the second-brain stays empty.

        ``KnowledgeBrain`` (SQLite + NetworkX, thread-safe via ``RLock``,
        WAL+checkpointing) is already wired and well-tested. This adapter
        lets the backbone use it as a drop-in store without rewriting any
        of the index_* methods upstream.

    Methods exposed (matching ``trustgraph.knowledge_store.KnowledgeStore``):
        - ``ingest(entity)`` — upsert entity → ``KnowledgeBrain.upsert_node``
        - ``add_relationship(rel)`` — write edge → ``KnowledgeBrain.add_edge``
        - ``get_entity(entity_id)`` — read entity (returns object with ``.to_dict``)
        - ``get_relationships(entity_id=...)`` — read edges
        - ``get_neighbors(entity_id=..., depth=...)`` — N-hop traversal
        - ``core_stats(core_id)`` — per-core entity/relationship counts
        - ``search(core_id, query_text, filters, limit)`` — name+properties LIKE
        - ``_get_conn()`` / ``_row_to_entity()`` — used by GraphRAGEnhanced
                                                   semantic_search LIKE fallback

    Thread safety:
        Inherits ``KnowledgeBrain``'s ``_conn_lock`` (re-entrant) and SQLite
        WAL mode. Safe for concurrent FastAPI request workers.
    """

    def __init__(
        self,
        db_path: Optional[str] = None,
        org_id: str = "default",
    ) -> None:
        from core.knowledge_brain import (  # local import — avoid cycle at module load
            EdgeType,
            EntityType,
            GraphEdge,
            GraphNode,
            get_brain,
        )

        self._GraphNode = GraphNode
        self._GraphEdge = GraphEdge
        self._EntityType = EntityType
        self._EdgeType = EdgeType
        self._org_id = org_id
        # Use the project-wide singleton when no explicit db_path is given so all
        # suites share one brain. When a db_path is supplied (tests), build a
        # dedicated KnowledgeBrain so test isolation is preserved.
        if db_path is None:
            self._brain = get_brain()
        else:
            from core.knowledge_brain import KnowledgeBrain

            self._brain = KnowledgeBrain(db_path=db_path)

    # ---------- internal helpers ----------

    def _coerce_entity_type(self, entity_type: str) -> Any:
        """Map free-form entity_type string to ``EntityType`` enum (best effort)."""
        try:
            return self._EntityType(entity_type.lower())
        except (ValueError, AttributeError):
            # Unknown type — keep as raw string; KnowledgeBrain accepts both.
            return entity_type

    def _coerce_edge_type(self, rel_type: str) -> Any:
        try:
            return self._EdgeType(rel_type.lower())
        except (ValueError, AttributeError):
            return rel_type

    # ---------- KnowledgeStore-compatible surface ----------

    def ingest(self, entity: Any) -> Any:
        """Upsert a KnowledgeEntity into the brain. Idempotent."""
        props = dict(getattr(entity, "properties", {}) or {})
        # Stamp identity-related fields into properties so consumers can read
        # them back even though KnowledgeBrain has no first-class 'core_id' column.
        props.setdefault("core_id", getattr(entity, "core_id", None))
        props.setdefault("entity_type", getattr(entity, "entity_type", "unknown"))
        props.setdefault("name", getattr(entity, "name", entity.entity_id))
        node = self._GraphNode(
            node_id=entity.entity_id,
            node_type=self._coerce_entity_type(getattr(entity, "entity_type", "unknown")),
            org_id=getattr(entity, "org_id", None) or self._org_id,
            properties=props,
        )
        return self._brain.upsert_node(node)

    def add_relationship(self, rel: Any) -> Any:
        """Add a KnowledgeRelationship as a brain edge. Idempotent on (src, tgt, type)."""
        edge = self._GraphEdge(
            source_id=rel.source_id,
            target_id=rel.target_id,
            edge_type=self._coerce_edge_type(getattr(rel, "rel_type", "references")),
            properties=dict(getattr(rel, "properties", {}) or {}),
            confidence=float(getattr(rel, "confidence", 1.0)),
        )
        return self._brain.add_edge(edge)

    def get_entity(self, entity_id: str) -> Optional[Any]:
        """Return an entity-like object exposing ``.entity_id``, ``.name``,
        ``.entity_type``, ``.core_id``, ``.properties``, ``.to_dict()``.
        """
        node = self._brain.get_node(entity_id)
        if node is None:
            return None
        return _AdaptedEntity(node)

    def get_relationships(self, entity_id: Optional[str] = None) -> List[Any]:
        """Return relationship-like objects with ``.source_id``, ``.target_id``,
        ``.rel_type``, ``.confidence``, ``.properties``, ``.rel_id``, ``.to_dict()``.
        """
        if entity_id is None:
            return []
        edges = self._brain.get_edges(entity_id, direction="both")
        return [_AdaptedRelationship(e) for e in edges]

    def get_neighbors(self, entity_id: str, depth: int = 1) -> List[Any]:
        result = self._brain.get_neighbors(entity_id, depth=depth)
        # Strip the center node — backbone callers expect strictly outbound
        # neighbors, not the seed itself.
        return [_AdaptedEntity(n) for n in result.nodes if n["node_id"] != entity_id]

    def core_stats(self, core_id: int) -> Dict[str, Any]:
        """Approximate per-core stats. KnowledgeBrain has no native concept of
        cores, so we count nodes whose properties.core_id matches.
        """
        stats = self._brain.stats()
        # Conservative approximation: cannot filter by JSON-embedded core_id
        # without a full scan. Return totals — callers chiefly use this to know
        # "graph not empty". Per-core breakdown is best-effort.
        return {
            "core_id": core_id,
            "entity_count": stats.get("total_nodes", 0),
            "relationship_count": stats.get("total_edges", 0),
        }

    def search(
        self,
        core_id: int,
        query_text: str,
        filters: Optional[Dict[str, Any]] = None,
        limit: int = 10,
    ) -> List[Any]:
        org_id = (filters or {}).get("org_id")
        result = self._brain.query_nodes(org_id=org_id, search=query_text, limit=limit)
        return [_AdaptedEntity(n) for n in result.nodes]

    def _get_conn(self):
        """Expose underlying SQLite connection for ``GraphRAGEnhanced`` LIKE fallback."""
        return self._brain._conn

    def _row_to_entity(self, row: Any) -> Any:
        """Best-effort row→entity converter for the LIKE-fallback path."""
        # The LIKE fallback in GraphRAGEnhanced.semantic_search assumes the
        # external store schema (entities table). KnowledgeBrain rows differ;
        # return a minimal adapted entity so the path doesn't crash.
        try:
            node_id = row[0] if isinstance(row, (list, tuple)) else row["node_id"]
        except (KeyError, IndexError, TypeError):
            return None
        node = self._brain.get_node(node_id)
        return _AdaptedEntity(node) if node else None


class _AdaptedEntity:
    """Entity façade matching the ``KnowledgeEntity`` shape backbone code expects."""

    __slots__ = ("entity_id", "core_id", "entity_type", "name", "properties", "org_id")

    def __init__(self, node: Dict[str, Any]) -> None:
        props = dict(node.get("properties", {}) or {})
        self.entity_id = node["node_id"]
        self.core_id = props.get("core_id")
        self.entity_type = props.get("entity_type") or node.get("node_type", "unknown")
        self.name = props.get("name") or node["node_id"]
        self.properties = props
        self.org_id = node.get("org_id")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entity_id": self.entity_id,
            "core_id": self.core_id,
            "entity_type": self.entity_type,
            "name": self.name,
            "properties": self.properties,
            "org_id": self.org_id,
        }


class _AdaptedRelationship:
    """Relationship façade matching the ``KnowledgeRelationship`` shape."""

    __slots__ = ("rel_id", "source_id", "target_id", "rel_type", "properties", "confidence")

    def __init__(self, edge: Dict[str, Any]) -> None:
        self.source_id = edge["source_id"]
        self.target_id = edge["target_id"]
        self.rel_type = edge.get("edge_type", "references")
        self.properties = dict(edge.get("properties", {}) or {})
        self.confidence = float(edge.get("confidence", 1.0))
        # Synthesize a stable rel_id from the tuple — KnowledgeBrain's UNIQUE
        # constraint means (src, tgt, type) is the natural key.
        self.rel_id = f"rel_{abs(hash((self.source_id, self.target_id, self.rel_type))) & 0xFFFFFFFF:08x}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rel_id": self.rel_id,
            "source_id": self.source_id,
            "target_id": self.target_id,
            "rel_type": self.rel_type,
            "properties": self.properties,
            "confidence": self.confidence,
        }


# ---------------------------------------------------------------------------
# TrustGraphBackbone
# ---------------------------------------------------------------------------


class TrustGraphBackbone:
    """Central nervous system — indexes every ALDECI entity into TrustGraph.

    All indexing methods are idempotent (upsert semantics from KnowledgeStore).
    Failures are logged but never raised, so callers never break when
    TrustGraph is unavailable.

    Args:
        db_path: Optional path to TrustGraph SQLite DB. Defaults to
                 the standard location used by KnowledgeStore.
        org_id: Tenant org ID for multi-tenancy.
    """

    def __init__(
        self,
        db_path: Optional[str] = None,
        org_id: str = "default",
    ) -> None:
        self.org_id = org_id
        self._db_path = db_path
        self._store: Optional[Any] = None
        self._available: bool = True
        self._init_store()

    def _init_store(self) -> None:
        """Lazy-load KnowledgeStore; degrade to KnowledgeBrain adapter on failure.

        Resolution order:
          1. External ``trustgraph.knowledge_store.KnowledgeStore`` package (preferred).
          2. ``KnowledgeBrainAdapter`` wrapping the in-tree ``KnowledgeBrain``
             SQLite+NetworkX store. Always available — no silent no-op.

        After this method, ``self._store`` is never ``None`` and
        ``self._available`` is always ``True`` unless even the in-tree
        KnowledgeBrain failed to initialize (e.g. disk full / permission denied).
        """
        try:
            from trustgraph.knowledge_store import KnowledgeStore

            kwargs: Dict[str, Any] = {}
            if self._db_path is not None:
                kwargs["db_path"] = self._db_path
            self._store = KnowledgeStore(**kwargs)
            self._available = True
            logger.info("TrustGraphBackbone: KnowledgeStore initialized")
            return
        except Exception as exc:
            logger.info(
                "TrustGraphBackbone: external KnowledgeStore unavailable (%s) — "
                "falling back to KnowledgeBrain adapter",
                exc,
            )

        # Fallback: wrap the in-tree KnowledgeBrain so every emit lands somewhere.
        try:
            self._store = KnowledgeBrainAdapter(
                db_path=self._db_path, org_id=self.org_id
            )
            self._available = True
            logger.info(
                "TrustGraphBackbone: KnowledgeBrain fallback active (db=%s)",
                self._db_path or "default",
            )
        except Exception as exc:  # pragma: no cover — disk/permission failure
            logger.error(
                "TrustGraphBackbone: KnowledgeBrain fallback ALSO failed (%s) — "
                "graph features disabled",
                exc,
            )
            self._store = None
            self._available = False

    def _make_entity(
        self,
        entity_id: str,
        core_id: int,
        entity_type: str,
        name: str,
        properties: Optional[Dict[str, Any]] = None,
    ) -> Any:
        """Create a KnowledgeEntity (or adapter-compatible stand-in)."""
        try:
            from trustgraph.knowledge_store import KnowledgeEntity

            return KnowledgeEntity(
                entity_id=entity_id,
                core_id=core_id,
                entity_type=entity_type,
                name=name,
                properties=properties or {},
                org_id=self.org_id,
            )
        except Exception:
            # External package missing — return a duck-typed object that the
            # KnowledgeBrainAdapter.ingest() reads via getattr.
            return _AdaptedEntity({
                "node_id": entity_id,
                "node_type": entity_type,
                "org_id": self.org_id,
                "properties": {
                    **(properties or {}),
                    "core_id": core_id,
                    "entity_type": entity_type,
                    "name": name,
                },
            })

    def _make_rel(
        self,
        source_id: str,
        target_id: str,
        rel_type: str,
        confidence: float = 0.95,
        properties: Optional[Dict[str, Any]] = None,
    ) -> Any:
        """Create a KnowledgeRelationship (or adapter-compatible stand-in)."""
        try:
            from trustgraph.knowledge_store import KnowledgeRelationship

            return KnowledgeRelationship(
                rel_id=_rel_id(),
                source_id=source_id,
                target_id=target_id,
                rel_type=rel_type,
                properties=properties or {},
                confidence=confidence,
            )
        except Exception:
            return _AdaptedRelationship({
                "source_id": source_id,
                "target_id": target_id,
                "edge_type": rel_type,
                "properties": properties or {},
                "confidence": confidence,
            })

    def _safe_ingest(self, entity: Any) -> bool:
        """Ingest entity, returning True on success."""
        if not self._available or self._store is None:
            return False
        try:
            self._store.ingest(entity)
            return True
        except Exception as exc:
            logger.warning("TrustGraphBackbone.ingest failed for %s: %s", entity.entity_id, exc)
            return False

    def _safe_relate(self, rel: Any) -> bool:
        """Add relationship, returning True on success."""
        if not self._available or self._store is None:
            return False
        try:
            self._store.add_relationship(rel)
            return True
        except Exception as exc:
            logger.warning("TrustGraphBackbone.relate failed: %s", exc)
            return False

    # =========================================================================
    # Entity Indexers
    # =========================================================================

    def index_finding(self, finding: Dict[str, Any]) -> str:
        """Index a security finding into Core 2 (Threat Intelligence).

        Creates:
        - Finding entity in Core 2
        - CVE entity in Core 2 (if cve_id present), linked FINDING_EXPLOITS_CVE
        - Asset link in Core 1 (if asset_id present), linked FINDING_AFFECTS_ASSET

        Args:
            finding: Dict with keys: id, title/name, severity, cve_id (optional),
                     asset_id (optional), cvss (optional), epss (optional),
                     scanner (optional), status (optional)

        Returns:
            entity_id used for the finding in TrustGraph
        """
        finding_id = finding.get("id") or finding.get("finding_id") or f"finding_{uuid.uuid4().hex[:8]}"
        entity_id = f"finding_{finding_id}" if not finding_id.startswith("finding_") else finding_id

        severity = finding.get("severity", "unknown")
        title = finding.get("title") or finding.get("name") or finding_id

        props: Dict[str, Any] = {
            "severity": severity,
            "status": finding.get("status", "open"),
            "scanner": finding.get("scanner", "unknown"),
            "cvss": finding.get("cvss"),
            "epss": finding.get("epss"),
            "description": finding.get("description", ""),
            "indexed_at": _now_iso(),
        }
        # Strip None values
        props = {k: v for k, v in props.items() if v is not None}

        entity = self._make_entity(
            entity_id=entity_id,
            core_id=CORE_THREAT_INTEL,
            entity_type="Finding",
            name=title,
            properties=props,
        )
        self._safe_ingest(entity)

        # Index CVE entity and link
        cve_id = finding.get("cve_id")
        if cve_id:
            cve_entity_id = f"cve_{cve_id.replace('-', '_').lower()}"
            cve_entity = self._make_entity(
                entity_id=cve_entity_id,
                core_id=CORE_THREAT_INTEL,
                entity_type="CVE",
                name=cve_id,
                properties={
                    "cve_id": cve_id,
                    "cvss": finding.get("cvss"),
                    "severity": severity,
                },
            )
            self._safe_ingest(cve_entity)
            self._safe_relate(self._make_rel(
                entity_id, cve_entity_id, RelationshipType.FINDING_EXPLOITS_CVE
            ))

        # Link to asset
        asset_id = finding.get("asset_id")
        if asset_id:
            asset_entity_id = f"asset_{asset_id}" if not asset_id.startswith("asset_") else asset_id
            self._safe_relate(self._make_rel(
                entity_id, asset_entity_id, RelationshipType.FINDING_AFFECTS_ASSET
            ))

        logger.debug("TrustGraphBackbone.index_finding: %s", entity_id)
        return entity_id

    def index_asset(self, asset: Dict[str, Any]) -> str:
        """Index an asset into Core 1 (Customer Environment).

        Creates:
        - Asset entity in Core 1
        - Zone entity in Core 1 (if zone present), linked ASSET_BELONGS_TO_ZONE

        Args:
            asset: Dict with keys: id, name, type (optional), owner (optional),
                   zone (optional), exposure (optional), criticality (optional),
                   ip (optional), hostname (optional)

        Returns:
            entity_id used for the asset in TrustGraph
        """
        asset_id = asset.get("id") or asset.get("asset_id") or f"asset_{uuid.uuid4().hex[:8]}"
        entity_id = f"asset_{asset_id}" if not asset_id.startswith("asset_") else asset_id
        name = asset.get("name") or asset.get("hostname") or asset.get("ip") or asset_id

        props: Dict[str, Any] = {
            "asset_type": asset.get("type", "unknown"),
            "owner": asset.get("owner"),
            "exposure": asset.get("exposure", "internal"),
            "criticality": asset.get("criticality", "medium"),
            "ip": asset.get("ip"),
            "hostname": asset.get("hostname"),
            "environment": asset.get("environment", "unknown"),
            "indexed_at": _now_iso(),
        }
        props = {k: v for k, v in props.items() if v is not None}

        entity = self._make_entity(
            entity_id=entity_id,
            core_id=CORE_CUSTOMER_ENV,
            entity_type="Asset",
            name=name,
            properties=props,
        )
        self._safe_ingest(entity)

        # Link to network zone
        zone = asset.get("zone")
        if zone:
            zone_id = f"zone_{zone.lower().replace(' ', '_')}"
            zone_entity = self._make_entity(
                entity_id=zone_id,
                core_id=CORE_CUSTOMER_ENV,
                entity_type="Zone",
                name=f"Zone: {zone}",
                properties={"zone_name": zone},
            )
            self._safe_ingest(zone_entity)
            self._safe_relate(self._make_rel(
                entity_id, zone_id, RelationshipType.ASSET_BELONGS_TO_ZONE
            ))

        logger.debug("TrustGraphBackbone.index_asset: %s", entity_id)
        return entity_id

    def index_incident(self, incident: Dict[str, Any]) -> str:
        """Index an incident into Core 4 (Decision Memory).

        Creates:
        - Incident entity in Core 4
        - Links to involved findings (INCIDENT_INVOLVES_FINDING)
        - Links to impacted assets (INCIDENT_IMPACTS_ASSET)

        Args:
            incident: Dict with keys: id, title/name, severity (optional),
                      status (optional), finding_ids (optional list),
                      asset_ids (optional list), resolution (optional)

        Returns:
            entity_id used for the incident in TrustGraph
        """
        incident_id = incident.get("id") or incident.get("incident_id") or f"incident_{uuid.uuid4().hex[:8]}"
        entity_id = f"incident_{incident_id}" if not incident_id.startswith("incident_") else incident_id
        title = incident.get("title") or incident.get("name") or incident_id

        props: Dict[str, Any] = {
            "severity": incident.get("severity", "unknown"),
            "status": incident.get("status", "open"),
            "resolution": incident.get("resolution"),
            "created_at": incident.get("created_at", _now_iso()),
            "indexed_at": _now_iso(),
        }
        props = {k: v for k, v in props.items() if v is not None}

        entity = self._make_entity(
            entity_id=entity_id,
            core_id=CORE_DECISION_MEMORY,
            entity_type="Incident",
            name=title,
            properties=props,
        )
        self._safe_ingest(entity)

        # Link to findings
        for fid in incident.get("finding_ids", []):
            finding_entity_id = f"finding_{fid}" if not fid.startswith("finding_") else fid
            self._safe_relate(self._make_rel(
                entity_id, finding_entity_id, RelationshipType.INCIDENT_INVOLVES_FINDING
            ))

        # Link to assets
        for aid in incident.get("asset_ids", []):
            asset_entity_id = f"asset_{aid}" if not aid.startswith("asset_") else aid
            self._safe_relate(self._make_rel(
                entity_id, asset_entity_id, RelationshipType.INCIDENT_IMPACTS_ASSET
            ))

        logger.debug("TrustGraphBackbone.index_incident: %s", entity_id)
        return entity_id

    def index_compliance_control(self, control: Dict[str, Any]) -> str:
        """Index a compliance control into Core 3 (Compliance & Regulatory).

        Creates:
        - Control entity in Core 3
        - Framework entity in Core 3 (if framework present)
        - Links controls to findings they mitigate (CONTROL_MITIGATES_FINDING)

        Args:
            control: Dict with keys: id, name, framework (optional),
                     description (optional), status (optional),
                     mitigates_finding_ids (optional list),
                     evidence_ids (optional list)

        Returns:
            entity_id used for the control in TrustGraph
        """
        ctrl_id = control.get("id") or control.get("control_id") or f"control_{uuid.uuid4().hex[:8]}"
        entity_id = f"control_{ctrl_id}" if not ctrl_id.startswith("control_") else ctrl_id
        name = control.get("name") or ctrl_id
        framework = control.get("framework", "unknown")

        props: Dict[str, Any] = {
            "framework": framework,
            "status": control.get("status", "not_assessed"),
            "description": control.get("description", ""),
            "evidence_count": len(control.get("evidence_ids", [])),
            "indexed_at": _now_iso(),
        }
        props = {k: v for k, v in props.items() if v is not None}

        entity = self._make_entity(
            entity_id=entity_id,
            core_id=CORE_COMPLIANCE,
            entity_type="Control",
            name=name,
            properties=props,
        )
        self._safe_ingest(entity)

        # Ensure framework entity exists
        if framework and framework != "unknown":
            fw_entity_id = f"framework_{framework.lower().replace(' ', '_')}"
            fw_entity = self._make_entity(
                entity_id=fw_entity_id,
                core_id=CORE_COMPLIANCE,
                entity_type="Framework",
                name=f"Framework: {framework}",
                properties={"framework_id": framework},
            )
            self._safe_ingest(fw_entity)
            self._safe_relate(self._make_rel(
                entity_id, fw_entity_id, "part_of", confidence=1.0
            ))

        # Link to findings this control mitigates
        for fid in control.get("mitigates_finding_ids", []):
            finding_entity_id = f"finding_{fid}" if not fid.startswith("finding_") else fid
            self._safe_relate(self._make_rel(
                entity_id, finding_entity_id, RelationshipType.CONTROL_MITIGATES_FINDING
            ))

        logger.debug("TrustGraphBackbone.index_compliance_control: %s", entity_id)
        return entity_id

    def index_vendor(self, vendor: Dict[str, Any]) -> str:
        """Index a vendor into Core 5 (External Intelligence).

        Creates:
        - Vendor entity in Core 5
        - Component entities in Core 5, linked VENDOR_PROVIDES_COMPONENT

        Args:
            vendor: Dict with keys: id, name, risk_score (optional),
                    category (optional), components (optional list of str),
                    country (optional), tier (optional)

        Returns:
            entity_id used for the vendor in TrustGraph
        """
        vendor_id = vendor.get("id") or vendor.get("vendor_id") or f"vendor_{uuid.uuid4().hex[:8]}"
        entity_id = f"vendor_{vendor_id}" if not vendor_id.startswith("vendor_") else vendor_id
        name = vendor.get("name") or vendor_id

        props: Dict[str, Any] = {
            "risk_score": vendor.get("risk_score"),
            "category": vendor.get("category", "unknown"),
            "country": vendor.get("country"),
            "tier": vendor.get("tier", 3),
            "component_count": len(vendor.get("components", [])),
            "indexed_at": _now_iso(),
        }
        props = {k: v for k, v in props.items() if v is not None}

        entity = self._make_entity(
            entity_id=entity_id,
            core_id=CORE_EXTERNAL,
            entity_type="Vendor",
            name=name,
            properties=props,
        )
        self._safe_ingest(entity)

        # Index components
        for component_name in vendor.get("components", []):
            comp_id = f"component_{entity_id}_{component_name.lower().replace(' ', '_')}"
            comp_entity = self._make_entity(
                entity_id=comp_id,
                core_id=CORE_EXTERNAL,
                entity_type="Component",
                name=component_name,
                properties={"vendor_id": entity_id, "component_name": component_name},
            )
            self._safe_ingest(comp_entity)
            self._safe_relate(self._make_rel(
                entity_id, comp_id, RelationshipType.VENDOR_PROVIDES_COMPONENT
            ))

        logger.debug("TrustGraphBackbone.index_vendor: %s", entity_id)
        return entity_id

    def index_threat_actor(self, actor: Dict[str, Any]) -> str:
        """Index a threat actor into Core 2 (Threat Intelligence).

        Creates:
        - ThreatActor entity in Core 2
        - TTP entities in Core 2, linked ACTOR_USES_TTP
        - Asset links in Core 1, linked ACTOR_TARGETS_ASSET

        Args:
            actor: Dict with keys: id, name, sophistication (optional),
                   motivation (optional), ttps (optional list of str),
                   target_asset_ids (optional list), campaigns (optional list)

        Returns:
            entity_id used for the actor in TrustGraph
        """
        actor_id = actor.get("id") or actor.get("actor_id") or f"actor_{uuid.uuid4().hex[:8]}"
        entity_id = f"actor_{actor_id}" if not actor_id.startswith("actor_") else actor_id
        name = actor.get("name") or actor_id

        props: Dict[str, Any] = {
            "sophistication": actor.get("sophistication", "unknown"),
            "motivation": actor.get("motivation", "unknown"),
            "campaigns": actor.get("campaigns", []),
            "ttp_count": len(actor.get("ttps", [])),
            "indexed_at": _now_iso(),
        }
        props = {k: v for k, v in props.items() if v is not None}

        entity = self._make_entity(
            entity_id=entity_id,
            core_id=CORE_THREAT_INTEL,
            entity_type="ThreatActor",
            name=name,
            properties=props,
        )
        self._safe_ingest(entity)

        # Link TTPs
        for ttp in actor.get("ttps", []):
            ttp_id = f"ttp_{ttp.replace('.', '_').replace(' ', '_').lower()}"
            ttp_entity = self._make_entity(
                entity_id=ttp_id,
                core_id=CORE_THREAT_INTEL,
                entity_type="TTP",
                name=ttp,
                properties={"mitre_id": ttp},
            )
            self._safe_ingest(ttp_entity)
            self._safe_relate(self._make_rel(
                entity_id, ttp_id, RelationshipType.ACTOR_USES_TTP
            ))

        # Link targeted assets
        for aid in actor.get("target_asset_ids", []):
            asset_entity_id = f"asset_{aid}" if not aid.startswith("asset_") else aid
            self._safe_relate(self._make_rel(
                entity_id, asset_entity_id, RelationshipType.ACTOR_TARGETS_ASSET
            ))

        logger.debug("TrustGraphBackbone.index_threat_actor: %s", entity_id)
        return entity_id

    def link_entities(
        self,
        entity_a_id: str,
        entity_b_id: str,
        relationship_type: str,
        confidence: float = 0.95,
        properties: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Create a typed edge between two entities.

        Args:
            entity_a_id: Source entity ID
            entity_b_id: Target entity ID
            relationship_type: One of RelationshipType constants
            confidence: Edge confidence score 0-1
            properties: Optional edge properties

        Returns:
            rel_id of the created relationship, or empty string on failure
        """
        if not self._available or self._store is None:
            return ""

        rel = self._make_rel(entity_a_id, entity_b_id, relationship_type, confidence, properties)
        if self._safe_relate(rel):
            logger.debug(
                "TrustGraphBackbone.link_entities: %s -[%s]-> %s",
                entity_a_id,
                relationship_type,
                entity_b_id,
            )
            return rel.rel_id
        return ""

    # =========================================================================
    # Event Bus Integration
    # =========================================================================

    def register_event_handlers(self, bus: Any) -> None:
        """Register auto-index handlers on the EventBus.

        Call this once at application startup to wire auto-indexing.

        Args:
            bus: EventBus instance (from core.event_bus.get_event_bus())
        """
        from core.event_bus import EventType

        @bus.on(EventType.FINDING_CREATED)
        async def on_finding_created(event: Any) -> None:
            """Auto-index finding when created."""
            try:
                self.index_finding(event.data)
            except Exception as exc:
                logger.warning("on_finding_created backbone handler failed: %s", exc)

        @bus.on(EventType.ASSET_DISCOVERED)
        async def on_asset_discovered(event: Any) -> None:
            """Auto-index asset when discovered."""
            try:
                self.index_asset(event.data)
            except Exception as exc:
                logger.warning("on_asset_discovered backbone handler failed: %s", exc)

        logger.info("TrustGraphBackbone: event handlers registered on EventBus")

    def on_finding_created(self, finding_data: Dict[str, Any]) -> str:
        """Synchronous handler for finding creation events."""
        return self.index_finding(finding_data)

    def on_asset_discovered(self, asset_data: Dict[str, Any]) -> str:
        """Synchronous handler for asset discovery events."""
        return self.index_asset(asset_data)

    def on_incident_created(self, incident_data: Dict[str, Any]) -> str:
        """Synchronous handler for incident creation events."""
        return self.index_incident(incident_data)

    def on_compliance_assessed(self, control_data: Dict[str, Any]) -> str:
        """Synchronous handler for compliance assessment events."""
        return self.index_compliance_control(control_data)

    # =========================================================================
    # Graph Statistics
    # =========================================================================

    def get_stats(self) -> Dict[str, Any]:
        """Return statistics for all 5 Knowledge Cores.

        Returns:
            Dict with per-core stats and aggregate totals
        """
        if not self._available or self._store is None:
            return {
                "available": False,
                "cores": {},
                "total_entities": 0,
                "total_relationships": 0,
            }

        stats: Dict[str, Any] = {
            "available": True,
            "cores": {},
            "total_entities": 0,
            "total_relationships": 0,
        }

        core_names = {
            1: "customer_env",
            2: "threat_intel",
            3: "compliance",
            4: "decision_memory",
            5: "external",
        }

        for core_id in range(1, 6):
            try:
                core_stat = self._store.core_stats(core_id)
                stats["cores"][core_id] = {
                    "name": core_names[core_id],
                    **core_stat,
                }
                stats["total_entities"] += core_stat.get("entity_count", 0)
                stats["total_relationships"] += core_stat.get("relationship_count", 0)
            except Exception as exc:
                logger.warning("Failed to get stats for core %d: %s", core_id, exc)
                stats["cores"][core_id] = {"name": core_names[core_id], "error": str(exc)}

        return stats


# ---------------------------------------------------------------------------
# GraphRAGEnhanced
# ---------------------------------------------------------------------------


class GraphRAGEnhanced:
    """AI-powered cross-module graph queries.

    Provides semantic traversal operations over the TrustGraph backbone,
    enabling impact analysis, root cause tracing, attack path finding,
    and natural language search across all knowledge cores.

    Args:
        db_path: Optional path override for TrustGraph SQLite DB.
        org_id: Tenant org ID.
    """

    def __init__(
        self,
        db_path: Optional[str] = None,
        org_id: str = "default",
    ) -> None:
        self.org_id = org_id
        self._backbone = TrustGraphBackbone(db_path=db_path, org_id=org_id)

    @property
    def _store(self) -> Optional[Any]:
        return self._backbone._store

    @property
    def _available(self) -> bool:
        return self._backbone._available

    def query_impact(self, entity_id: str, depth: int = 2) -> Dict[str, Any]:
        """What is affected if this entity is compromised?

        Traverses outgoing relationships from the entity to find all
        transitively affected assets, services, and findings.

        Args:
            entity_id: Starting entity ID
            depth: Traversal depth (1-3)

        Returns:
            Dict with affected_entities, relationships, summary
        """
        if not self._available or self._store is None:
            return {"available": False, "entity_id": entity_id, "affected_entities": []}

        depth = max(1, min(depth, 3))

        try:
            neighbors = self._store.get_neighbors(entity_id=entity_id, depth=depth)
            rels = self._store.get_relationships(entity_id=entity_id)

            # Build downstream relationships (what this entity affects)
            downstream_rels = [r for r in rels if r.source_id == entity_id]

            affected = [n.to_dict() for n in neighbors]
            rel_dicts = [r.to_dict() for r in downstream_rels]

            # Classify impact by entity type
            by_type: Dict[str, int] = {}
            for n in neighbors:
                by_type[n.entity_type] = by_type.get(n.entity_type, 0) + 1

            return {
                "available": True,
                "entity_id": entity_id,
                "depth": depth,
                "affected_entities": affected,
                "relationships": rel_dicts,
                "affected_count": len(affected),
                "impact_by_type": by_type,
                "summary": (
                    f"Entity '{entity_id}' has {len(affected)} affected neighbors "
                    f"at depth {depth}: {by_type}"
                ),
            }
        except Exception as exc:
            logger.warning("GraphRAGEnhanced.query_impact failed for %s: %s", entity_id, exc)
            return {"available": False, "entity_id": entity_id, "error": str(exc), "affected_entities": []}

    def query_root_cause(self, finding_id: str) -> Dict[str, Any]:
        """Trace a finding back to its root cause.

        Follows FINDING_EXPLOITS_CVE and FINDING_AFFECTS_ASSET relationships
        backward to identify the underlying vulnerability and affected scope.

        Args:
            finding_id: Finding entity ID (with or without 'finding_' prefix)

        Returns:
            Dict with root_causes, affected_assets, cves, summary
        """
        if not self._available or self._store is None:
            return {"available": False, "finding_id": finding_id, "root_causes": []}

        # Normalize ID
        entity_id = f"finding_{finding_id}" if not finding_id.startswith("finding_") else finding_id

        try:
            entity = self._store.get_entity(entity_id)
            if entity is None:
                return {
                    "available": True,
                    "finding_id": finding_id,
                    "error": "Finding not found in graph",
                    "root_causes": [],
                }

            rels = self._store.get_relationships(entity_id=entity_id)

            cves = []
            affected_assets = []

            for rel in rels:
                if rel.rel_type == RelationshipType.FINDING_EXPLOITS_CVE:
                    target = self._store.get_entity(rel.target_id)
                    if target:
                        cves.append(target.to_dict())
                elif rel.rel_type == RelationshipType.FINDING_AFFECTS_ASSET:
                    target = self._store.get_entity(rel.target_id)
                    if target:
                        affected_assets.append(target.to_dict())

            root_causes = cves if cves else [{"note": "No CVE linked — check scanner output"}]

            return {
                "available": True,
                "finding_id": finding_id,
                "finding": entity.to_dict(),
                "root_causes": root_causes,
                "cves": cves,
                "affected_assets": affected_assets,
                "summary": (
                    f"Finding '{finding_id}' exploits {len(cves)} CVE(s) "
                    f"and affects {len(affected_assets)} asset(s)"
                ),
            }
        except Exception as exc:
            logger.warning("GraphRAGEnhanced.query_root_cause failed for %s: %s", finding_id, exc)
            return {"available": False, "finding_id": finding_id, "error": str(exc), "root_causes": []}

    def query_attack_path(self, source_id: str, target_id: str) -> Dict[str, Any]:
        """Find graph paths between source and target entities.

        Uses BFS traversal to discover paths, useful for modeling
        lateral movement or supply chain attack vectors.

        Args:
            source_id: Starting entity ID
            target_id: Target entity ID

        Returns:
            Dict with paths, path_count, summary
        """
        if not self._available or self._store is None:
            return {"available": False, "source_id": source_id, "target_id": target_id, "paths": []}

        try:
            # BFS up to depth 4
            max_depth = 4
            queue: List[List[str]] = [[source_id]]
            visited: set = {source_id}
            found_paths: List[List[str]] = []

            while queue and len(found_paths) < 5:
                path = queue.pop(0)
                current = path[-1]

                if len(path) > max_depth:
                    continue

                rels = self._store.get_relationships(entity_id=current)
                for rel in rels:
                    neighbor = rel.target_id if rel.source_id == current else rel.source_id
                    if neighbor == target_id:
                        found_paths.append(path + [neighbor])
                    elif neighbor not in visited and len(path) < max_depth:
                        visited.add(neighbor)
                        queue.append(path + [neighbor])

            # Enrich paths with entity names
            enriched_paths = []
            for path in found_paths:
                enriched = []
                for eid in path:
                    entity = self._store.get_entity(eid)
                    enriched.append({
                        "entity_id": eid,
                        "name": entity.name if entity else eid,
                        "entity_type": entity.entity_type if entity else "unknown",
                    })
                enriched_paths.append(enriched)

            return {
                "available": True,
                "source_id": source_id,
                "target_id": target_id,
                "paths": enriched_paths,
                "path_count": len(enriched_paths),
                "summary": (
                    f"Found {len(enriched_paths)} path(s) from '{source_id}' to '{target_id}'"
                    if enriched_paths
                    else f"No path found from '{source_id}' to '{target_id}' within depth {max_depth}"
                ),
            }
        except Exception as exc:
            logger.warning(
                "GraphRAGEnhanced.query_attack_path failed %s->%s: %s", source_id, target_id, exc
            )
            return {
                "available": False,
                "source_id": source_id,
                "target_id": target_id,
                "error": str(exc),
                "paths": [],
            }

    def query_related(self, entity_id: str, depth: int = 2) -> Dict[str, Any]:
        """Neighborhood exploration — what's related to this entity.

        Args:
            entity_id: Entity to explore
            depth: Traversal depth (1-3)

        Returns:
            Dict with entity, neighbors, relationships, grouped by type
        """
        if not self._available or self._store is None:
            return {"available": False, "entity_id": entity_id, "neighbors": []}

        depth = max(1, min(depth, 3))

        try:
            entity = self._store.get_entity(entity_id)
            neighbors = self._store.get_neighbors(entity_id=entity_id, depth=depth)
            rels = self._store.get_relationships(entity_id=entity_id)

            # Group neighbors by entity type
            by_type: Dict[str, List[Dict[str, Any]]] = {}
            for n in neighbors:
                by_type.setdefault(n.entity_type, []).append(n.to_dict())

            return {
                "available": True,
                "entity_id": entity_id,
                "entity": entity.to_dict() if entity else None,
                "depth": depth,
                "neighbors": [n.to_dict() for n in neighbors],
                "relationships": [r.to_dict() for r in rels],
                "neighbors_by_type": by_type,
                "neighbor_count": len(neighbors),
            }
        except Exception as exc:
            logger.warning("GraphRAGEnhanced.query_related failed for %s: %s", entity_id, exc)
            return {"available": False, "entity_id": entity_id, "error": str(exc), "neighbors": []}

    def query_risk_context(self, finding_id: str) -> Dict[str, Any]:
        """Full risk context for LLM Council decision-making.

        Assembles: finding details, linked CVEs, affected assets,
        applicable compliance controls, related incidents, and
        historical decisions from Core 4.

        Args:
            finding_id: Finding entity ID

        Returns:
            Dict with full risk context suitable for LLM Council injection
        """
        if not self._available or self._store is None:
            return {"available": False, "finding_id": finding_id}

        entity_id = f"finding_{finding_id}" if not finding_id.startswith("finding_") else finding_id

        try:
            finding = self._store.get_entity(entity_id)
            if finding is None:
                return {"available": True, "finding_id": finding_id, "error": "Not found"}

            rels = self._store.get_relationships(entity_id=entity_id)

            cves: List[Dict[str, Any]] = []
            assets: List[Dict[str, Any]] = []
            controls: List[Dict[str, Any]] = []
            incidents: List[Dict[str, Any]] = []

            for rel in rels:
                other_id = rel.target_id if rel.source_id == entity_id else rel.source_id
                other = self._store.get_entity(other_id)
                if other is None:
                    continue

                if rel.rel_type == RelationshipType.FINDING_EXPLOITS_CVE:
                    cves.append(other.to_dict())
                elif rel.rel_type == RelationshipType.FINDING_AFFECTS_ASSET:
                    assets.append(other.to_dict())
                elif rel.rel_type == RelationshipType.CONTROL_MITIGATES_FINDING:
                    controls.append(other.to_dict())
                elif rel.rel_type == RelationshipType.INCIDENT_INVOLVES_FINDING:
                    incidents.append(other.to_dict())

            # Build LLM-ready context string
            context_lines = [
                f"Finding: {finding.name} (severity: {finding.properties.get('severity', 'unknown')})",
                f"CVEs: {', '.join(c.get('name', '') for c in cves) or 'None'}",
                f"Affected assets: {len(assets)} asset(s)",
                f"Mitigating controls: {len(controls)} control(s)",
                f"Related incidents: {len(incidents)} incident(s)",
            ]

            return {
                "available": True,
                "finding_id": finding_id,
                "finding": finding.to_dict(),
                "cves": cves,
                "affected_assets": assets,
                "mitigating_controls": controls,
                "related_incidents": incidents,
                "llm_context": "\n".join(context_lines),
                "risk_score_inputs": {
                    "severity": finding.properties.get("severity", "unknown"),
                    "cvss": finding.properties.get("cvss"),
                    "epss": finding.properties.get("epss"),
                    "asset_count": len(assets),
                    "control_count": len(controls),
                    "in_incident": len(incidents) > 0,
                },
            }
        except Exception as exc:
            logger.warning("GraphRAGEnhanced.query_risk_context failed for %s: %s", finding_id, exc)
            return {"available": False, "finding_id": finding_id, "error": str(exc)}

    def semantic_search(
        self,
        query: str,
        cores: Optional[List[int]] = None,
        limit: int = 10,
    ) -> Dict[str, Any]:
        """Natural language graph search across knowledge cores.

        Searches entity names and properties using FTS5 with LIKE fallback.

        Args:
            query: Natural language search string
            cores: List of core IDs to search (default: all 5)
            limit: Max results per core

        Returns:
            Dict with results grouped by core, total_count
        """
        if not self._available or self._store is None:
            return {"available": False, "query": query, "results": [], "total_count": 0}

        search_cores = cores if cores else [1, 2, 3, 4, 5]

        all_results: List[Dict[str, Any]] = []
        by_core: Dict[int, List[Dict[str, Any]]] = {}

        for core_id in search_cores:
            try:
                entities = self._store.search(
                    core_id=core_id,
                    query_text=query,
                    filters={"org_id": self.org_id},
                    limit=limit,
                )
                if not entities:
                    # LIKE fallback
                    conn = self._store._get_conn()
                    cursor = conn.cursor()
                    like_term = f"%{query}%"
                    cursor.execute(
                        """
                        SELECT * FROM entities
                        WHERE (name LIKE ? OR properties LIKE ?)
                        AND core_id = ? AND org_id = ? AND deleted_at IS NULL
                        LIMIT ?
                        """,
                        (like_term, like_term, core_id, self.org_id, limit),
                    )
                    rows = cursor.fetchall()
                    entities = [self._store._row_to_entity(row) for row in rows]

                core_results = [e.to_dict() for e in entities]
                by_core[core_id] = core_results
                all_results.extend(core_results)
            except Exception as exc:
                logger.debug("semantic_search failed for core %d: %s", core_id, exc)

        return {
            "available": True,
            "query": query,
            "results": all_results,
            "results_by_core": by_core,
            "total_count": len(all_results),
            "cores_searched": search_cores,
        }

    def get_visualization_data(self, entity_id: str, depth: int = 2) -> Dict[str, Any]:
        """Return graph data suitable for frontend visualization.

        Produces a nodes+edges structure compatible with D3/Cytoscape/React Flow.

        Args:
            entity_id: Central entity for visualization
            depth: Traversal depth

        Returns:
            Dict with nodes (list) and edges (list) for graph rendering
        """
        if not self._available or self._store is None:
            return {"available": False, "entity_id": entity_id, "nodes": [], "edges": []}

        depth = max(1, min(depth, 3))

        try:
            center = self._store.get_entity(entity_id)
            neighbors = self._store.get_neighbors(entity_id=entity_id, depth=depth)
            all_entities = ([center] if center else []) + neighbors

            nodes = []
            seen_ids: set = set()
            for e in all_entities:
                if e.entity_id in seen_ids:
                    continue
                seen_ids.add(e.entity_id)
                nodes.append({
                    "id": e.entity_id,
                    "label": e.name,
                    "type": e.entity_type,
                    "core_id": e.core_id,
                    "properties": e.properties,
                    "is_center": e.entity_id == entity_id,
                })

            edges = []
            for eid in seen_ids:
                try:
                    rels = self._store.get_relationships(entity_id=eid)
                    for rel in rels:
                        if rel.source_id in seen_ids and rel.target_id in seen_ids:
                            edges.append({
                                "id": rel.rel_id,
                                "source": rel.source_id,
                                "target": rel.target_id,
                                "type": rel.rel_type,
                                "confidence": rel.confidence,
                                "properties": rel.properties,
                            })
                except Exception as exc:
                    logger.debug("trustgraph_backbone: relationship serialization failed", exc_info=exc)

            return {
                "available": True,
                "entity_id": entity_id,
                "nodes": nodes,
                "edges": edges,
                "node_count": len(nodes),
                "edge_count": len(edges),
            }
        except Exception as exc:
            logger.warning("GraphRAGEnhanced.get_visualization_data failed for %s: %s", entity_id, exc)
            return {"available": False, "entity_id": entity_id, "error": str(exc), "nodes": [], "edges": []}


# ---------------------------------------------------------------------------
# Module-level singletons
# ---------------------------------------------------------------------------

_backbone: Optional[TrustGraphBackbone] = None
_graphrag_enhanced: Optional[GraphRAGEnhanced] = None


def get_backbone(db_path: Optional[str] = None, org_id: str = "default") -> TrustGraphBackbone:
    """Return the module-level TrustGraphBackbone singleton."""
    global _backbone
    if _backbone is None:
        _backbone = TrustGraphBackbone(db_path=db_path, org_id=org_id)
    return _backbone


def get_graphrag_enhanced(db_path: Optional[str] = None, org_id: str = "default") -> GraphRAGEnhanced:
    """Return the module-level GraphRAGEnhanced singleton."""
    global _graphrag_enhanced
    if _graphrag_enhanced is None:
        _graphrag_enhanced = GraphRAGEnhanced(db_path=db_path, org_id=org_id)
    return _graphrag_enhanced
