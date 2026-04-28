"""
TrustGraph Integration Layer — Universal adapter wiring ALL ALDECI security engines
into the TrustGraph knowledge graph backbone.

Every ALDECI engine (SAST, DAST, SCA, CSPM, RASP, ASM, connectors, feeds) emits
findings through this layer. This module normalizes, deduplicates, enriches, and
routes them into the correct Knowledge Core, then exposes pre-built GraphRAG query
templates for dashboards.

Knowledge Core routing:
    SecurityCore  → Core 2 (threat_intel): vulns, findings, CVEs, scan results
    AssetCore     → Core 1 (customer_env): infra, containers, services, K8s, zones
    ComplianceCore→ Core 3 (compliance): controls, frameworks, evidence, gaps
    ThreatCore    → Core 2 (threat_intel): actors, campaigns, TTPs, IOCs
    OperationalCore→Core 4 (decision_memory): incidents, SLAs, metrics, verdicts

Usage:
    indexer = UniversalFindingIndexer()
    entity_id = indexer.index({"engine": "sast", "cve_id": "CVE-2024-1234", ...})

    correlator = CrossDomainCorrelator()
    chain = correlator.correlate_cve("CVE-2024-1234")

    analyzer = ImpactAnalyzer()
    blast = analyzer.blast_radius("asset_prod_api")

    graphrag = GraphRAGQueries()
    risks = graphrag.top_risks()
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import structlog
from pydantic import BaseModel, Field, field_validator

logger = structlog.get_logger(__name__)

__all__ = [
    "UniversalFindingIndexer",
    "CrossDomainCorrelator",
    "AttackPathEnricher",
    "ImpactAnalyzer",
    "KnowledgeCoreRouter",
    "BatchIndexer",
    "GraphRAGQueries",
    "FindingInput",
    "BatchIndexResult",
    "ImpactResult",
    "CorrelationResult",
]

# ---------------------------------------------------------------------------
# Engine → Knowledge Core routing table
# ---------------------------------------------------------------------------

_ENGINE_CORE_MAP: Dict[str, int] = {
    # Security engines → Core 2 (threat_intel)
    "sast": 2,
    "dast": 2,
    "sca": 2,
    "rasp": 2,
    "iast": 2,
    "scanner": 2,
    "pentest": 2,
    "fuzzer": 2,
    "secrets": 2,
    "dependency": 2,
    # Cloud/infra engines → Core 1 (customer_env) for assets, Core 2 for findings
    "cspm": 2,
    "cwpp": 2,
    "asm": 2,
    "container": 2,
    # Threat intel → Core 2
    "threat_intel": 2,
    "feed": 2,
    "osint": 2,
    # Compliance → Core 3
    "compliance": 3,
    "audit": 3,
    "policy": 3,
    # Operational → Core 4
    "incident": 4,
    "siem": 4,
    "soar": 4,
    # External/vendor → Core 5
    "vendor": 5,
    "sbom": 5,
    "supply_chain": 5,
}

# Severity → numeric risk weight
_SEVERITY_WEIGHT: Dict[str, float] = {
    "critical": 10.0,
    "high": 7.5,
    "medium": 5.0,
    "low": 2.5,
    "info": 0.5,
    "informational": 0.5,
    "unknown": 1.0,
}

# Supported GraphRAG query templates
_QUERY_TEMPLATES = {
    "top_risks",
    "exposure_chain",
    "compliance_gaps",
    "attack_surface",
    "threat_landscape",
}

CORE_SECURITY = 2   # threat_intel
CORE_ASSET = 1      # customer_env
CORE_COMPLIANCE = 3
CORE_THREAT = 2     # threat_intel (actors, campaigns)
CORE_OPERATIONAL = 4  # decision_memory


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _entity_id(*parts: str) -> str:
    """Build a stable entity ID from parts, lower-cased and underscored."""
    joined = "_".join(p.lower().replace("-", "_").replace(" ", "_").replace(".", "_") for p in parts if p)
    return joined[:128]  # cap length


# ---------------------------------------------------------------------------
# Pydantic v2 Models
# ---------------------------------------------------------------------------


class FindingInput(BaseModel):
    """Normalized input for any security finding from any engine."""

    id: Optional[str] = Field(default=None, description="Finding ID (auto-generated if absent)")
    engine: str = Field(..., description="Source engine: sast, dast, sca, cspm, rasp, asm, etc.")
    title: Optional[str] = Field(default=None, description="Human-readable finding title")
    description: Optional[str] = Field(default=None)
    severity: str = Field(default="unknown", description="critical|high|medium|low|info|unknown")
    cve_id: Optional[str] = Field(default=None, description="CVE identifier if applicable")
    cwe_id: Optional[str] = Field(default=None, description="CWE identifier if applicable")
    cvss: Optional[float] = Field(default=None, ge=0.0, le=10.0)
    epss: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    asset_id: Optional[str] = Field(default=None)
    asset_name: Optional[str] = Field(default=None)
    asset_type: Optional[str] = Field(default=None, description="container|vm|service|endpoint|k8s_pod|etc.")
    namespace: Optional[str] = Field(default=None, description="K8s namespace or logical grouping")
    control_ids: List[str] = Field(default_factory=list, description="Compliance control IDs violated")
    scanner: Optional[str] = Field(default=None, description="Specific scanner within the engine")
    status: str = Field(default="open", description="open|confirmed|false_positive|remediated")
    timestamp: Optional[str] = Field(default=None, description="ISO 8601 timestamp of detection")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Engine-specific extra fields")

    @field_validator("severity")
    @classmethod
    def normalise_severity(cls, v: str) -> str:
        v = v.lower().strip()
        return v if v in _SEVERITY_WEIGHT else "unknown"

    @field_validator("engine")
    @classmethod
    def normalise_engine(cls, v: str) -> str:
        return v.lower().strip()

    model_config = {"extra": "ignore"}


class BatchIndexResult(BaseModel):
    """Result of a batch indexing operation."""

    total: int
    indexed: int
    deduplicated: int
    merged: int
    failed: int
    entity_ids: List[str]
    errors: List[str] = Field(default_factory=list)


class ImpactResult(BaseModel):
    """Blast radius analysis for an entity."""

    entity_id: str
    available: bool
    blast_radius: int
    upstream_dependencies: List[Dict[str, Any]] = Field(default_factory=list)
    downstream_consumers: List[Dict[str, Any]] = Field(default_factory=list)
    data_flows: List[Dict[str, Any]] = Field(default_factory=list)
    compliance_impact: List[Dict[str, Any]] = Field(default_factory=list)
    risk_weight: float = 0.0
    summary: str = ""


class CorrelationResult(BaseModel):
    """Cross-domain correlation result for a CVE or finding."""

    query: str
    available: bool
    containers: List[Dict[str, Any]] = Field(default_factory=list)
    namespaces: List[Dict[str, Any]] = Field(default_factory=list)
    data_classifications: List[str] = Field(default_factory=list)
    compliance_controls: List[Dict[str, Any]] = Field(default_factory=list)
    dollar_risk_estimate: float = 0.0
    chain_summary: str = ""


# ---------------------------------------------------------------------------
# Knowledge Core Router
# ---------------------------------------------------------------------------


class KnowledgeCoreRouter:
    """Route entities to the correct TrustGraph Knowledge Core.

    Stateless — methods are pure functions over the routing table.
    """

    # Core name labels
    CORE_NAMES = {
        1: "AssetCore (customer_env)",
        2: "SecurityCore (threat_intel)",
        3: "ComplianceCore (compliance)",
        4: "OperationalCore (decision_memory)",
        5: "ExternalCore (vendors/components)",
    }

    @staticmethod
    def core_for_engine(engine: str) -> int:
        """Return the Knowledge Core ID for a given engine name."""
        return _ENGINE_CORE_MAP.get(engine.lower(), CORE_SECURITY)

    @staticmethod
    def core_for_entity_type(entity_type: str) -> int:
        """Return the Knowledge Core ID for a given entity type string."""
        mapping = {
            "finding": CORE_SECURITY,
            "vulnerability": CORE_SECURITY,
            "cve": CORE_SECURITY,
            "ttp": CORE_SECURITY,
            "threat_actor": CORE_SECURITY,
            "ioc": CORE_SECURITY,
            "campaign": CORE_SECURITY,
            "asset": CORE_ASSET,
            "service": CORE_ASSET,
            "container": CORE_ASSET,
            "k8s_namespace": CORE_ASSET,
            "k8s_pod": CORE_ASSET,
            "zone": CORE_ASSET,
            "network": CORE_ASSET,
            "control": CORE_COMPLIANCE,
            "framework": CORE_COMPLIANCE,
            "evidence": CORE_COMPLIANCE,
            "policy": CORE_COMPLIANCE,
            "incident": CORE_OPERATIONAL,
            "verdict": CORE_OPERATIONAL,
            "metric": CORE_OPERATIONAL,
            "sla": CORE_OPERATIONAL,
            "vendor": 5,
            "component": 5,
            "sbom_entry": 5,
        }
        return mapping.get(entity_type.lower(), CORE_SECURITY)

    @classmethod
    def describe(cls, core_id: int) -> str:
        """Human-readable description of a core."""
        return cls.CORE_NAMES.get(core_id, f"Core {core_id}")


# ---------------------------------------------------------------------------
# Universal Finding Indexer
# ---------------------------------------------------------------------------


class UniversalFindingIndexer:
    """Accept findings from ANY engine and index into TrustGraph.

    Creates the following graph structure per finding:
      Finding entity (SecurityCore)
        ├─ FINDING_EXPLOITS_CVE → CVE entity (SecurityCore)
        ├─ FINDING_AFFECTS_ASSET → Asset entity (AssetCore)
        ├─ caused_by_cwe → CWE entity (SecurityCore)
        ├─ found_by_scanner → Scanner entity (SecurityCore)
        └─ violates_control → Control entity (ComplianceCore) [for each control_id]

    Idempotent — upsert semantics via backbone._safe_ingest.

    Args:
        org_id: Tenant org ID for multi-tenancy.
        db_path: Optional TrustGraph DB path override.
    """

    def __init__(self, org_id: str = "default", db_path: Optional[str] = None) -> None:
        self.org_id = org_id
        self._db_path = db_path
        self._router = KnowledgeCoreRouter()

    def _get_backbone(self):
        from core.trustgraph_backbone import TrustGraphBackbone
        return TrustGraphBackbone(db_path=self._db_path, org_id=self.org_id)

    def index(self, raw_finding: Dict[str, Any]) -> str:
        """Index a raw finding dict from any engine.

        Normalises via FindingInput, routes to the correct core, creates
        entities and relationships. Never raises — failures are logged.

        Args:
            raw_finding: Dict with at minimum an 'engine' key. All other
                         fields are optional and engine-specific.

        Returns:
            entity_id of the indexed finding in TrustGraph.
        """
        try:
            finding = FindingInput.model_validate(raw_finding)
        except Exception as exc:
            logger.warning("trustgraph_integrations.index: validation failed", error=str(exc))
            # Fallback: use raw dict, engine defaults to "scanner"
            finding = FindingInput(
                engine=raw_finding.get("engine", "scanner"),
                severity=raw_finding.get("severity", "unknown"),
            )

        backbone = self._get_backbone()
        core_id = self._router.core_for_engine(finding.engine)

        # Build stable entity ID
        raw_id = finding.id or f"{finding.engine}_{uuid.uuid4().hex[:8]}"
        finding_id = _entity_id("finding", raw_id) if not raw_id.startswith("finding_") else raw_id
        title = finding.title or finding.cve_id or raw_id

        props: Dict[str, Any] = {
            "engine": finding.engine,
            "severity": finding.severity,
            "status": finding.status,
            "scanner": finding.scanner or finding.engine,
            "description": finding.description or "",
            "timestamp": finding.timestamp or _now_iso(),
            "indexed_at": _now_iso(),
            "risk_weight": _SEVERITY_WEIGHT.get(finding.severity, 1.0),
            **{k: v for k, v in finding.metadata.items() if v is not None},
        }
        if finding.cvss is not None:
            props["cvss"] = finding.cvss
        if finding.epss is not None:
            props["epss"] = finding.epss
        if finding.cwe_id:
            props["cwe_id"] = finding.cwe_id

        entity = backbone._make_entity(
            entity_id=finding_id,
            core_id=core_id,
            entity_type="Finding",
            name=title,
            properties=props,
        )
        backbone._safe_ingest(entity)

        # CVE relationship
        if finding.cve_id:
            cve_entity_id = _entity_id("cve", finding.cve_id)
            cve_ent = backbone._make_entity(
                entity_id=cve_entity_id,
                core_id=CORE_SECURITY,
                entity_type="CVE",
                name=finding.cve_id,
                properties={
                    "cve_id": finding.cve_id,
                    "cvss": finding.cvss,
                    "severity": finding.severity,
                    "indexed_at": _now_iso(),
                },
            )
            backbone._safe_ingest(cve_ent)
            backbone._safe_relate(backbone._make_rel(
                finding_id, cve_entity_id, "FINDING_EXPLOITS_CVE"
            ))

        # CWE relationship
        if finding.cwe_id:
            cwe_entity_id = _entity_id("cwe", finding.cwe_id)
            cwe_ent = backbone._make_entity(
                entity_id=cwe_entity_id,
                core_id=CORE_SECURITY,
                entity_type="CWE",
                name=finding.cwe_id,
                properties={"cwe_id": finding.cwe_id, "indexed_at": _now_iso()},
            )
            backbone._safe_ingest(cwe_ent)
            backbone._safe_relate(backbone._make_rel(
                finding_id, cwe_entity_id, "caused_by_cwe"
            ))

        # Asset relationship
        if finding.asset_id or finding.asset_name:
            raw_asset_id = finding.asset_id or _entity_id("asset", finding.asset_name or "unknown")
            asset_entity_id = raw_asset_id if raw_asset_id.startswith("asset_") else _entity_id("asset", raw_asset_id)

            # Ensure asset entity exists (minimal upsert)
            asset_ent = backbone._make_entity(
                entity_id=asset_entity_id,
                core_id=CORE_ASSET,
                entity_type="Asset",
                name=finding.asset_name or finding.asset_id or asset_entity_id,
                properties={
                    "asset_type": finding.asset_type or "unknown",
                    "namespace": finding.namespace,
                    "indexed_at": _now_iso(),
                },
            )
            backbone._safe_ingest(asset_ent)
            backbone._safe_relate(backbone._make_rel(
                finding_id, asset_entity_id, "FINDING_AFFECTS_ASSET"
            ))

        # Scanner entity
        scanner_name = finding.scanner or finding.engine
        scanner_entity_id = _entity_id("scanner", scanner_name)
        scanner_ent = backbone._make_entity(
            entity_id=scanner_entity_id,
            core_id=CORE_SECURITY,
            entity_type="Scanner",
            name=scanner_name,
            properties={"engine": finding.engine, "indexed_at": _now_iso()},
        )
        backbone._safe_ingest(scanner_ent)
        backbone._safe_relate(backbone._make_rel(
            finding_id, scanner_entity_id, "found_by_scanner"
        ))

        # Compliance control violations
        for ctrl_id in finding.control_ids:
            ctrl_entity_id = _entity_id("control", ctrl_id)
            backbone._safe_relate(backbone._make_rel(
                finding_id, ctrl_entity_id, "violates_control"
            ))

        logger.debug(
            "trustgraph_integrations.index: indexed finding",
            finding_id=finding_id,
            engine=finding.engine,
            core_id=core_id,
        )
        return finding_id

    def index_from_scan_result(self, scan_result: Dict[str, Any]) -> List[str]:
        """Index all findings within a scanner result dict.

        Supports the common pattern where scanners return a dict with a
        'findings' or 'vulnerabilities' list.

        Args:
            scan_result: Dict with 'engine' and 'findings'/'vulnerabilities' list.

        Returns:
            List of entity_ids indexed.
        """
        engine = scan_result.get("engine", "scanner")
        findings_raw: List[Dict[str, Any]] = (
            scan_result.get("findings")
            or scan_result.get("vulnerabilities")
            or scan_result.get("results")
            or []
        )
        entity_ids: List[str] = []
        for item in findings_raw:
            item.setdefault("engine", engine)
            entity_ids.append(self.index(item))
        return entity_ids


# ---------------------------------------------------------------------------
# Cross-Domain Correlator
# ---------------------------------------------------------------------------


class CrossDomainCorrelator:
    """Enable cross-domain graph queries across all security engines.

    Given a CVE, finding, or asset, traverse the graph to build the full
    exposure chain: containers → namespaces → data classifications →
    compliance controls → dollar risk estimate.

    Args:
        org_id: Tenant org ID.
        db_path: Optional DB path override.
    """

    def __init__(self, org_id: str = "default", db_path: Optional[str] = None) -> None:
        self.org_id = org_id
        self._db_path = db_path

    def _get_backbone(self):
        from core.trustgraph_backbone import TrustGraphBackbone
        return TrustGraphBackbone(db_path=self._db_path, org_id=self.org_id)

    def correlate_cve(self, cve_id: str) -> CorrelationResult:
        """Full cross-domain correlation for a CVE.

        Query: "Given CVE-2024-1234, show which containers use it →
        which K8s namespaces → which data they process →
        which compliance controls are affected → dollar risk estimate."

        Args:
            cve_id: CVE identifier (e.g. "CVE-2024-1234")

        Returns:
            CorrelationResult with full chain.
        """
        backbone = self._get_backbone()
        if not backbone._available or backbone._store is None:
            return CorrelationResult(query=cve_id, available=False)

        cve_entity_id = _entity_id("cve", cve_id)

        try:
            store = backbone._store
            containers: List[Dict[str, Any]] = []
            namespaces: List[Dict[str, Any]] = []
            controls: List[Dict[str, Any]] = []
            data_classifications: List[str] = []

            # Step 1: Find findings that exploit this CVE
            cve_rels = store.get_relationships(entity_id=cve_entity_id)
            finding_ids = [
                r.source_id for r in cve_rels
                if r.rel_type == "FINDING_EXPLOITS_CVE"
            ]

            # Step 2: For each finding, get affected assets
            asset_entity_ids: List[str] = []
            for fid in finding_ids:
                f_rels = store.get_relationships(entity_id=fid)
                for rel in f_rels:
                    if rel.rel_type == "FINDING_AFFECTS_ASSET":
                        asset_entity_ids.append(rel.target_id)
                    elif rel.rel_type == "violates_control":
                        ctrl = store.get_entity(rel.target_id)
                        if ctrl:
                            controls.append(ctrl.to_dict())

            # Step 3: Classify assets as containers, pods, namespaces
            for aid in set(asset_entity_ids):
                asset = store.get_entity(aid)
                if asset is None:
                    continue
                asset_dict = asset.to_dict()
                asset_type = asset.properties.get("asset_type", "").lower()

                if asset_type in ("container", "k8s_pod", "pod"):
                    containers.append(asset_dict)
                elif asset_type in ("k8s_namespace", "namespace"):
                    namespaces.append(asset_dict)
                else:
                    containers.append(asset_dict)  # generic — treat as compute asset

                # Extract namespace from container
                ns = asset.properties.get("namespace")
                if ns and ns not in [n.get("name") for n in namespaces]:
                    namespaces.append({"name": ns, "type": "k8s_namespace"})

                # Data classification hints from properties
                dc = asset.properties.get("data_classification") or asset.properties.get("data_type")
                if dc and dc not in data_classifications:
                    data_classifications.append(dc)

            # Step 4: Estimate dollar risk
            dollar_risk = self._estimate_dollar_risk(
                cve_id=cve_id,
                asset_count=len(set(asset_entity_ids)),
                control_count=len(controls),
                finding_count=len(finding_ids),
            )

            chain_summary = (
                f"CVE {cve_id} affects {len(finding_ids)} finding(s), "
                f"{len(set(asset_entity_ids))} asset(s) "
                f"({len(containers)} container(s), {len(namespaces)} namespace(s)), "
                f"{len(controls)} compliance control(s) at risk. "
                f"Estimated dollar risk: ${dollar_risk:,.0f}"
            )

            return CorrelationResult(
                query=cve_id,
                available=True,
                containers=containers,
                namespaces=namespaces,
                data_classifications=data_classifications,
                compliance_controls=controls,
                dollar_risk_estimate=dollar_risk,
                chain_summary=chain_summary,
            )

        except Exception as exc:
            logger.warning("CrossDomainCorrelator.correlate_cve failed", cve_id=cve_id, error=str(exc))
            return CorrelationResult(query=cve_id, available=False, chain_summary=str(exc))

    def correlate_finding(self, finding_id: str) -> Dict[str, Any]:
        """Cross-domain correlation for a specific finding entity.

        Args:
            finding_id: Finding entity ID (with or without 'finding_' prefix)

        Returns:
            Dict with full cross-domain context.
        """
        backbone = self._get_backbone()
        if not backbone._available or backbone._store is None:
            return {"available": False, "finding_id": finding_id}

        eid = finding_id if finding_id.startswith("finding_") else _entity_id("finding", finding_id)

        try:
            store = backbone._store
            finding = store.get_entity(eid)
            if finding is None:
                return {"available": True, "finding_id": finding_id, "error": "Not found"}

            rels = store.get_relationships(entity_id=eid)
            cves, assets, controls, scanners = [], [], [], []

            for rel in rels:
                other_id = rel.target_id if rel.source_id == eid else rel.source_id
                other = store.get_entity(other_id)
                if other is None:
                    continue
                if rel.rel_type == "FINDING_EXPLOITS_CVE":
                    cves.append(other.to_dict())
                elif rel.rel_type == "FINDING_AFFECTS_ASSET":
                    assets.append(other.to_dict())
                elif rel.rel_type == "violates_control":
                    controls.append(other.to_dict())
                elif rel.rel_type == "found_by_scanner":
                    scanners.append(other.to_dict())

            return {
                "available": True,
                "finding_id": finding_id,
                "finding": finding.to_dict(),
                "cves": cves,
                "affected_assets": assets,
                "violated_controls": controls,
                "detected_by": scanners,
                "cross_domain_summary": (
                    f"Finding '{finding.name}' detected by {len(scanners)} scanner(s), "
                    f"exploits {len(cves)} CVE(s), affects {len(assets)} asset(s), "
                    f"violates {len(controls)} control(s)"
                ),
            }
        except Exception as exc:
            logger.warning("CrossDomainCorrelator.correlate_finding failed", finding_id=finding_id, error=str(exc))
            return {"available": False, "finding_id": finding_id, "error": str(exc)}

    @staticmethod
    def _estimate_dollar_risk(
        cve_id: str,
        asset_count: int,
        control_count: int,
        finding_count: int,
    ) -> float:
        """Heuristic dollar risk estimate.

        Uses a simple model: base cost * asset multiplier * control gap penalty.
        In production this would call the risk scoring engine.

        Args:
            cve_id: CVE identifier for severity lookup
            asset_count: Number of affected assets
            control_count: Number of violated controls (0 = no mitigations)
            finding_count: Number of findings referencing this CVE

        Returns:
            Estimated dollar risk (USD).
        """
        # Base breach cost: $50K per affected asset (industry average ~$4.5M / 90 assets)
        base = asset_count * 50_000.0
        # Control gap multiplier: more gaps = higher risk
        gap_mult = 1.0 + (max(0, 5 - control_count) * 0.1)
        # Finding frequency: more findings = wider blast
        freq_mult = 1.0 + (min(finding_count, 10) * 0.05)
        return round(base * gap_mult * freq_mult, 2)


# ---------------------------------------------------------------------------
# Attack Path Enricher
# ---------------------------------------------------------------------------


class AttackPathEnricher:
    """Enrich ASM-discovered exposed assets with full security context.

    When ASM finds an exposed asset, auto-enrich with:
    - Known vulns from SCA
    - Misconfigs from CSPM
    - Runtime blocks from RASP
    - Compliance gaps from compliance engine

    Args:
        org_id: Tenant org ID.
        db_path: Optional DB path override.
    """

    def __init__(self, org_id: str = "default", db_path: Optional[str] = None) -> None:
        self.org_id = org_id
        self._db_path = db_path

    def _get_backbone(self):
        from core.trustgraph_backbone import TrustGraphBackbone
        return TrustGraphBackbone(db_path=self._db_path, org_id=self.org_id)

    def enrich_asset(self, asset_id: str) -> Dict[str, Any]:
        """Enrich an exposed asset with full cross-engine security context.

        Args:
            asset_id: Asset entity ID (with or without 'asset_' prefix)

        Returns:
            Dict with vulns, misconfigs, runtime_blocks, compliance_gaps, risk_score.
        """
        backbone = self._get_backbone()
        if not backbone._available or backbone._store is None:
            return {"available": False, "asset_id": asset_id}

        eid = asset_id if asset_id.startswith("asset_") else _entity_id("asset", asset_id)

        try:
            store = backbone._store
            asset = store.get_entity(eid)
            if asset is None:
                return {"available": True, "asset_id": asset_id, "error": "Asset not found in graph"}

            # Get all relationships for this asset
            rels = store.get_relationships(entity_id=eid)

            vulns: List[Dict[str, Any]] = []
            misconfigs: List[Dict[str, Any]] = []
            runtime_blocks: List[Dict[str, Any]] = []
            compliance_gaps: List[Dict[str, Any]] = []

            # Traverse inbound relationships (findings that affect this asset)
            for rel in rels:
                other_id = rel.source_id if rel.target_id == eid else rel.target_id
                if other_id == eid:
                    continue
                other = store.get_entity(other_id)
                if other is None:
                    continue

                if rel.rel_type == "FINDING_AFFECTS_ASSET" and rel.target_id == eid:
                    engine = other.properties.get("engine", "")
                    finding_dict = other.to_dict()
                    if engine in ("sca", "dependency", "sbom"):
                        vulns.append(finding_dict)
                    elif engine in ("cspm", "cwpp", "policy"):
                        misconfigs.append(finding_dict)
                    elif engine in ("rasp", "iast"):
                        runtime_blocks.append(finding_dict)
                    else:
                        vulns.append(finding_dict)
                elif rel.rel_type == "CONTROL_MITIGATES_FINDING":
                    # Find controls that don't cover this asset's findings
                    compliance_gaps.append(other.to_dict())

            # Aggregate risk score
            total_risk = sum(
                _SEVERITY_WEIGHT.get(f.get("properties", {}).get("severity", "unknown"), 1.0)
                for f in vulns + misconfigs
            )

            return {
                "available": True,
                "asset_id": asset_id,
                "asset": asset.to_dict(),
                "known_vulnerabilities": vulns,
                "misconfigurations": misconfigs,
                "runtime_blocks": runtime_blocks,
                "compliance_gaps": compliance_gaps,
                "finding_count": len(vulns) + len(misconfigs) + len(runtime_blocks),
                "aggregate_risk_score": round(total_risk, 2),
                "enrichment_summary": (
                    f"Asset '{asset.name}': {len(vulns)} vuln(s), "
                    f"{len(misconfigs)} misconfig(s), "
                    f"{len(runtime_blocks)} runtime block(s), "
                    f"{len(compliance_gaps)} compliance gap(s). "
                    f"Risk score: {round(total_risk, 2)}"
                ),
            }
        except Exception as exc:
            logger.warning("AttackPathEnricher.enrich_asset failed", asset_id=asset_id, error=str(exc))
            return {"available": False, "asset_id": asset_id, "error": str(exc)}

    def find_attack_paths_from_exposure(
        self,
        exposed_asset_id: str,
        target_asset_id: str,
    ) -> Dict[str, Any]:
        """Find attack paths from an exposed asset to a high-value target.

        Uses backbone GraphRAG BFS traversal and enriches each node.

        Args:
            exposed_asset_id: Entry point asset (internet-exposed)
            target_asset_id: High-value target asset

        Returns:
            Dict with paths enriched with vuln/config context at each hop.
        """
        from core.trustgraph_backbone import GraphRAGEnhanced
        graphrag = GraphRAGEnhanced(db_path=self._db_path, org_id=self.org_id)

        paths_result = graphrag.query_attack_path(
            source_id=exposed_asset_id,
            target_id=target_asset_id,
        )

        # Enrich each node in each path with security context
        enriched_paths = []
        for path in paths_result.get("paths", []):
            enriched_nodes = []
            for node in path:
                node_id = node.get("entity_id", "")
                if node_id.startswith("asset_"):
                    enrichment = self.enrich_asset(node_id)
                    node["enrichment"] = {
                        "finding_count": enrichment.get("finding_count", 0),
                        "aggregate_risk_score": enrichment.get("aggregate_risk_score", 0.0),
                    }
                enriched_nodes.append(node)
            enriched_paths.append(enriched_nodes)

        paths_result["paths"] = enriched_paths
        paths_result["enriched"] = True
        return paths_result


# ---------------------------------------------------------------------------
# Impact Analyzer
# ---------------------------------------------------------------------------


class ImpactAnalyzer:
    """Blast radius analysis for any entity in the graph.

    For any entity, calculate:
    - Upstream dependencies (what does this entity depend on)
    - Downstream consumers (what depends on this entity)
    - Data flows
    - Compliance impact
    - Dollar risk estimate

    Args:
        org_id: Tenant org ID.
        db_path: Optional DB path override.
    """

    def __init__(self, org_id: str = "default", db_path: Optional[str] = None) -> None:
        self.org_id = org_id
        self._db_path = db_path

    def _get_backbone(self):
        from core.trustgraph_backbone import TrustGraphBackbone
        return TrustGraphBackbone(db_path=self._db_path, org_id=self.org_id)

    def blast_radius(self, entity_id: str, depth: int = 2) -> ImpactResult:
        """Calculate blast radius for an entity.

        Traverses the graph to find all upstream and downstream entities,
        data flows, and compliance impacts.

        Args:
            entity_id: Entity to analyze.
            depth: Traversal depth (1-3).

        Returns:
            ImpactResult with full blast radius data.
        """
        from core.trustgraph_backbone import GraphRAGEnhanced
        graphrag = GraphRAGEnhanced(db_path=self._db_path, org_id=self.org_id)

        if not graphrag._available or graphrag._store is None:
            return ImpactResult(
                entity_id=entity_id,
                available=False,
                blast_radius=0,
            )

        try:
            store = graphrag._store
            depth = max(1, min(depth, 3))

            # Get all neighbors at specified depth
            neighbors = store.get_neighbors(entity_id=entity_id, depth=depth)
            all_rels = store.get_relationships(entity_id=entity_id)

            upstream: List[Dict[str, Any]] = []
            downstream: List[Dict[str, Any]] = []
            data_flows: List[Dict[str, Any]] = []
            compliance_impact: List[Dict[str, Any]] = []
            risk_weight = 0.0

            # Classify relationships as upstream vs downstream
            _upstream_rel_types = {
                "VENDOR_PROVIDES_COMPONENT",
                "caused_by_cwe",
                "FINDING_EXPLOITS_CVE",
                "found_by_scanner",
            }
            _downstream_rel_types = {
                "FINDING_AFFECTS_ASSET",
                "ACTOR_TARGETS_ASSET",
                "INCIDENT_IMPACTS_ASSET",
                "INCIDENT_INVOLVES_FINDING",
            }
            _compliance_rel_types = {
                "violates_control",
                "CONTROL_MITIGATES_FINDING",
                "part_of",
            }
            _dataflow_rel_types = {
                "ASSET_BELONGS_TO_ZONE",
                "COMPONENT_HAS_VULNERABILITY",
            }

            for rel in all_rels:
                other_id = rel.target_id if rel.source_id == entity_id else rel.source_id
                other = store.get_entity(other_id)
                if other is None:
                    continue
                other_dict = other.to_dict()

                if rel.rel_type in _upstream_rel_types:
                    upstream.append(other_dict)
                elif rel.rel_type in _downstream_rel_types:
                    downstream.append(other_dict)
                    # Accumulate risk from downstream affected entities
                    severity = other.properties.get("severity", "unknown")
                    risk_weight += _SEVERITY_WEIGHT.get(severity, 1.0)
                elif rel.rel_type in _compliance_rel_types:
                    compliance_impact.append(other_dict)
                elif rel.rel_type in _dataflow_rel_types:
                    data_flows.append(other_dict)

            blast = len(neighbors)
            summary = (
                f"Entity '{entity_id}' blast radius: {blast} neighbor(s) at depth {depth}. "
                f"Upstream: {len(upstream)}, downstream: {len(downstream)}, "
                f"compliance: {len(compliance_impact)}, risk_weight: {round(risk_weight, 2)}"
            )

            return ImpactResult(
                entity_id=entity_id,
                available=True,
                blast_radius=blast,
                upstream_dependencies=upstream,
                downstream_consumers=downstream,
                data_flows=data_flows,
                compliance_impact=compliance_impact,
                risk_weight=round(risk_weight, 2),
                summary=summary,
            )

        except Exception as exc:
            logger.warning("ImpactAnalyzer.blast_radius failed", entity_id=entity_id, error=str(exc))
            return ImpactResult(entity_id=entity_id, available=False, blast_radius=0, summary=str(exc))

    def structured_json(self, entity_id: str, depth: int = 2) -> Dict[str, Any]:
        """Return blast radius as structured JSON suitable for API responses.

        Args:
            entity_id: Entity to analyze.
            depth: Traversal depth (1-3).

        Returns:
            Structured JSON dict.
        """
        result = self.blast_radius(entity_id=entity_id, depth=depth)
        return result.model_dump()


# ---------------------------------------------------------------------------
# Batch Indexer
# ---------------------------------------------------------------------------


class BatchIndexer:
    """Bulk index findings with dedup, merge, and conflict resolution.

    Dedup: Same CVE from multiple scanners → single entity, multiple
           found_by_scanner relationships.
    Merge: Partial findings (e.g. severity from one scanner, CVSS from
           another) → merged into one entity using latest timestamp wins.
    Conflict: If timestamps match, higher severity wins.

    Args:
        org_id: Tenant org ID.
        db_path: Optional DB path override.
    """

    def __init__(self, org_id: str = "default", db_path: Optional[str] = None) -> None:
        self.org_id = org_id
        self._db_path = db_path
        self._indexer = UniversalFindingIndexer(org_id=org_id, db_path=db_path)

    def index_batch(self, findings: List[Dict[str, Any]]) -> BatchIndexResult:
        """Bulk index a list of findings with dedup and merge.

        Args:
            findings: List of raw finding dicts from any engine.

        Returns:
            BatchIndexResult with counts and entity_ids.
        """
        if not findings:
            return BatchIndexResult(
                total=0, indexed=0, deduplicated=0, merged=0, failed=0, entity_ids=[]
            )

        # Step 1: Normalize all findings
        normalized: List[Tuple[FindingInput, Dict[str, Any]]] = []
        errors: List[str] = []
        for raw in findings:
            try:
                fi = FindingInput.model_validate(raw)
                normalized.append((fi, raw))
            except Exception as exc:
                errors.append(str(exc))

        # Step 2: Group by dedup key (cve_id+asset_id for CVE findings, else title+engine)
        groups: Dict[str, List[Tuple[FindingInput, Dict[str, Any]]]] = {}
        for fi, raw in normalized:
            if fi.cve_id and fi.asset_id:
                key = f"{fi.cve_id}::{fi.asset_id}"
            elif fi.cve_id:
                key = fi.cve_id
            elif fi.id:
                key = fi.id
            else:
                key = f"{fi.engine}::{fi.title or fi.description or uuid.uuid4().hex[:8]}"
            groups.setdefault(key, []).append((fi, raw))

        deduplicated = sum(1 for g in groups.values() if len(g) > 1)
        merged = 0
        indexed = 0
        entity_ids: List[str] = []

        # Step 3: For each group, merge and index
        for key, group in groups.items():
            try:
                merged_raw = self._merge_group(group)
                entity_id = self._indexer.index(merged_raw)
                entity_ids.append(entity_id)
                indexed += 1
                if len(group) > 1:
                    merged += 1
            except Exception as exc:
                errors.append(f"key={key}: {exc}")

        return BatchIndexResult(
            total=len(findings),
            indexed=indexed,
            deduplicated=deduplicated,
            merged=merged,
            failed=len(errors),
            entity_ids=entity_ids,
            errors=errors,
        )

    @staticmethod
    def _merge_group(group: List[Tuple[FindingInput, Dict[str, Any]]]) -> Dict[str, Any]:
        """Merge a group of duplicate findings.

        Latest timestamp wins for metadata. Higher severity wins for
        severity field. Unions scanner names. Keeps first non-null for
        cvss/epss/cwe_id/description.

        Args:
            group: List of (FindingInput, raw_dict) tuples.

        Returns:
            Merged raw dict.
        """
        if len(group) == 1:
            return group[0][1]

        # Sort by timestamp descending (latest first)
        def _ts(fi: FindingInput) -> str:
            return fi.timestamp or "1970-01-01T00:00:00+00:00"

        sorted_group = sorted(group, key=lambda t: _ts(t[0]), reverse=True)
        primary_fi, primary_raw = sorted_group[0]

        # Merge fields
        merged: Dict[str, Any] = dict(primary_raw)

        # Highest severity wins
        max_sev = primary_fi.severity
        max_weight = _SEVERITY_WEIGHT.get(max_sev, 1.0)
        for fi, _ in sorted_group[1:]:
            w = _SEVERITY_WEIGHT.get(fi.severity, 1.0)
            if w > max_weight:
                max_sev = fi.severity
                max_weight = w
        merged["severity"] = max_sev

        # Union scanners
        scanners = list({fi.scanner or fi.engine for fi, _ in group if fi.scanner or fi.engine})
        merged["scanner"] = ", ".join(scanners)
        merged.setdefault("metadata", {})["merged_from"] = len(group)

        # First non-null for optional fields
        for field_name in ("cvss", "epss", "cwe_id", "description"):
            if not merged.get(field_name):
                for fi, _ in sorted_group:
                    val = getattr(fi, field_name, None)
                    if val is not None:
                        merged[field_name] = val
                        break

        return merged


# ---------------------------------------------------------------------------
# GraphRAG Queries — pre-built templates for dashboards
# ---------------------------------------------------------------------------


class GraphRAGQueries:
    """Pre-built GraphRAG query templates for dashboards.

    Each method returns structured JSON suitable for direct dashboard
    consumption. All queries degrade gracefully when TrustGraph is
    unavailable.

    Args:
        org_id: Tenant org ID.
        db_path: Optional DB path override.
    """

    TEMPLATES = _QUERY_TEMPLATES

    def __init__(self, org_id: str = "default", db_path: Optional[str] = None) -> None:
        self.org_id = org_id
        self._db_path = db_path

    def _get_backbone(self):
        from core.trustgraph_backbone import TrustGraphBackbone
        return TrustGraphBackbone(db_path=self._db_path, org_id=self.org_id)

    def run_template(self, template: str, **kwargs: Any) -> Dict[str, Any]:
        """Run a named query template.

        Args:
            template: One of the TEMPLATES set.
            **kwargs: Template-specific parameters.

        Returns:
            Structured query result dict.

        Raises:
            ValueError: If template name is not recognised.
        """
        if template not in self.TEMPLATES:
            raise ValueError(f"Unknown template '{template}'. Valid: {sorted(self.TEMPLATES)}")
        method = getattr(self, template)
        return method(**kwargs)

    def top_risks(self, limit: int = 20) -> Dict[str, Any]:
        """Return the top-N highest risk findings across all engines.

        Sorts by risk_weight (severity-derived) descending.

        Args:
            limit: Max findings to return.

        Returns:
            Dict with findings sorted by risk, aggregate stats.
        """
        backbone = self._get_backbone()
        if not backbone._available or backbone._store is None:
            return {"available": False, "template": "top_risks", "findings": []}

        try:
            store = backbone._store
            # Search Core 2 (SecurityCore) for all Finding entities
            all_findings = store.search(
                core_id=CORE_SECURITY,
                query_text="",
                filters={"org_id": self.org_id},
                limit=500,
            )

            finding_dicts = [
                e.to_dict() for e in all_findings
                if e.entity_type == "Finding"
            ]

            # Sort by risk_weight descending
            finding_dicts.sort(
                key=lambda f: _SEVERITY_WEIGHT.get(
                    f.get("properties", {}).get("severity", "unknown"), 1.0
                ),
                reverse=True,
            )

            top = finding_dicts[:limit]

            # Aggregate severity counts
            severity_counts: Dict[str, int] = {}
            for f in finding_dicts:
                sev = f.get("properties", {}).get("severity", "unknown")
                severity_counts[sev] = severity_counts.get(sev, 0) + 1

            return {
                "available": True,
                "template": "top_risks",
                "total_findings": len(finding_dicts),
                "findings": top,
                "severity_distribution": severity_counts,
                "generated_at": _now_iso(),
            }
        except Exception as exc:
            logger.warning("GraphRAGQueries.top_risks failed", error=str(exc))
            return {"available": False, "template": "top_risks", "error": str(exc), "findings": []}

    def exposure_chain(self, asset_id: Optional[str] = None, limit: int = 10) -> Dict[str, Any]:
        """Show the exposure chain: internet exposure → findings → compliance impact.

        If asset_id is provided, scope to that asset. Otherwise returns
        the top exposed assets.

        Args:
            asset_id: Optional asset to scope the chain.
            limit: Max assets to include when no specific asset given.

        Returns:
            Dict with exposure chain data.
        """
        backbone = self._get_backbone()
        if not backbone._available or backbone._store is None:
            return {"available": False, "template": "exposure_chain"}

        try:
            enricher = AttackPathEnricher(org_id=self.org_id, db_path=self._db_path)
            store = backbone._store

            if asset_id:
                enriched = enricher.enrich_asset(asset_id)
                return {
                    "available": True,
                    "template": "exposure_chain",
                    "asset_id": asset_id,
                    "chain": [enriched],
                    "generated_at": _now_iso(),
                }

            # Get all assets from Core 1
            assets = store.search(
                core_id=CORE_ASSET,
                query_text="",
                filters={"org_id": self.org_id},
                limit=limit * 2,
            )
            asset_entities = [e for e in assets if e.entity_type == "Asset"][:limit]

            chain = []
            for asset in asset_entities:
                enriched = enricher.enrich_asset(asset.entity_id)
                if enriched.get("finding_count", 0) > 0:
                    chain.append(enriched)

            # Sort by aggregate risk descending
            chain.sort(key=lambda x: x.get("aggregate_risk_score", 0.0), reverse=True)

            return {
                "available": True,
                "template": "exposure_chain",
                "asset_count": len(chain),
                "chain": chain,
                "generated_at": _now_iso(),
            }
        except Exception as exc:
            logger.warning("GraphRAGQueries.exposure_chain failed", error=str(exc))
            return {"available": False, "template": "exposure_chain", "error": str(exc)}

    def compliance_gaps(self, framework: Optional[str] = None, limit: int = 50) -> Dict[str, Any]:
        """Return compliance controls with open findings that violate them.

        Args:
            framework: Optional framework filter (e.g. "NIST", "SOC2", "PCI").
            limit: Max controls to return.

        Returns:
            Dict with gap analysis per framework.
        """
        backbone = self._get_backbone()
        if not backbone._available or backbone._store is None:
            return {"available": False, "template": "compliance_gaps"}

        try:
            store = backbone._store
            # Search without org_id filter: compliance controls are shared across
            # orgs and may have been seeded with a different org_id. Filter by
            # framework keyword only if provided; otherwise fetch all controls.
            controls = store.search(
                core_id=CORE_COMPLIANCE,
                query_text=framework or "",
                limit=limit * 3,
            )
            control_entities = [e for e in controls if e.entity_type == "Control"]

            gaps: List[Dict[str, Any]] = []
            for ctrl in control_entities:
                fw = ctrl.properties.get("framework", "unknown")
                if framework and fw.upper() != framework.upper():
                    continue
                rels = store.get_relationships(entity_id=ctrl.entity_id)
                violating_findings = [
                    r.source_id for r in rels
                    if r.rel_type == "violates_control"
                ]
                if violating_findings:
                    gaps.append({
                        "control": ctrl.to_dict(),
                        "violating_finding_count": len(violating_findings),
                        "violating_finding_ids": violating_findings[:10],
                    })

            # Sort by most violated controls first
            gaps.sort(key=lambda x: x["violating_finding_count"], reverse=True)

            # Framework summary
            by_framework: Dict[str, int] = {}
            for g in gaps:
                fw = g["control"].get("properties", {}).get("framework", "unknown")
                by_framework[fw] = by_framework.get(fw, 0) + 1

            return {
                "available": True,
                "template": "compliance_gaps",
                "framework_filter": framework,
                "total_gaps": len(gaps),
                "gaps": gaps,
                "by_framework": by_framework,
                "generated_at": _now_iso(),
            }
        except Exception as exc:
            logger.warning("GraphRAGQueries.compliance_gaps failed", error=str(exc))
            return {"available": False, "template": "compliance_gaps", "error": str(exc)}

    def attack_surface(self, limit: int = 30) -> Dict[str, Any]:
        """Return the full attack surface: all assets with open findings.

        Groups by asset type and exposure level.

        Args:
            limit: Max assets to include.

        Returns:
            Dict with attack surface grouped by type and exposure.
        """
        backbone = self._get_backbone()
        if not backbone._available or backbone._store is None:
            return {"available": False, "template": "attack_surface"}

        try:
            store = backbone._store
            assets = store.search(
                core_id=CORE_ASSET,
                query_text="",
                filters={"org_id": self.org_id},
                limit=limit * 2,
            )
            asset_entities = [e for e in assets if e.entity_type == "Asset"][:limit]

            surface: List[Dict[str, Any]] = []
            by_type: Dict[str, int] = {}
            by_exposure: Dict[str, int] = {}

            for asset in asset_entities:
                rels = store.get_relationships(entity_id=asset.entity_id)
                finding_count = sum(
                    1 for r in rels
                    if r.rel_type == "FINDING_AFFECTS_ASSET" and r.target_id == asset.entity_id
                )
                asset_type = asset.properties.get("asset_type", "unknown")
                exposure = asset.properties.get("exposure", "internal")

                by_type[asset_type] = by_type.get(asset_type, 0) + 1
                by_exposure[exposure] = by_exposure.get(exposure, 0) + 1

                if finding_count > 0:
                    surface.append({
                        "asset": asset.to_dict(),
                        "open_finding_count": finding_count,
                        "asset_type": asset_type,
                        "exposure": exposure,
                    })

            surface.sort(key=lambda x: x["open_finding_count"], reverse=True)

            return {
                "available": True,
                "template": "attack_surface",
                "total_assets": len(asset_entities),
                "assets_with_findings": len(surface),
                "surface": surface,
                "by_asset_type": by_type,
                "by_exposure": by_exposure,
                "generated_at": _now_iso(),
            }
        except Exception as exc:
            logger.warning("GraphRAGQueries.attack_surface failed", error=str(exc))
            return {"available": False, "template": "attack_surface", "error": str(exc)}

    def threat_landscape(self, limit: int = 20) -> Dict[str, Any]:
        """Return the threat landscape: active actors, campaigns, TTPs, targeted assets.

        Args:
            limit: Max threat actors to include.

        Returns:
            Dict with threat actor profiles, TTP coverage, targeted assets.
        """
        backbone = self._get_backbone()
        if not backbone._available or backbone._store is None:
            return {"available": False, "template": "threat_landscape"}

        try:
            store = backbone._store
            # ThreatActor entities live in Core 2 alongside many Finding/Scanner
            # entities. Use a large fetch limit so we don't miss actors when
            # findings (225+) occupy the first rows returned by LIKE fallback.
            actors = store.search(
                core_id=CORE_SECURITY,
                query_text="",
                filters={"org_id": self.org_id},
                limit=500,
            )
            actor_entities = [e for e in actors if e.entity_type == "ThreatActor"][:limit]

            landscape: List[Dict[str, Any]] = []
            all_ttps: List[str] = []
            targeted_asset_ids: List[str] = []

            for actor in actor_entities:
                rels = store.get_relationships(entity_id=actor.entity_id)
                ttps = []
                targets = []
                for rel in rels:
                    if rel.rel_type == "ACTOR_USES_TTP":
                        ttp = store.get_entity(rel.target_id)
                        if ttp:
                            ttps.append(ttp.to_dict())
                            all_ttps.append(ttp.name)
                    elif rel.rel_type == "ACTOR_TARGETS_ASSET":
                        target = store.get_entity(rel.target_id)
                        if target:
                            targets.append(target.to_dict())
                            targeted_asset_ids.append(rel.target_id)

                landscape.append({
                    "actor": actor.to_dict(),
                    "ttps": ttps,
                    "targeted_assets": targets,
                    "ttp_count": len(ttps),
                    "target_count": len(targets),
                })

            # TTP frequency
            ttp_freq: Dict[str, int] = {}
            for t in all_ttps:
                ttp_freq[t] = ttp_freq.get(t, 0) + 1

            return {
                "available": True,
                "template": "threat_landscape",
                "actor_count": len(landscape),
                "landscape": landscape,
                "top_ttps": sorted(ttp_freq.items(), key=lambda x: x[1], reverse=True)[:10],
                "unique_targeted_assets": len(set(targeted_asset_ids)),
                "generated_at": _now_iso(),
            }
        except Exception as exc:
            logger.warning("GraphRAGQueries.threat_landscape failed", error=str(exc))
            return {"available": False, "template": "threat_landscape", "error": str(exc)}


# ---------------------------------------------------------------------------
# Module-level singletons (lazy, per-call — matches backbone pattern)
# ---------------------------------------------------------------------------


def get_universal_indexer(org_id: str = "default", db_path: Optional[str] = None) -> UniversalFindingIndexer:
    """Return a UniversalFindingIndexer instance."""
    return UniversalFindingIndexer(org_id=org_id, db_path=db_path)


def get_cross_domain_correlator(org_id: str = "default", db_path: Optional[str] = None) -> CrossDomainCorrelator:
    """Return a CrossDomainCorrelator instance."""
    return CrossDomainCorrelator(org_id=org_id, db_path=db_path)


def get_impact_analyzer(org_id: str = "default", db_path: Optional[str] = None) -> ImpactAnalyzer:
    """Return an ImpactAnalyzer instance."""
    return ImpactAnalyzer(org_id=org_id, db_path=db_path)


def get_graphrag_queries(org_id: str = "default", db_path: Optional[str] = None) -> GraphRAGQueries:
    """Return a GraphRAGQueries instance."""
    return GraphRAGQueries(org_id=org_id, db_path=db_path)
