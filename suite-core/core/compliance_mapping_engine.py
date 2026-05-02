"""Compliance Mapping Engine — ALDECI.

Cross-framework control mapping: NIST CSF, ISO 27001, PCI-DSS, SOC 2, HIPAA,
GDPR, CIS Controls, NIST 800-53. Tracks evidence, implementation status, and
coverage statistics across all frameworks.

Compliance: NIST CSF ID.GV-4, ISO/IEC 27001 A.18.2, SOC 2 CC9.1
"""

from __future__ import annotations

import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


def _emit_event(event_type: str, payload) -> None:  # type: ignore[no-untyped-def]
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

_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "compliance_mapping.db"
)

_VALID_FRAMEWORKS = {
    # Legacy (pre-GAP-022)
    "nist_csf", "iso27001", "pci_dss", "soc2", "hipaa",
    "gdpr", "cis_controls", "nist_800_53",
    # GAP-022 framework library extension (100+ frameworks)
    "nist_csf_2_0", "nist_sp_800_53_r5", "iso_27001_2022", "iso_27002_2022",
    "cis_controls_v8_1", "cis_benchmark_aws", "cis_benchmark_azure",
    "cis_benchmark_gcp", "cis_benchmark_k8s", "cis_benchmark_linux",
    "cis_benchmark_windows", "cis_benchmark_docker",
    "pci_dss_v4_0", "hipaa_security_rule", "soc2_tsc", "soc2_type2",
    "gdpr_core", "ccpa_cpra", "fedramp_moderate", "fedramp_high",
    "ny_dfs_23_nycrr_500", "mitre_attack_enterprise", "mitre_d3fend",
    "owasp_asvs_4_0_3", "owasp_top10_2021", "owasp_api_top10_2023",
    "owasp_samm_v2", "csa_ccm_v4", "hitrust_csf_v11", "ffiec_cat",
    "cjis_policy", "swift_cscp", "naic_model_law",
    "nist_800_171_r2", "nist_800_172", "nist_800_161_r1", "nist_ssdf_1_1",
    "nist_ai_rmf_1_0", "nist_privacy_framework_1_0",
    "iso_27017", "iso_27018", "iso_27701", "iso_27799",
    "iso_42001", "iso_22301_bcms", "iso_31000_risk",
    "cmmc_2_0_level1", "cmmc_2_0_level2", "cmmc_2_0_level3",
    "fisma_moderate", "fisma_high", "cnssi_1253",
    "dora_digital_operational_resilience",
    "nis2_directive", "uk_cyber_essentials", "uk_cyber_essentials_plus",
    "essential_eight_australian",
    "pdpa_singapore", "pdpa_thailand", "pipl_china", "lgpd_brazil",
    "popia_south_africa", "pipeda_canada",
    "glba_financial", "sox_404", "sox_itgc",
    "fips_140_2", "fips_140_3", "fips_199", "fips_200", "fips_201",
    "itil_4_service_management", "cobit_2019",
    "csa_star_level1", "csa_star_level2",
    "aws_well_architected_security", "aws_foundational_security",
    "azure_security_benchmark_v3", "gcp_security_foundations",
    "oracle_cloud_security", "alibaba_cloud_security",
    "kubernetes_pci_benchmark", "kubernetes_hipaa_benchmark",
    "docker_cis_benchmark", "nist_container_security",
    "mitre_atlas_ai", "mitre_engage", "mitre_shield",
    "lockheed_kill_chain", "diamond_model",
    "unified_compliance_framework", "sci_regulation",
    "psd2_payment_services", "pci_pa_dss", "pci_p2pe",
    "hitech_act", "21_cfr_part_11_fda",
    "tcf_2_2_privacy", "ico_uk_gdpr",
    "stigs_dod", "disa_srg", "dod_8570",
    "itar_export", "ear_export",
    "iec_62443_ot", "nerc_cip", "tsa_pipeline_security",
    "fcc_tcpa", "ccma_code_of_conduct",
    "nist_1800_series", "nist_7298_glossary",
    "bsi_grundschutz", "anssi_reference", "cesg_uk",
    "jasa_japan", "krisa_korea",
    "ens_spain", "mehari_france",
    "pci_sscp", "pci_piin_mapping",
    "fedramp_li_saas", "statecamp_sled",
    "c5_germany", "agreed_code_of_conduct",
    "iso_29100_privacy", "iso_24760_identity",
    "nist_8286_erm", "oecd_ai_principles",
    "fair_risk_quantification", "octave_risk",
    "sig_shared_assessments", "ccpa_loyalty",
    "general", "custom", "internal",
}
_VALID_CONTROL_STATUSES = {
    "implemented", "partial", "not_implemented", "not_applicable",
}
_VALID_MAPPING_STRENGTHS = {"strong", "moderate", "weak"}


class ComplianceMappingEngine:
    """SQLite WAL-backed Compliance Mapping engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    """

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self.db_path = db_path
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
                CREATE TABLE IF NOT EXISTS compliance_controls (
                    id                   TEXT PRIMARY KEY,
                    org_id               TEXT NOT NULL,
                    control_id           TEXT NOT NULL,
                    framework            TEXT NOT NULL,
                    control_name         TEXT NOT NULL DEFAULT '',
                    description          TEXT NOT NULL DEFAULT '',
                    control_status       TEXT NOT NULL DEFAULT 'not_implemented',
                    implementation_notes TEXT NOT NULL DEFAULT '',
                    owner                TEXT NOT NULL DEFAULT '',
                    evidence_count       INTEGER NOT NULL DEFAULT 0,
                    last_reviewed        DATETIME,
                    created_at           DATETIME NOT NULL
                );

                CREATE TABLE IF NOT EXISTS control_mappings (
                    id               TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    source_control_id TEXT NOT NULL,
                    target_control_id TEXT NOT NULL,
                    source_framework TEXT NOT NULL,
                    target_framework TEXT NOT NULL,
                    mapping_strength TEXT NOT NULL DEFAULT 'moderate',
                    notes            TEXT NOT NULL DEFAULT '',
                    created_at       DATETIME NOT NULL
                );

                CREATE TABLE IF NOT EXISTS control_evidence (
                    id             TEXT PRIMARY KEY,
                    org_id         TEXT NOT NULL,
                    control_id     TEXT NOT NULL,
                    evidence_type  TEXT NOT NULL DEFAULT '',
                    description    TEXT NOT NULL DEFAULT '',
                    file_reference TEXT NOT NULL DEFAULT '',
                    collected_at   DATETIME,
                    expires_at     DATETIME,
                    collector      TEXT NOT NULL DEFAULT '',
                    created_at     DATETIME NOT NULL
                );
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    # ------------------------------------------------------------------
    # Controls
    # ------------------------------------------------------------------

    def add_control(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Add a compliance control.

        Required: control_id, control_name.
        framework defaults to 'nist_csf'; control_status defaults to 'not_implemented'.
        """
        control_id = (data.get("control_id") or "").strip()
        if not control_id:
            raise ValueError("control_id is required")

        control_name = (data.get("control_name") or "").strip()
        if not control_name:
            raise ValueError("control_name is required")

        framework = data.get("framework", "nist_csf")
        if framework not in _VALID_FRAMEWORKS:
            raise ValueError(
                f"Invalid framework '{framework}'. Valid: {sorted(_VALID_FRAMEWORKS)}"
            )

        control_status = data.get("control_status", "not_implemented")
        if control_status not in _VALID_CONTROL_STATUSES:
            raise ValueError(
                f"Invalid control_status '{control_status}'. "
                f"Valid: {sorted(_VALID_CONTROL_STATUSES)}"
            )

        now = self._now()
        rec = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "control_id": control_id,
            "framework": framework,
            "control_name": control_name,
            "description": data.get("description", ""),
            "control_status": control_status,
            "implementation_notes": data.get("implementation_notes", ""),
            "owner": data.get("owner", ""),
            "evidence_count": 0,
            "last_reviewed": data.get("last_reviewed"),
            "created_at": now,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO compliance_controls
                        (id, org_id, control_id, framework, control_name, description,
                         control_status, implementation_notes, owner, evidence_count,
                         last_reviewed, created_at)
                    VALUES
                        (:id, :org_id, :control_id, :framework, :control_name,
                         :description, :control_status, :implementation_notes,
                         :owner, :evidence_count, :last_reviewed, :created_at)
                    """,
                    rec,
                )
        if _get_tg_bus is not None:
            try:
                _get_tg_bus().emit("CONTROL_ASSESSED", {
                    "org_id": org_id,
                    "entity": "compliance_control",
                    "record_id": rec["id"],
                    "control_id": control_id,
                    "framework": framework,
                    "control_status": control_status,
                })
            except Exception:
                pass
        return rec

    def list_controls(
        self,
        org_id: str,
        framework: Optional[str] = None,
        control_status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List compliance controls with optional filters."""
        query = "SELECT * FROM compliance_controls WHERE org_id = ?"
        params: List[Any] = [org_id]

        if framework is not None:
            query += " AND framework = ?"
            params.append(framework)
        if control_status is not None:
            query += " AND control_status = ?"
            params.append(control_status)

        query += " ORDER BY framework, control_id"

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    def get_control(self, org_id: str, control_id_param: str) -> Optional[Dict[str, Any]]:
        """Get a single control by its primary-key id column."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM compliance_controls WHERE org_id = ? AND id = ?",
                (org_id, control_id_param),
            ).fetchone()
        return self._row(row) if row else None

    def list_controls_with_d3fend_fallback(
        self,
        org_id: str,
        framework: Optional[str] = None,
        control_status: Optional[str] = None,
        d3fend_db_path: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List org controls; when the org has zero MITRE D3FEND controls,
        project the imported D3FEND ontology (data/d3fend.db) as derived rows.

        Behaviour:
            - Org-registered controls always take precedence.
            - When ``framework`` is None or ``"mitre_d3fend"`` AND the org
              has no D3FEND rows in ``compliance_controls``, the imported
              ``d3fend_techniques`` table is read live and projected into
              the engine response shape (one dict per technique).
            - When ``framework`` is supplied as a different value, fallback
              is bypassed (the caller asked for a specific non-D3FEND
              framework and we honour that exactly).
            - When ``control_status`` is supplied and is not
              ``"not_implemented"``, fallback is bypassed (derived rows
              have no implementation state yet — only "not_implemented"
              matches; any other status filter would falsely exclude them).
            - When the side-DB does not exist or is empty, the response
              is identical to ``list_controls`` (no error).

        Each derived row carries provenance fields ``source="mitre-d3fend"``
        and ``source_iri=<original IRI>`` so the UI can badge it.
        """
        # Always honour org-registered rows first (filters intact).
        rows = self.list_controls(
            org_id, framework=framework, control_status=control_status
        )

        # Determine whether the caller would accept D3FEND-derived rows.
        wants_d3fend = framework is None or framework == "mitre_d3fend"
        if not wants_d3fend:
            return rows
        if control_status is not None and control_status != "not_implemented":
            return rows

        # If the caller didn't filter framework but the org already has
        # *any* D3FEND row, do not duplicate via fallback.
        org_has_d3fend = any(r.get("framework") == "mitre_d3fend" for r in rows)
        if org_has_d3fend:
            return rows

        # Read the side-DB live.
        try:
            from feeds.d3fend.importer import (
                get_db_path as _d3fend_db_path,
            )
            from feeds.d3fend.importer import (
                list_techniques_from_db,
            )
        except ImportError:
            return rows

        target_db = d3fend_db_path or _d3fend_db_path()
        techniques = list_techniques_from_db(db_path=target_db)
        if not techniques:
            return rows

        now = self._now()
        derived: List[Dict[str, Any]] = []
        for t in techniques:
            cid = t.get("control_id") or ""
            if not cid:
                continue
            derived.append({
                "id": f"d3fend:{cid}",
                "org_id": org_id,
                "control_id": cid,
                "framework": "mitre_d3fend",
                "control_name": (t.get("control_name") or cid)[:500],
                "description": t.get("description") or "",
                "control_status": "not_implemented",
                "implementation_notes": "",
                "owner": "",
                "evidence_count": 0,
                "last_reviewed": None,
                "created_at": t.get("imported_at") or now,
                # Provenance fields (derived rows only)
                "source": "mitre-d3fend",
                "source_iri": t.get("source_iri") or "",
                "top_category": t.get("top_category") or "",
                "parent_id": t.get("parent_id"),
                "attack_techniques": t.get("attack_techniques") or [],
            })

        # Append derived rows AFTER any org-registered non-D3FEND rows so
        # callers without a framework filter see the org's data first.
        return rows + derived

    def update_control_status(
        self,
        org_id: str,
        control_id_param: str,
        new_status: str,
        notes: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Update control_status (and optionally implementation_notes).

        Raises KeyError if control not found, ValueError for invalid status.
        """
        if new_status not in _VALID_CONTROL_STATUSES:
            raise ValueError(
                f"Invalid control_status '{new_status}'. "
                f"Valid: {sorted(_VALID_CONTROL_STATUSES)}"
            )

        now = self._now()
        with self._lock:
            with self._conn() as conn:
                existing = conn.execute(
                    "SELECT * FROM compliance_controls WHERE org_id = ? AND id = ?",
                    (org_id, control_id_param),
                ).fetchone()
                if existing is None:
                    raise KeyError(f"Control '{control_id_param}' not found")

                if notes is not None:
                    conn.execute(
                        """
                        UPDATE compliance_controls
                        SET control_status = ?, implementation_notes = ?, last_reviewed = ?
                        WHERE org_id = ? AND id = ?
                        """,
                        (new_status, notes, now, org_id, control_id_param),
                    )
                else:
                    conn.execute(
                        """
                        UPDATE compliance_controls
                        SET control_status = ?, last_reviewed = ?
                        WHERE org_id = ? AND id = ?
                        """,
                        (new_status, now, org_id, control_id_param),
                    )

                row = conn.execute(
                    "SELECT * FROM compliance_controls WHERE org_id = ? AND id = ?",
                    (org_id, control_id_param),
                ).fetchone()
        return self._row(row)

    # ------------------------------------------------------------------
    # Mappings
    # ------------------------------------------------------------------

    def add_mapping(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Add a cross-framework control mapping.

        Required: source_control_id, target_control_id, source_framework,
        target_framework, mapping_strength.
        """
        source_control_id = (data.get("source_control_id") or "").strip()
        if not source_control_id:
            raise ValueError("source_control_id is required")

        target_control_id = (data.get("target_control_id") or "").strip()
        if not target_control_id:
            raise ValueError("target_control_id is required")

        source_framework = data.get("source_framework", "")
        if source_framework not in _VALID_FRAMEWORKS:
            raise ValueError(
                f"Invalid source_framework '{source_framework}'. "
                f"Valid: {sorted(_VALID_FRAMEWORKS)}"
            )

        target_framework = data.get("target_framework", "")
        if target_framework not in _VALID_FRAMEWORKS:
            raise ValueError(
                f"Invalid target_framework '{target_framework}'. "
                f"Valid: {sorted(_VALID_FRAMEWORKS)}"
            )

        mapping_strength = data.get("mapping_strength", "")
        if mapping_strength not in _VALID_MAPPING_STRENGTHS:
            raise ValueError(
                f"Invalid mapping_strength '{mapping_strength}'. "
                f"Valid: {sorted(_VALID_MAPPING_STRENGTHS)}"
            )

        now = self._now()
        rec = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "source_control_id": source_control_id,
            "target_control_id": target_control_id,
            "source_framework": source_framework,
            "target_framework": target_framework,
            "mapping_strength": mapping_strength,
            "notes": data.get("notes", ""),
            "created_at": now,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO control_mappings
                        (id, org_id, source_control_id, target_control_id,
                         source_framework, target_framework, mapping_strength,
                         notes, created_at)
                    VALUES
                        (:id, :org_id, :source_control_id, :target_control_id,
                         :source_framework, :target_framework, :mapping_strength,
                         :notes, :created_at)
                    """,
                    rec,
                )
        return rec

    def list_mappings(
        self,
        org_id: str,
        source_framework: Optional[str] = None,
        target_framework: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List mappings with optional framework filters."""
        query = "SELECT * FROM control_mappings WHERE org_id = ?"
        params: List[Any] = [org_id]

        if source_framework is not None:
            query += " AND source_framework = ?"
            params.append(source_framework)
        if target_framework is not None:
            query += " AND target_framework = ?"
            params.append(target_framework)

        query += " ORDER BY source_framework, source_control_id"

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Evidence
    # ------------------------------------------------------------------

    def add_evidence(
        self, org_id: str, control_id_param: str, data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Add evidence for a control; increments evidence_count on the control.

        Required: evidence_type, description.
        control_id_param is the primary-key id of the compliance_controls row.
        """
        evidence_type = (data.get("evidence_type") or "").strip()
        if not evidence_type:
            raise ValueError("evidence_type is required")

        description = (data.get("description") or "").strip()
        if not description:
            raise ValueError("description is required")

        now = self._now()
        rec = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "control_id": control_id_param,
            "evidence_type": evidence_type,
            "description": description,
            "file_reference": data.get("file_reference", ""),
            "collected_at": data.get("collected_at", now),
            "expires_at": data.get("expires_at"),
            "collector": data.get("collector", ""),
            "created_at": now,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO control_evidence
                        (id, org_id, control_id, evidence_type, description,
                         file_reference, collected_at, expires_at, collector, created_at)
                    VALUES
                        (:id, :org_id, :control_id, :evidence_type, :description,
                         :file_reference, :collected_at, :expires_at, :collector,
                         :created_at)
                    """,
                    rec,
                )
                # Increment evidence_count on the parent control
                conn.execute(
                    """
                    UPDATE compliance_controls
                    SET evidence_count = evidence_count + 1
                    WHERE org_id = ? AND id = ?
                    """,
                    (org_id, control_id_param),
                )
        return rec

    def list_evidence(
        self,
        org_id: str,
        control_id_param: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List evidence records; optionally filter by control primary-key id."""
        query = "SELECT * FROM control_evidence WHERE org_id = ?"
        params: List[Any] = [org_id]

        if control_id_param is not None:
            query += " AND control_id = ?"
            params.append(control_id_param)

        query += " ORDER BY collected_at DESC"

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_control_context(self, org_id: str, control_id: str) -> Dict[str, Any]:
        """Query TrustGraph for cross-domain context about a compliance control.

        Returns related findings, evidence, and assets covered by this control.
        Degrades gracefully when TrustGraph is unavailable.
        """
        context: Dict[str, Any] = {
            "related_assets": [],
            "related_findings": [],
            "related_evidence": [],
            "trustgraph_available": False,
        }
        try:
            from trustgraph.knowledge_store import KnowledgeStore
            store = KnowledgeStore()
            context["trustgraph_available"] = True

            control = self.get_control(org_id, control_id)
            search_term = control.get("control_name", control_id) if control else control_id

            for core_id in (1, 2, 3):
                try:
                    results = store.search(core_id=core_id, query_text=search_term, limit=10)
                    for entity in results:
                        if entity.org_id not in ("default", org_id):
                            continue
                        entry = {"id": entity.entity_id, "name": entity.name, "type": entity.entity_type}
                        etype = entity.entity_type.lower()
                        if etype in ("asset", "service", "host"):
                            context["related_assets"].append(entry)
                        elif etype in ("finding", "vulnerability", "cve"):
                            context["related_findings"].append(entry)
                        elif etype in ("evidence", "document", "artifact"):
                            context["related_evidence"].append(entry)
                except Exception:
                    pass

            neighbors = store.get_neighbors(entity_id=control_id, depth=1)
            for n in neighbors:
                if n.org_id not in ("default", org_id):
                    continue
                entry = {"id": n.entity_id, "name": n.name, "type": n.entity_type}
                etype = n.entity_type.lower()
                if etype in ("asset", "service", "host"):
                    if entry not in context["related_assets"]:
                        context["related_assets"].append(entry)
                elif etype in ("finding", "vulnerability", "cve"):
                    if entry not in context["related_findings"]:
                        context["related_findings"].append(entry)
                elif etype in ("evidence", "document", "artifact"):
                    if entry not in context["related_evidence"]:
                        context["related_evidence"].append(entry)
        except Exception:
            pass
        return context

    def get_mapping_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregate mapping statistics for an org.

        Returns:
            total_controls, by_framework, by_status,
            implementation_rate (% of implemented + partial),
            total_mappings, controls_with_evidence.
        """
        with self._conn() as conn:
            total_controls: int = conn.execute(
                "SELECT COUNT(*) FROM compliance_controls WHERE org_id = ?",
                (org_id,),
            ).fetchone()[0]

            # Per-framework counts
            fw_rows = conn.execute(
                """
                SELECT framework, COUNT(*) as cnt
                FROM compliance_controls WHERE org_id = ?
                GROUP BY framework
                """,
                (org_id,),
            ).fetchall()
            by_framework = {r["framework"]: r["cnt"] for r in fw_rows}

            # Per-status counts
            st_rows = conn.execute(
                """
                SELECT control_status, COUNT(*) as cnt
                FROM compliance_controls WHERE org_id = ?
                GROUP BY control_status
                """,
                (org_id,),
            ).fetchall()
            by_status = {r["control_status"]: r["cnt"] for r in st_rows}

            # Implementation rate: (implemented + partial) / total
            implemented = by_status.get("implemented", 0) + by_status.get("partial", 0)
            implementation_rate = (
                round(implemented / total_controls * 100, 2)
                if total_controls > 0
                else 0.0
            )

            total_mappings: int = conn.execute(
                "SELECT COUNT(*) FROM control_mappings WHERE org_id = ?",
                (org_id,),
            ).fetchone()[0]

            controls_with_evidence: int = conn.execute(
                """
                SELECT COUNT(*) FROM compliance_controls
                WHERE org_id = ? AND evidence_count > 0
                """,
                (org_id,),
            ).fetchone()[0]

        return {
            "total_controls": total_controls,
            "by_framework": by_framework,
            "by_status": by_status,
            "implementation_rate": implementation_rate,
            "total_mappings": total_mappings,
            "controls_with_evidence": controls_with_evidence,
        }

    # ------------------------------------------------------------------
    # GAP-022 — Framework Library Bulk Seed
    # ------------------------------------------------------------------

    def seed_framework_library(
        self,
        org_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Bulk-seed a library of 100+ compliance frameworks.

        Idempotent: re-running will NOT duplicate rows — we skip any
        ``(org_id, framework, control_id)`` triple already present.

        Returns a summary dict: ``{frameworks: int, controls_inserted: int,
        controls_skipped: int, total_controls_in_org: int}``.
        """
        target_org = org_id or "default"
        entries = _framework_library_catalog()

        inserted = 0
        skipped = 0
        now = self._now()
        frameworks_seen = set()

        with self._lock:
            with self._conn() as conn:
                # Preload existing (framework, control_id) set for this org
                existing_rows = conn.execute(
                    "SELECT framework, control_id FROM compliance_controls WHERE org_id = ?",
                    (target_org,),
                ).fetchall()
                existing: set = {(r["framework"], r["control_id"]) for r in existing_rows}

                for e in entries:
                    fw = e["framework"]
                    cid = e["control_id"]
                    frameworks_seen.add(fw)
                    if (fw, cid) in existing:
                        skipped += 1
                        continue
                    rec_id = str(uuid.uuid4())
                    conn.execute(
                        """
                        INSERT INTO compliance_controls
                            (id, org_id, control_id, framework, control_name, description,
                             control_status, implementation_notes, owner, evidence_count,
                             last_reviewed, created_at)
                        VALUES
                            (?, ?, ?, ?, ?, ?, 'not_implemented', '', '', 0, NULL, ?)
                        """,
                        (
                            rec_id,
                            target_org,
                            cid,
                            fw,
                            e.get("control_name", cid),
                            e.get("description", ""),
                            now,
                        ),
                    )
                    existing.add((fw, cid))
                    inserted += 1

                total = conn.execute(
                    "SELECT COUNT(*) FROM compliance_controls WHERE org_id = ?",
                    (target_org,),
                ).fetchone()[0]

        return {
            "frameworks": len(frameworks_seen),
            "controls_inserted": inserted,
            "controls_skipped": skipped,
            "total_controls_in_org": total,
            "org_id": target_org,
        }


# ----------------------------------------------------------------------
# GAP-022 — Framework Library Catalog (module-level helpers, 100+ frameworks)
# ----------------------------------------------------------------------


def _framework_library_catalog() -> List[Dict[str, str]]:
    """Return the full 100+ framework library catalog.

    Each entry is a dict with keys:
        framework, control_id, control_name, description

    This catalog is intentionally content-heavy. It is assembled from
    per-framework helper functions to keep any single function under
    500 lines.
    """
    out: List[Dict[str, str]] = []
    out.extend(_fw_nist_csf_2_0())
    out.extend(_fw_nist_sp_800_53_r5())
    out.extend(_fw_iso_27001_2022())
    out.extend(_fw_iso_27002_2022())
    out.extend(_fw_cis_controls_v8_1())
    out.extend(_fw_cis_benchmarks())
    out.extend(_fw_pci_dss_v4_0())
    out.extend(_fw_hipaa_security_rule())
    out.extend(_fw_soc2_tsc())
    out.extend(_fw_gdpr_core())
    out.extend(_fw_ccpa_cpra())
    out.extend(_fw_fedramp())
    out.extend(_fw_ny_dfs())
    out.extend(_fw_mitre_attack_enterprise())
    out.extend(_fw_mitre_d3fend())
    out.extend(_fw_owasp_asvs())
    out.extend(_fw_csa_ccm())
    out.extend(_fw_hitrust())
    out.extend(_fw_ffiec_cat())
    out.extend(_fw_cjis())
    out.extend(_fw_swift_cscp())
    out.extend(_fw_naic_model_law())
    out.extend(_fw_misc_library())
    return out


def _fw_nist_csf_2_0() -> List[Dict[str, str]]:
    """NIST CSF 2.0 — 6 functions × 22 categories × subcategory sample (108 total)."""
    rows: List[Dict[str, str]] = []
    # Function: GV (Govern) — new in 2.0
    gv = [
        ("GV.OC-01", "Organizational mission is understood and security-relevant context is communicated"),
        ("GV.OC-02", "Internal and external stakeholders are identified"),
        ("GV.OC-03", "Legal, regulatory, contractual requirements are understood"),
        ("GV.OC-04", "Critical objectives, capabilities, services are understood"),
        ("GV.OC-05", "Outcomes, capabilities, services communicated to stakeholders"),
        ("GV.RM-01", "Risk management objectives are established"),
        ("GV.RM-02", "Risk appetite and tolerance are expressed"),
        ("GV.RM-03", "Cybersecurity risk is integrated with enterprise risk"),
        ("GV.RM-04", "Strategic direction for risk is communicated"),
        ("GV.RM-05", "Third-party risk is integrated"),
        ("GV.RM-06", "Risk methodology is documented"),
        ("GV.RM-07", "Strategic opportunities are characterized"),
        ("GV.RR-01", "Organizational leadership demonstrates accountability"),
        ("GV.RR-02", "Roles, responsibilities, authorities are established"),
        ("GV.RR-03", "Adequate resources are allocated"),
        ("GV.RR-04", "Cybersecurity is included in HR practices"),
        ("GV.PO-01", "Policy is established and communicated"),
        ("GV.PO-02", "Policy is reviewed and updated"),
        ("GV.OV-01", "Cybersecurity strategy is reviewed"),
        ("GV.OV-02", "Strategy is adjusted for changing requirements"),
        ("GV.OV-03", "Cybersecurity performance is evaluated"),
        ("GV.SC-01", "Supply chain risk management program is established"),
        ("GV.SC-02", "Cybersecurity roles for suppliers are established"),
        ("GV.SC-03", "Supply chain risk is integrated with enterprise risk"),
        ("GV.SC-04", "Suppliers are known and prioritized"),
        ("GV.SC-05", "Contracts address cybersecurity requirements"),
        ("GV.SC-06", "Due diligence is performed on suppliers"),
        ("GV.SC-07", "Supplier risks are monitored"),
        ("GV.SC-08", "Suppliers are included in incident response"),
        ("GV.SC-09", "Supply chain risk is managed across partnership lifecycle"),
        ("GV.SC-10", "Supply chain plans include end-of-life activities"),
    ]
    for cid, name in gv:
        rows.append({"framework": "nist_csf_2_0", "control_id": cid, "control_name": name, "description": "NIST CSF 2.0 Govern"})

    # Function: ID (Identify)
    idf = [
        ("ID.AM-01", "Inventory of physical devices is maintained"),
        ("ID.AM-02", "Inventory of software platforms is maintained"),
        ("ID.AM-03", "Organizational communication and data flows are mapped"),
        ("ID.AM-04", "Services from external providers are catalogued"),
        ("ID.AM-05", "Resources are prioritized based on classification"),
        ("ID.AM-07", "Inventory of data and metadata is maintained"),
        ("ID.AM-08", "Systems, hardware, software, services are managed across lifecycle"),
        ("ID.RA-01", "Vulnerabilities in assets are identified, validated, recorded"),
        ("ID.RA-02", "Cyber threat intelligence is received"),
        ("ID.RA-03", "Internal and external threats are identified"),
        ("ID.RA-04", "Potential impacts and likelihoods are identified"),
        ("ID.RA-05", "Threats, vulnerabilities, impacts used to understand risk"),
        ("ID.RA-06", "Risk responses are chosen, prioritized, planned, tracked"),
        ("ID.RA-07", "Changes and exceptions are managed, assessed for risk"),
        ("ID.RA-08", "Processes to receive/act on vulnerability disclosures are established"),
        ("ID.RA-09", "Authenticity and integrity of hardware/software is assessed"),
        ("ID.RA-10", "Critical suppliers are assessed"),
        ("ID.IM-01", "Improvements are identified from evaluations"),
        ("ID.IM-02", "Improvements are identified from tests and exercises"),
        ("ID.IM-03", "Improvements are identified from operations execution"),
        ("ID.IM-04", "Incident response plans are established, communicated, maintained"),
    ]
    for cid, name in idf:
        rows.append({"framework": "nist_csf_2_0", "control_id": cid, "control_name": name, "description": "NIST CSF 2.0 Identify"})

    # Function: PR (Protect)
    pr = [
        ("PR.AA-01", "Identities and credentials are managed"),
        ("PR.AA-02", "Identities are proofed, bound to credentials, asserted"),
        ("PR.AA-03", "Users, services, hardware are authenticated"),
        ("PR.AA-04", "Identity assertions are protected, conveyed, verified"),
        ("PR.AA-05", "Access permissions/entitlements/authorizations enforce least privilege"),
        ("PR.AA-06", "Physical access is managed, monitored, enforced"),
        ("PR.AT-01", "Personnel receive training on cybersecurity"),
        ("PR.AT-02", "Personnel in specialized roles receive training"),
        ("PR.DS-01", "Confidentiality, integrity, availability of data-at-rest"),
        ("PR.DS-02", "Confidentiality/integrity/availability of data-in-transit"),
        ("PR.DS-10", "Confidentiality/integrity/availability of data-in-use"),
        ("PR.DS-11", "Backups of data are created, protected, maintained, tested"),
        ("PR.PS-01", "Configuration management practices are established"),
        ("PR.PS-02", "Software is maintained, replaced, removed per risk"),
        ("PR.PS-03", "Hardware is maintained, replaced, removed per risk"),
        ("PR.PS-04", "Log records are generated, available for monitoring"),
        ("PR.PS-05", "Installation/execution of unauthorized software is prevented"),
        ("PR.PS-06", "Secure software development practices are integrated"),
        ("PR.IR-01", "Networks and environments are protected"),
        ("PR.IR-02", "Technology assets are protected from environmental threats"),
        ("PR.IR-03", "Mechanisms are implemented to achieve resilience"),
        ("PR.IR-04", "Adequate capacity is maintained"),
    ]
    for cid, name in pr:
        rows.append({"framework": "nist_csf_2_0", "control_id": cid, "control_name": name, "description": "NIST CSF 2.0 Protect"})

    # Function: DE (Detect)
    de = [
        ("DE.CM-01", "Networks and services are monitored for anomalies"),
        ("DE.CM-02", "Physical environment is monitored"),
        ("DE.CM-03", "Personnel activity is monitored to find anomalies"),
        ("DE.CM-06", "External service provider activity is monitored"),
        ("DE.CM-09", "Computing hardware/software is monitored"),
        ("DE.AE-02", "Potentially adverse events are analyzed"),
        ("DE.AE-03", "Information is correlated from multiple sources"),
        ("DE.AE-04", "Estimated impact of events is understood"),
        ("DE.AE-06", "Information on adverse events is provided to staff"),
        ("DE.AE-07", "Cyber threat intelligence is integrated"),
        ("DE.AE-08", "Incidents are declared when criteria are met"),
    ]
    for cid, name in de:
        rows.append({"framework": "nist_csf_2_0", "control_id": cid, "control_name": name, "description": "NIST CSF 2.0 Detect"})

    # Function: RS (Respond)
    rs = [
        ("RS.MA-01", "Incident response plan is executed"),
        ("RS.MA-02", "Incident reports are triaged, validated"),
        ("RS.MA-03", "Incidents are categorized, prioritized"),
        ("RS.MA-04", "Incidents are escalated, elevated per need"),
        ("RS.MA-05", "Criteria for starting incident recovery are applied"),
        ("RS.AN-03", "Analysis is performed to determine what happened"),
        ("RS.AN-06", "Investigation actions are performed, preserved"),
        ("RS.AN-07", "Incident data and metadata are collected, integrity preserved"),
        ("RS.AN-08", "Incident magnitude is estimated, validated"),
        ("RS.CO-02", "Internal and external stakeholders are notified"),
        ("RS.CO-03", "Information is shared with designated stakeholders"),
        ("RS.MI-01", "Incidents are contained"),
        ("RS.MI-02", "Incidents are eradicated"),
    ]
    for cid, name in rs:
        rows.append({"framework": "nist_csf_2_0", "control_id": cid, "control_name": name, "description": "NIST CSF 2.0 Respond"})

    # Function: RC (Recover)
    rc = [
        ("RC.RP-01", "Recovery portion of IR plan is executed"),
        ("RC.RP-02", "Recovery actions are selected, scoped, prioritized"),
        ("RC.RP-03", "Integrity of backups and restore assets is verified"),
        ("RC.RP-04", "Critical mission functions and cybersecurity risk management are considered"),
        ("RC.RP-05", "Integrity of restored assets is verified, systems/services restored, normal operating status confirmed"),
        ("RC.RP-06", "End of incident recovery is declared"),
        ("RC.CO-03", "Recovery activities are communicated to stakeholders"),
        ("RC.CO-04", "Public updates on incident recovery are shared using approved methods/messaging"),
    ]
    for cid, name in rc:
        rows.append({"framework": "nist_csf_2_0", "control_id": cid, "control_name": name, "description": "NIST CSF 2.0 Recover"})

    return rows


def _fw_nist_sp_800_53_r5() -> List[Dict[str, str]]:
    """NIST SP 800-53 Rev 5 — 20 control families with representative baseline controls."""
    families = [
        ("AC", "Access Control"),
        ("AT", "Awareness and Training"),
        ("AU", "Audit and Accountability"),
        ("CA", "Assessment, Authorization, and Monitoring"),
        ("CM", "Configuration Management"),
        ("CP", "Contingency Planning"),
        ("IA", "Identification and Authentication"),
        ("IR", "Incident Response"),
        ("MA", "Maintenance"),
        ("MP", "Media Protection"),
        ("PE", "Physical and Environmental Protection"),
        ("PL", "Planning"),
        ("PM", "Program Management"),
        ("PS", "Personnel Security"),
        ("PT", "Personally Identifiable Information Processing and Transparency"),
        ("RA", "Risk Assessment"),
        ("SA", "System and Services Acquisition"),
        ("SC", "System and Communications Protection"),
        ("SI", "System and Information Integrity"),
        ("SR", "Supply Chain Risk Management"),
    ]
    rows: List[Dict[str, str]] = []
    # 6 baseline controls per family = 120 entries
    for fam, label in families:
        for n in range(1, 7):
            cid = f"{fam}-{n}"
            rows.append({
                "framework": "nist_sp_800_53_r5",
                "control_id": cid,
                "control_name": f"{label} — baseline control {cid}",
                "description": f"NIST SP 800-53 Rev 5 {label} baseline",
            })
    return rows


def _fw_iso_27001_2022() -> List[Dict[str, str]]:
    """ISO/IEC 27001:2022 — Annex A controls (93 controls across 4 themes)."""
    rows: List[Dict[str, str]] = []
    organizational = [
        ("5.1", "Policies for information security"),
        ("5.2", "Information security roles and responsibilities"),
        ("5.3", "Segregation of duties"),
        ("5.4", "Management responsibilities"),
        ("5.5", "Contact with authorities"),
        ("5.6", "Contact with special interest groups"),
        ("5.7", "Threat intelligence"),
        ("5.8", "Information security in project management"),
        ("5.9", "Inventory of information and other associated assets"),
        ("5.10", "Acceptable use of information and other associated assets"),
        ("5.11", "Return of assets"),
        ("5.12", "Classification of information"),
        ("5.13", "Labelling of information"),
        ("5.14", "Information transfer"),
        ("5.15", "Access control"),
        ("5.16", "Identity management"),
        ("5.17", "Authentication information"),
        ("5.18", "Access rights"),
        ("5.19", "Information security in supplier relationships"),
        ("5.20", "Addressing information security within supplier agreements"),
        ("5.21", "Managing information security in the ICT supply chain"),
        ("5.22", "Monitoring, review, and change management of supplier services"),
        ("5.23", "Information security for use of cloud services"),
        ("5.24", "Information security incident management planning and preparation"),
        ("5.25", "Assessment and decision on information security events"),
        ("5.26", "Response to information security incidents"),
        ("5.27", "Learning from information security incidents"),
        ("5.28", "Collection of evidence"),
        ("5.29", "Information security during disruption"),
        ("5.30", "ICT readiness for business continuity"),
        ("5.31", "Legal, statutory, regulatory, and contractual requirements"),
        ("5.32", "Intellectual property rights"),
        ("5.33", "Protection of records"),
        ("5.34", "Privacy and protection of PII"),
        ("5.35", "Independent review of information security"),
        ("5.36", "Compliance with policies, rules and standards"),
        ("5.37", "Documented operating procedures"),
    ]
    people = [
        ("6.1", "Screening"),
        ("6.2", "Terms and conditions of employment"),
        ("6.3", "Information security awareness, education and training"),
        ("6.4", "Disciplinary process"),
        ("6.5", "Responsibilities after termination or change of employment"),
        ("6.6", "Confidentiality or non-disclosure agreements"),
        ("6.7", "Remote working"),
        ("6.8", "Information security event reporting"),
    ]
    physical = [
        ("7.1", "Physical security perimeters"),
        ("7.2", "Physical entry"),
        ("7.3", "Securing offices, rooms and facilities"),
        ("7.4", "Physical security monitoring"),
        ("7.5", "Protecting against physical and environmental threats"),
        ("7.6", "Working in secure areas"),
        ("7.7", "Clear desk and clear screen"),
        ("7.8", "Equipment siting and protection"),
        ("7.9", "Security of assets off-premises"),
        ("7.10", "Storage media"),
        ("7.11", "Supporting utilities"),
        ("7.12", "Cabling security"),
        ("7.13", "Equipment maintenance"),
        ("7.14", "Secure disposal or re-use of equipment"),
    ]
    technological = [
        ("8.1", "User end-point devices"),
        ("8.2", "Privileged access rights"),
        ("8.3", "Information access restriction"),
        ("8.4", "Access to source code"),
        ("8.5", "Secure authentication"),
        ("8.6", "Capacity management"),
        ("8.7", "Protection against malware"),
        ("8.8", "Management of technical vulnerabilities"),
        ("8.9", "Configuration management"),
        ("8.10", "Information deletion"),
        ("8.11", "Data masking"),
        ("8.12", "Data leakage prevention"),
        ("8.13", "Information backup"),
        ("8.14", "Redundancy of information processing facilities"),
        ("8.15", "Logging"),
        ("8.16", "Monitoring activities"),
        ("8.17", "Clock synchronization"),
        ("8.18", "Use of privileged utility programs"),
        ("8.19", "Installation of software on operational systems"),
        ("8.20", "Networks security"),
        ("8.21", "Security of network services"),
        ("8.22", "Segregation of networks"),
        ("8.23", "Web filtering"),
        ("8.24", "Use of cryptography"),
        ("8.25", "Secure development lifecycle"),
        ("8.26", "Application security requirements"),
        ("8.27", "Secure system architecture and engineering principles"),
        ("8.28", "Secure coding"),
        ("8.29", "Security testing in development and acceptance"),
        ("8.30", "Outsourced development"),
        ("8.31", "Separation of development, test and production environments"),
        ("8.32", "Change management"),
        ("8.33", "Test information"),
        ("8.34", "Protection of information systems during audit testing"),
    ]
    for cid, name in organizational:
        rows.append({"framework": "iso_27001_2022", "control_id": f"A.{cid}", "control_name": name, "description": "ISO/IEC 27001:2022 Organizational"})
    for cid, name in people:
        rows.append({"framework": "iso_27001_2022", "control_id": f"A.{cid}", "control_name": name, "description": "ISO/IEC 27001:2022 People"})
    for cid, name in physical:
        rows.append({"framework": "iso_27001_2022", "control_id": f"A.{cid}", "control_name": name, "description": "ISO/IEC 27001:2022 Physical"})
    for cid, name in technological:
        rows.append({"framework": "iso_27001_2022", "control_id": f"A.{cid}", "control_name": name, "description": "ISO/IEC 27001:2022 Technological"})
    return rows


def _fw_iso_27002_2022() -> List[Dict[str, str]]:
    """ISO/IEC 27002:2022 — 14 domains (aligned with 27001 guidance)."""
    domains = [
        ("ISO27002.1", "Information security policies"),
        ("ISO27002.2", "Organization of information security"),
        ("ISO27002.3", "Human resource security"),
        ("ISO27002.4", "Asset management"),
        ("ISO27002.5", "Access control"),
        ("ISO27002.6", "Cryptography"),
        ("ISO27002.7", "Physical and environmental security"),
        ("ISO27002.8", "Operations security"),
        ("ISO27002.9", "Communications security"),
        ("ISO27002.10", "System acquisition, development and maintenance"),
        ("ISO27002.11", "Supplier relationships"),
        ("ISO27002.12", "Information security incident management"),
        ("ISO27002.13", "Information security aspects of business continuity"),
        ("ISO27002.14", "Compliance"),
    ]
    return [{"framework": "iso_27002_2022", "control_id": c, "control_name": n, "description": "ISO/IEC 27002:2022 domain"} for c, n in domains]


def _fw_cis_controls_v8_1() -> List[Dict[str, str]]:
    """CIS Controls v8.1 — 18 critical controls."""
    controls = [
        ("CIS-1", "Inventory and Control of Enterprise Assets"),
        ("CIS-2", "Inventory and Control of Software Assets"),
        ("CIS-3", "Data Protection"),
        ("CIS-4", "Secure Configuration of Enterprise Assets and Software"),
        ("CIS-5", "Account Management"),
        ("CIS-6", "Access Control Management"),
        ("CIS-7", "Continuous Vulnerability Management"),
        ("CIS-8", "Audit Log Management"),
        ("CIS-9", "Email and Web Browser Protections"),
        ("CIS-10", "Malware Defenses"),
        ("CIS-11", "Data Recovery"),
        ("CIS-12", "Network Infrastructure Management"),
        ("CIS-13", "Network Monitoring and Defense"),
        ("CIS-14", "Security Awareness and Skills Training"),
        ("CIS-15", "Service Provider Management"),
        ("CIS-16", "Application Software Security"),
        ("CIS-17", "Incident Response Management"),
        ("CIS-18", "Penetration Testing"),
    ]
    return [{"framework": "cis_controls_v8_1", "control_id": c, "control_name": n, "description": "CIS Controls v8.1"} for c, n in controls]


def _fw_cis_benchmarks() -> List[Dict[str, str]]:
    """CIS Benchmarks — AWS L1/L2, Azure L1/L2, GCP L1/L2, K8s L1/L2."""
    rows: List[Dict[str, str]] = []
    for cloud, cloud_key in [("aws", "cis_benchmark_aws"), ("azure", "cis_benchmark_azure"),
                             ("gcp", "cis_benchmark_gcp"), ("k8s", "cis_benchmark_k8s"),
                             ("linux", "cis_benchmark_linux"), ("windows", "cis_benchmark_windows"),
                             ("docker", "cis_benchmark_docker")]:
        for lvl in (1, 2):
            for n in range(1, 11):
                cid = f"CIS-{cloud.upper()}-L{lvl}-{n:02d}"
                rows.append({
                    "framework": cloud_key,
                    "control_id": cid,
                    "control_name": f"CIS {cloud.upper()} Benchmark Level {lvl} — Rule {n}",
                    "description": f"Level {lvl} hardening for {cloud.upper()}",
                })
    return rows


def _fw_pci_dss_v4_0() -> List[Dict[str, str]]:
    """PCI-DSS v4.0 — 12 requirements."""
    reqs = [
        ("PCI-1", "Install and maintain network security controls"),
        ("PCI-2", "Apply secure configurations to all system components"),
        ("PCI-3", "Protect stored account data"),
        ("PCI-4", "Protect cardholder data with strong cryptography during transmission"),
        ("PCI-5", "Protect all systems and networks from malicious software"),
        ("PCI-6", "Develop and maintain secure systems and software"),
        ("PCI-7", "Restrict access to system components and cardholder data by business need-to-know"),
        ("PCI-8", "Identify users and authenticate access to system components"),
        ("PCI-9", "Restrict physical access to cardholder data"),
        ("PCI-10", "Log and monitor all access to system components and cardholder data"),
        ("PCI-11", "Test security of systems and networks regularly"),
        ("PCI-12", "Support information security with organizational policies and programs"),
    ]
    return [{"framework": "pci_dss_v4_0", "control_id": c, "control_name": n, "description": "PCI-DSS v4.0 Requirement"} for c, n in reqs]


def _fw_hipaa_security_rule() -> List[Dict[str, str]]:
    """HIPAA Security Rule — 3 safeguard categories with standards."""
    admin = [
        ("HIPAA-AS-1", "Security management process"),
        ("HIPAA-AS-2", "Assigned security responsibility"),
        ("HIPAA-AS-3", "Workforce security"),
        ("HIPAA-AS-4", "Information access management"),
        ("HIPAA-AS-5", "Security awareness and training"),
        ("HIPAA-AS-6", "Security incident procedures"),
        ("HIPAA-AS-7", "Contingency plan"),
        ("HIPAA-AS-8", "Evaluation"),
        ("HIPAA-AS-9", "Business associate contracts"),
    ]
    physical = [
        ("HIPAA-PS-1", "Facility access controls"),
        ("HIPAA-PS-2", "Workstation use"),
        ("HIPAA-PS-3", "Workstation security"),
        ("HIPAA-PS-4", "Device and media controls"),
    ]
    tech = [
        ("HIPAA-TS-1", "Access control"),
        ("HIPAA-TS-2", "Audit controls"),
        ("HIPAA-TS-3", "Integrity"),
        ("HIPAA-TS-4", "Person or entity authentication"),
        ("HIPAA-TS-5", "Transmission security"),
    ]
    rows = []
    for group, data, desc in [("Admin", admin, "Administrative Safeguard"), ("Physical", physical, "Physical Safeguard"), ("Technical", tech, "Technical Safeguard")]:
        for cid, name in data:
            rows.append({"framework": "hipaa_security_rule", "control_id": cid, "control_name": name, "description": f"HIPAA {desc}"})
    return rows


def _fw_soc2_tsc() -> List[Dict[str, str]]:
    """SOC 2 Trust Services Criteria — 5 principles with core criteria."""
    criteria = [
        ("CC1.1", "COSO Principle 1 — commitment to integrity and ethical values"),
        ("CC1.2", "COSO Principle 2 — board oversight"),
        ("CC1.3", "COSO Principle 3 — management establishes structures, authorities, responsibilities"),
        ("CC1.4", "COSO Principle 4 — commitment to competence"),
        ("CC1.5", "COSO Principle 5 — accountability"),
        ("CC2.1", "Internal communication of information security"),
        ("CC2.2", "External communication of security commitments"),
        ("CC2.3", "Communication to customers and partners"),
        ("CC3.1", "Risk identification and assessment"),
        ("CC3.2", "Risk mitigation strategies"),
        ("CC3.3", "Risk from fraud"),
        ("CC3.4", "Changes that affect internal controls"),
        ("CC4.1", "Monitoring activities — ongoing and separate evaluations"),
        ("CC4.2", "Communicate deficiencies"),
        ("CC5.1", "Selects and develops control activities"),
        ("CC5.2", "Technology general controls"),
        ("CC5.3", "Policies and procedures"),
        ("CC6.1", "Logical access — software and system components"),
        ("CC6.2", "Logical access — authentication and authorization"),
        ("CC6.3", "Logical access — modify, remove, disable access"),
        ("CC6.6", "Logical access — external threat protection"),
        ("CC6.7", "Transmission/movement of data"),
        ("CC6.8", "Prevention/detection of unauthorized/malicious software"),
        ("CC7.1", "Detection of security events"),
        ("CC7.2", "Monitor system components for anomalies"),
        ("CC7.3", "Evaluate security events to determine whether they represent incidents"),
        ("CC7.4", "Respond to security incidents"),
        ("CC7.5", "Recover from identified security incidents"),
        ("CC8.1", "Authorize, design, develop, acquire, configure, document, test, approve, implement changes"),
        ("CC9.1", "Business disruption risk mitigation"),
        ("CC9.2", "Vendor and business partner risk"),
        ("A1.1", "Availability — capacity demand"),
        ("A1.2", "Availability — environmental protections, software, data backup, recovery"),
        ("A1.3", "Availability — recovery plan testing"),
        ("C1.1", "Confidentiality — identify confidential info"),
        ("C1.2", "Confidentiality — disposal"),
        ("PI1.1", "Processing integrity — data input procedures"),
        ("PI1.2", "Processing integrity — processing of inputs"),
        ("PI1.3", "Processing integrity — output processing"),
        ("PI1.4", "Processing integrity — storage of output"),
        ("PI1.5", "Processing integrity — stored inputs/outputs"),
        ("P1.1", "Privacy — notice"),
        ("P2.1", "Privacy — choice and consent"),
        ("P3.1", "Privacy — collection"),
        ("P4.1", "Privacy — use, retention, disposal"),
        ("P5.1", "Privacy — access"),
        ("P6.1", "Privacy — disclosure to 3rd parties"),
        ("P7.1", "Privacy — quality"),
        ("P8.1", "Privacy — monitoring and enforcement"),
    ]
    return [{"framework": "soc2_tsc", "control_id": c, "control_name": n, "description": "SOC 2 Trust Services Criteria"} for c, n in criteria]


def _fw_gdpr_core() -> List[Dict[str, str]]:
    """GDPR — key articles (5, 25, 32, plus 6, 7, 17, 30, 33, 35)."""
    arts = [
        ("GDPR-Art5", "Principles relating to processing of personal data"),
        ("GDPR-Art6", "Lawfulness of processing"),
        ("GDPR-Art7", "Conditions for consent"),
        ("GDPR-Art13", "Information to be provided where data is collected from the data subject"),
        ("GDPR-Art15", "Right of access by the data subject"),
        ("GDPR-Art17", "Right to erasure (right to be forgotten)"),
        ("GDPR-Art20", "Right to data portability"),
        ("GDPR-Art25", "Data protection by design and by default"),
        ("GDPR-Art28", "Processor obligations"),
        ("GDPR-Art30", "Records of processing activities"),
        ("GDPR-Art32", "Security of processing"),
        ("GDPR-Art33", "Notification of personal data breach to supervisory authority"),
        ("GDPR-Art34", "Communication of personal data breach to data subject"),
        ("GDPR-Art35", "Data protection impact assessment"),
        ("GDPR-Art37", "Designation of a data protection officer"),
    ]
    return [{"framework": "gdpr_core", "control_id": c, "control_name": n, "description": "GDPR Article"} for c, n in arts]


def _fw_ccpa_cpra() -> List[Dict[str, str]]:
    """CCPA / CPRA — core consumer rights."""
    items = [
        ("CCPA-Right-1", "Right to know what personal information is collected"),
        ("CCPA-Right-2", "Right to delete personal information"),
        ("CCPA-Right-3", "Right to opt-out of sale/sharing"),
        ("CCPA-Right-4", "Right to non-discrimination"),
        ("CPRA-Right-5", "Right to correct inaccurate personal information"),
        ("CPRA-Right-6", "Right to limit use of sensitive personal information"),
        ("CPRA-Right-7", "Right to data portability"),
        ("CPRA-Obl-1", "Data minimization"),
        ("CPRA-Obl-2", "Purpose limitation"),
        ("CPRA-Obl-3", "Storage limitation and retention schedule"),
        ("CPRA-Obl-4", "Vendor contract requirements"),
        ("CPRA-Obl-5", "Risk assessment for high-risk processing"),
        ("CPRA-Obl-6", "Annual cybersecurity audit for high-risk processing"),
    ]
    return [{"framework": "ccpa_cpra", "control_id": c, "control_name": n, "description": "CCPA/CPRA right or obligation"} for c, n in items]


def _fw_fedramp() -> List[Dict[str, str]]:
    """FedRAMP Moderate/High — baseline mappings to 800-53 families."""
    fams = ["AC", "AU", "CA", "CM", "CP", "IA", "IR", "MA", "MP", "PS", "RA", "SA", "SC", "SI", "SR"]
    rows: List[Dict[str, str]] = []
    for impact, key in [("Moderate", "fedramp_moderate"), ("High", "fedramp_high")]:
        for f in fams:
            rows.append({
                "framework": key,
                "control_id": f"FR-{impact[:1]}-{f}",
                "control_name": f"FedRAMP {impact} baseline family {f}",
                "description": f"FedRAMP {impact} inherits NIST 800-53 {f}",
            })
    return rows


def _fw_ny_dfs() -> List[Dict[str, str]]:
    """NY DFS 23 NYCRR 500 — key sections."""
    items = [
        ("NYDFS-500.02", "Cybersecurity program"),
        ("NYDFS-500.03", "Cybersecurity policy"),
        ("NYDFS-500.04", "Chief Information Security Officer"),
        ("NYDFS-500.05", "Penetration testing and vulnerability assessments"),
        ("NYDFS-500.06", "Audit trail"),
        ("NYDFS-500.07", "Access privileges"),
        ("NYDFS-500.08", "Application security"),
        ("NYDFS-500.09", "Risk assessment"),
        ("NYDFS-500.10", "Cybersecurity personnel and intelligence"),
        ("NYDFS-500.11", "Third-party service provider security policy"),
        ("NYDFS-500.12", "Multi-factor authentication"),
        ("NYDFS-500.13", "Limitations on data retention"),
        ("NYDFS-500.14", "Training and monitoring"),
        ("NYDFS-500.15", "Encryption of nonpublic information"),
        ("NYDFS-500.16", "Incident response plan"),
        ("NYDFS-500.17", "Notices to superintendent"),
    ]
    return [{"framework": "ny_dfs_23_nycrr_500", "control_id": c, "control_name": n, "description": "23 NYCRR 500"} for c, n in items]


def _fw_mitre_attack_enterprise() -> List[Dict[str, str]]:
    """MITRE ATT&CK Enterprise — 14 tactics."""
    tactics = [
        ("TA0043", "Reconnaissance"),
        ("TA0042", "Resource Development"),
        ("TA0001", "Initial Access"),
        ("TA0002", "Execution"),
        ("TA0003", "Persistence"),
        ("TA0004", "Privilege Escalation"),
        ("TA0005", "Defense Evasion"),
        ("TA0006", "Credential Access"),
        ("TA0007", "Discovery"),
        ("TA0008", "Lateral Movement"),
        ("TA0009", "Collection"),
        ("TA0011", "Command and Control"),
        ("TA0010", "Exfiltration"),
        ("TA0040", "Impact"),
    ]
    return [{"framework": "mitre_attack_enterprise", "control_id": c, "control_name": n, "description": "MITRE ATT&CK tactic"} for c, n in tactics]


def _fw_mitre_d3fend() -> List[Dict[str, str]]:
    """MITRE D3FEND — high-level countermeasure categories."""
    items = [
        ("D3-HARDEN", "Harden"),
        ("D3-DETECT", "Detect"),
        ("D3-ISOLATE", "Isolate"),
        ("D3-DECEIVE", "Deceive"),
        ("D3-EVICT", "Evict"),
        ("D3-RESTORE", "Restore"),
    ]
    return [{"framework": "mitre_d3fend", "control_id": c, "control_name": n, "description": "MITRE D3FEND countermeasure"} for c, n in items]


def _fw_owasp_asvs() -> List[Dict[str, str]]:
    """OWASP ASVS v4.0.3 — 3 levels × 14 chapters."""
    chapters = [
        ("V1", "Architecture, Design and Threat Modeling"),
        ("V2", "Authentication"),
        ("V3", "Session Management"),
        ("V4", "Access Control"),
        ("V5", "Validation, Sanitization and Encoding"),
        ("V6", "Stored Cryptography"),
        ("V7", "Error Handling and Logging"),
        ("V8", "Data Protection"),
        ("V9", "Communications"),
        ("V10", "Malicious Code"),
        ("V11", "Business Logic"),
        ("V12", "Files and Resources"),
        ("V13", "API and Web Service"),
        ("V14", "Configuration"),
    ]
    rows: List[Dict[str, str]] = []
    for lvl in (1, 2, 3):
        for cid, name in chapters:
            rows.append({
                "framework": "owasp_asvs_4_0_3",
                "control_id": f"ASVS-L{lvl}-{cid}",
                "control_name": f"{name} (L{lvl})",
                "description": f"OWASP ASVS v4.0.3 Level {lvl} — {name}",
            })
    return rows


def _fw_csa_ccm() -> List[Dict[str, str]]:
    """Cloud Security Alliance CCM v4 — 17 domains."""
    domains = [
        ("CCM-AIS", "Application & Interface Security"),
        ("CCM-AAC", "Audit Assurance & Compliance"),
        ("CCM-BCR", "Business Continuity Management & Operational Resilience"),
        ("CCM-CCC", "Change Control & Configuration Management"),
        ("CCM-DSI", "Data Security & Information Lifecycle Management"),
        ("CCM-DCS", "Datacenter Security"),
        ("CCM-EKM", "Encryption & Key Management"),
        ("CCM-GRM", "Governance and Risk Management"),
        ("CCM-HRS", "Human Resources"),
        ("CCM-IAM", "Identity & Access Management"),
        ("CCM-IVS", "Infrastructure & Virtualization Security"),
        ("CCM-IPY", "Interoperability & Portability"),
        ("CCM-MOS", "Mobile Security"),
        ("CCM-SEF", "Security Incident Management, E-Disc & Cloud Forensics"),
        ("CCM-STA", "Supply Chain Management, Transparency and Accountability"),
        ("CCM-TVM", "Threat and Vulnerability Management"),
        ("CCM-UEM", "Universal Endpoint Management"),
    ]
    return [{"framework": "csa_ccm_v4", "control_id": c, "control_name": n, "description": "CSA CCM v4 domain"} for c, n in domains]


def _fw_hitrust() -> List[Dict[str, str]]:
    """HITRUST CSF v11 — 14 major control categories."""
    cats = [
        ("HITRUST-01", "Information Protection Program"),
        ("HITRUST-02", "Endpoint Protection"),
        ("HITRUST-03", "Portable Media Security"),
        ("HITRUST-04", "Mobile Device Security"),
        ("HITRUST-05", "Wireless Security"),
        ("HITRUST-06", "Configuration Management"),
        ("HITRUST-07", "Vulnerability Management"),
        ("HITRUST-08", "Network Protection"),
        ("HITRUST-09", "Transmission Protection"),
        ("HITRUST-10", "Password Management"),
        ("HITRUST-11", "Access Control"),
        ("HITRUST-12", "Audit Logging & Monitoring"),
        ("HITRUST-13", "Education, Training and Awareness"),
        ("HITRUST-14", "Third-Party Assurance"),
    ]
    return [{"framework": "hitrust_csf_v11", "control_id": c, "control_name": n, "description": "HITRUST CSF v11 category"} for c, n in cats]


def _fw_ffiec_cat() -> List[Dict[str, str]]:
    """FFIEC CAT — Cybersecurity Assessment Tool domains."""
    items = [
        ("FFIEC-D1", "Cyber Risk Management and Oversight"),
        ("FFIEC-D2", "Threat Intelligence and Collaboration"),
        ("FFIEC-D3", "Cybersecurity Controls"),
        ("FFIEC-D4", "External Dependency Management"),
        ("FFIEC-D5", "Cyber Incident Management and Resilience"),
    ]
    return [{"framework": "ffiec_cat", "control_id": c, "control_name": n, "description": "FFIEC CAT domain"} for c, n in items]


def _fw_cjis() -> List[Dict[str, str]]:
    """CJIS Security Policy — 13 policy areas."""
    items = [
        ("CJIS-5.1", "Information exchange agreements"),
        ("CJIS-5.2", "Security awareness training"),
        ("CJIS-5.3", "Incident response"),
        ("CJIS-5.4", "Auditing and accountability"),
        ("CJIS-5.5", "Access control"),
        ("CJIS-5.6", "Identification and authentication"),
        ("CJIS-5.7", "Configuration management"),
        ("CJIS-5.8", "Media protection"),
        ("CJIS-5.9", "Physical protection"),
        ("CJIS-5.10", "Systems and communications protection"),
        ("CJIS-5.11", "Formal audits"),
        ("CJIS-5.12", "Personnel security"),
        ("CJIS-5.13", "Mobile devices"),
    ]
    return [{"framework": "cjis_policy", "control_id": c, "control_name": n, "description": "CJIS Policy Area"} for c, n in items]


def _fw_swift_cscp() -> List[Dict[str, str]]:
    """SWIFT Customer Security Programme — 8 objectives."""
    items = [
        ("SWIFT-CSP-1", "Restrict Internet Access"),
        ("SWIFT-CSP-2", "Segregate Critical Systems"),
        ("SWIFT-CSP-3", "Reduce Attack Surface"),
        ("SWIFT-CSP-4", "Physically Secure Environment"),
        ("SWIFT-CSP-5", "Prevent Compromise of Credentials"),
        ("SWIFT-CSP-6", "Manage Identities and Segregate Privileges"),
        ("SWIFT-CSP-7", "Detect Anomalous Activity"),
        ("SWIFT-CSP-8", "Plan for Incident Response and Information Sharing"),
    ]
    return [{"framework": "swift_cscp", "control_id": c, "control_name": n, "description": "SWIFT CSCP objective"} for c, n in items]


def _fw_naic_model_law() -> List[Dict[str, str]]:
    """NAIC Insurance Data Security Model Law — sections."""
    items = [
        ("NAIC-IDSML-1", "Purpose and intent"),
        ("NAIC-IDSML-2", "Definitions"),
        ("NAIC-IDSML-3", "Information security program"),
        ("NAIC-IDSML-4", "Investigation of cybersecurity event"),
        ("NAIC-IDSML-5", "Notification of cybersecurity event"),
        ("NAIC-IDSML-6", "Power of commissioner"),
        ("NAIC-IDSML-7", "Confidentiality"),
        ("NAIC-IDSML-8", "Exceptions"),
        ("NAIC-IDSML-9", "Penalties"),
    ]
    return [{"framework": "naic_model_law", "control_id": c, "control_name": n, "description": "NAIC Model Law section"} for c, n in items]


def _fw_misc_library() -> List[Dict[str, str]]:
    """Additional 80+ representative frameworks — one control each."""
    entries = [
        ("nist_800_171_r2", "NIST-800-171-3.1", "Access Control (CUI)"),
        ("nist_800_171_r2", "NIST-800-171-3.3", "Audit and Accountability (CUI)"),
        ("nist_800_172", "NIST-800-172-3.1.1e", "Enhanced Access Control"),
        ("nist_800_161_r1", "NIST-800-161-SR-3", "Supply Chain Protection"),
        ("nist_ssdf_1_1", "SSDF-PO.1", "Prepare the Organization"),
        ("nist_ssdf_1_1", "SSDF-PS.1", "Protect Software"),
        ("nist_ssdf_1_1", "SSDF-PW.1", "Produce Well-Secured Software"),
        ("nist_ssdf_1_1", "SSDF-RV.1", "Respond to Vulnerabilities"),
        ("nist_ai_rmf_1_0", "AI-RMF-GOVERN", "Govern AI risk"),
        ("nist_ai_rmf_1_0", "AI-RMF-MAP", "Map AI context"),
        ("nist_ai_rmf_1_0", "AI-RMF-MEASURE", "Measure AI systems"),
        ("nist_ai_rmf_1_0", "AI-RMF-MANAGE", "Manage AI risk"),
        ("nist_privacy_framework_1_0", "PF-ID-P", "Identify privacy risks"),
        ("nist_privacy_framework_1_0", "PF-GV-P", "Govern privacy"),
        ("nist_privacy_framework_1_0", "PF-CT-P", "Control privacy"),
        ("nist_privacy_framework_1_0", "PF-CM-P", "Communicate privacy"),
        ("nist_privacy_framework_1_0", "PF-PR-P", "Protect privacy"),
        ("iso_27017", "ISO27017-CLD.6.3.1", "Shared roles and responsibilities in cloud"),
        ("iso_27018", "ISO27018-A.2.1", "PII processor obligations"),
        ("iso_27701", "ISO27701-6.3", "Privacy information management"),
        ("iso_27799", "ISO27799-A.1", "Health-sector information security"),
        ("iso_42001", "ISO42001-6", "AI management system"),
        ("iso_22301_bcms", "ISO22301-8.3", "Business continuity procedures"),
        ("iso_31000_risk", "ISO31000-6.4", "Risk assessment process"),
        ("cmmc_2_0_level1", "CMMC-L1-AC.1.001", "Level 1 access control"),
        ("cmmc_2_0_level2", "CMMC-L2-AC.2.005", "Level 2 session lock"),
        ("cmmc_2_0_level3", "CMMC-L3-AC.3.014", "Level 3 session termination"),
        ("fisma_moderate", "FISMA-M-AC-2", "Account Management (Moderate)"),
        ("fisma_high", "FISMA-H-AC-2", "Account Management (High)"),
        ("cnssi_1253", "CNSSI1253-AC-2", "Committee on NSS AC-2"),
        ("dora_digital_operational_resilience", "DORA-Art5", "ICT risk management framework"),
        ("dora_digital_operational_resilience", "DORA-Art9", "ICT risk management systems"),
        ("dora_digital_operational_resilience", "DORA-Art17", "ICT-related incident management"),
        ("nis2_directive", "NIS2-Art21", "Cybersecurity risk-management measures"),
        ("nis2_directive", "NIS2-Art23", "Reporting obligations"),
        ("uk_cyber_essentials", "CE-1", "Boundary firewalls and internet gateways"),
        ("uk_cyber_essentials", "CE-2", "Secure configuration"),
        ("uk_cyber_essentials", "CE-3", "Access control"),
        ("uk_cyber_essentials", "CE-4", "Malware protection"),
        ("uk_cyber_essentials", "CE-5", "Patch management"),
        ("uk_cyber_essentials_plus", "CE+Pen-1", "Penetration testing"),
        ("essential_eight_australian", "E8-1", "Application control"),
        ("essential_eight_australian", "E8-2", "Patch applications"),
        ("essential_eight_australian", "E8-3", "Configure Office macro settings"),
        ("essential_eight_australian", "E8-4", "User application hardening"),
        ("essential_eight_australian", "E8-5", "Restrict administrative privileges"),
        ("essential_eight_australian", "E8-6", "Patch operating systems"),
        ("essential_eight_australian", "E8-7", "Multi-factor authentication"),
        ("essential_eight_australian", "E8-8", "Regular backups"),
        ("pdpa_singapore", "PDPA-SG-9", "Consent"),
        ("pdpa_thailand", "PDPA-TH-6", "Lawful basis"),
        ("pipl_china", "PIPL-13", "Legal basis for processing"),
        ("lgpd_brazil", "LGPD-7", "Lawful processing hypotheses"),
        ("popia_south_africa", "POPIA-9", "Lawfulness of processing"),
        ("pipeda_canada", "PIPEDA-4.3", "Consent"),
        ("glba_financial", "GLBA-Safeguards", "Safeguards rule"),
        ("sox_404", "SOX-404", "Management assessment of internal controls"),
        ("sox_itgc", "SOX-ITGC-1", "IT general controls"),
        ("fips_140_2", "FIPS140-2-L1", "Cryptographic module level 1"),
        ("fips_140_3", "FIPS140-3-L2", "Cryptographic module level 2"),
        ("fips_199", "FIPS199-L", "Low impact classification"),
        ("fips_200", "FIPS200-Min", "Minimum security requirements"),
        ("fips_201", "FIPS201-PIV", "Personal identity verification"),
        ("itil_4_service_management", "ITIL4-SM-1", "Service management practice"),
        ("cobit_2019", "COBIT-APO13", "Manage Security"),
        ("csa_star_level1", "STAR-L1", "Self-Assessment"),
        ("csa_star_level2", "STAR-L2", "Third-Party Certification"),
        ("aws_well_architected_security", "AWS-WA-SEC-1", "Securely operate workload"),
        ("aws_foundational_security", "AWS-FSBP-IAM", "IAM best practices"),
        ("azure_security_benchmark_v3", "ASB-NS", "Network Security"),
        ("gcp_security_foundations", "GCP-SF-IAM", "IAM foundational"),
        ("oracle_cloud_security", "OCI-Sec-1", "Identity management"),
        ("alibaba_cloud_security", "Ali-Sec-1", "Security center baseline"),
        ("kubernetes_pci_benchmark", "K8s-PCI-1", "Cluster policy"),
        ("kubernetes_hipaa_benchmark", "K8s-HIPAA-1", "Namespace policy"),
        ("docker_cis_benchmark", "Docker-CIS-1.1", "Host configuration"),
        ("nist_container_security", "NIST-SP800-190-4", "Container runtime security"),
        ("mitre_atlas_ai", "ATLAS-T1", "Reconnaissance (AI)"),
        ("mitre_engage", "ENGAGE-Prepare", "Prepare engagement"),
        ("mitre_shield", "SHIELD-DT0001", "Defensive technique"),
        ("lockheed_kill_chain", "LKC-1", "Reconnaissance"),
        ("lockheed_kill_chain", "LKC-2", "Weaponization"),
        ("lockheed_kill_chain", "LKC-3", "Delivery"),
        ("lockheed_kill_chain", "LKC-4", "Exploitation"),
        ("lockheed_kill_chain", "LKC-5", "Installation"),
        ("lockheed_kill_chain", "LKC-6", "Command and Control"),
        ("lockheed_kill_chain", "LKC-7", "Actions on Objectives"),
        ("diamond_model", "DM-Adversary", "Adversary"),
        ("diamond_model", "DM-Capability", "Capability"),
        ("diamond_model", "DM-Infrastructure", "Infrastructure"),
        ("diamond_model", "DM-Victim", "Victim"),
        ("unified_compliance_framework", "UCF-1", "Unified control set"),
        ("sci_regulation", "SCI-1", "Systems Compliance and Integrity"),
        ("psd2_payment_services", "PSD2-SCA", "Strong customer authentication"),
        ("pci_pa_dss", "PA-DSS-4", "Log centralized auditing"),
        ("pci_p2pe", "P2PE-D1", "Encryption device management"),
        ("hitech_act", "HITECH-13402", "Breach notification"),
        ("21_cfr_part_11_fda", "21CFR11-10", "Electronic records controls"),
        ("tcf_2_2_privacy", "TCF-Purpose-1", "Store and/or access information on a device"),
        ("ico_uk_gdpr", "ICO-Principle-1", "Lawfulness, fairness and transparency"),
        ("stigs_dod", "STIG-APP-1", "Application security STIG"),
        ("disa_srg", "DISA-SRG-1", "Application security requirements guide"),
        ("dod_8570", "DOD-8570-IAT1", "IAT Level I baseline"),
        ("itar_export", "ITAR-120", "Export of defense articles"),
        ("ear_export", "EAR-734", "Scope of EAR"),
        ("iec_62443_ot", "IEC62443-SR1.1", "Human user identification"),
        ("nerc_cip", "NERC-CIP-007-6", "Systems security management"),
        ("tsa_pipeline_security", "TSA-PS-1", "Pipeline cybersecurity directive"),
        ("fcc_tcpa", "TCPA-227", "Restrictions on telephone equipment"),
        ("ccma_code_of_conduct", "CCMA-Art1", "Code of conduct commitments"),
        ("nist_1800_series", "NIST-1800-5", "IT Asset Management"),
        ("nist_7298_glossary", "NIST-7298", "Glossary of key security terms"),
        ("bsi_grundschutz", "BSI-APP.1.1", "Office products"),
        ("anssi_reference", "ANSSI-H-1", "Authentication hygiene"),
        ("cesg_uk", "CESG-GPG-13", "Protective monitoring"),
        ("jasa_japan", "JASA-1", "Information security audit"),
        ("krisa_korea", "KISA-ISMS-P", "ISMS-P certification"),
        ("ens_spain", "ENS-OP.ACC", "Access control"),
        ("mehari_france", "MEHARI-S1", "Security reference module"),
        ("pci_sscp", "SSCP-1", "Secure software core practice"),
        ("pci_piin_mapping", "PIIN-1", "Payment information identifier"),
        ("fedramp_li_saas", "FR-LI-SAAS-1", "Low-Impact SaaS baseline"),
        ("statecamp_sled", "StateCamp-1", "State/Local baseline"),
        ("c5_germany", "C5-OPS-1", "Operational practices"),
        ("agreed_code_of_conduct", "ACoC-1", "Cloud code of conduct"),
        ("iso_29100_privacy", "ISO29100-5", "Privacy framework principles"),
        ("iso_24760_identity", "ISO24760-7", "Identity management framework"),
        ("nist_8286_erm", "NIST-8286-1", "Integrating cybersecurity and enterprise risk management"),
        ("oecd_ai_principles", "OECD-AI-1", "Inclusive growth, sustainable development, well-being"),
        ("fair_risk_quantification", "FAIR-LEF", "Loss Event Frequency"),
        ("octave_risk", "OCTAVE-P1", "Phase 1 — build asset-based threat profiles"),
        ("sig_shared_assessments", "SIG-A", "Shared assessments questionnaire A"),
        ("ccpa_loyalty", "CCPA-Loyalty-1", "Loyalty program disclosures"),
        ("general", "general-baseline", "Generic baseline control"),
        ("custom", "custom-baseline", "Customer-defined control"),
        ("internal", "internal-baseline", "Internal audit control"),
    ]
    return [{"framework": fw, "control_id": cid, "control_name": name, "description": f"{fw} representative control"} for fw, cid, name in entries]
