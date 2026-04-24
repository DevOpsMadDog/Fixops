"""Threat Modeling Pipeline Engine — ALDECI.

Automated threat modeling pipeline with STRIDE analysis, threat enumeration,
and mitigation tracking across multiple methodologies.

Supports:
- Model lifecycle (draft → finalized)
- Component registry with trust boundary mapping
- STRIDE threat enumeration with risk_level computation
- Mitigation tracking — risk_score recomputed from unmitigated threats only
- STRIDE summary per category
- Cross-org unmitigated threat query

Compliance: NIST SP 800-154, OWASP Threat Modeling, ISO/IEC 27005
"""
from __future__ import annotations

import contextlib
import json
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


_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "threat_modeling_pipeline.db"
)

_VALID_METHODOLOGIES = {"STRIDE", "PASTA", "VAST", "attack-tree", "OCTAVE", "custom"}
_VALID_STRIDE_CATEGORIES = {
    "S-Spoofing", "T-Tampering", "R-Repudiation",
    "I-InfoDisclosure", "D-DenialOfService", "E-ElevationOfPrivilege",
}
_VALID_COMPONENT_TYPES = {
    "process", "datastore", "external-entity", "data-flow", "trust-boundary",
}
_VALID_LIKELIHOODS = {"critical", "high", "medium", "low"}
_VALID_IMPACTS = {"critical", "high", "medium", "low"}
_VALID_STATUSES = {"draft", "finalized"}

# Numeric mapping for risk_score averaging
_RISK_NUMERIC = {"critical": 4, "high": 3, "medium": 2, "low": 1}
_NUMERIC_RISK = {4: "critical", 3: "high", 2: "medium", 1: "low"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _compute_risk_level(likelihood: str, impact: str) -> str:
    """Compute risk_level from likelihood x impact matrix.

    Matrix (likelihood × impact → risk_level):
      critical/high + critical/high → critical
      high+medium or critical+low   → high
      medium+medium                 → medium
      else                          → low
    """
    l = likelihood.lower()
    i = impact.lower()
    if l in ("critical", "high") and i in ("critical", "high"):
        return "critical"
    if (l == "high" and i == "medium") or (l == "critical" and i == "low"):
        return "high"
    if (l == "medium" and i == "critical") or (l == "medium" and i == "high"):
        return "high"
    if l == "medium" and i == "medium":
        return "medium"
    if l == "low" and i in ("critical", "high"):
        return "high"
    if l == "low" and i == "medium":
        return "medium"
    return "low"


def _recompute_model_risk_score(conn, model_id: str, org_id: str) -> float:
    """Recompute risk_score as avg numeric value of UNMITIGATED threats only."""
    rows = conn.execute(
        "SELECT risk_level FROM model_threats "
        "WHERE model_id=? AND org_id=? AND mitigated=0",
        (model_id, org_id),
    ).fetchall()
    if not rows:
        return 0.0
    total = sum(_RISK_NUMERIC.get(r["risk_level"], 1) for r in rows)
    return round(total / len(rows), 4)


class ThreatModelingPipelineEngine:
    """SQLite WAL-backed Threat Modeling Pipeline engine.

    Thread-safe via RLock.  Multi-tenant via org_id.
    """

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self._db_path = db_path
        self._lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @contextlib.contextmanager
    def _conn(self):
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_db(self) -> None:
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS threat_models (
                    id                TEXT PRIMARY KEY,
                    org_id            TEXT NOT NULL,
                    model_name        TEXT NOT NULL,
                    system_description TEXT NOT NULL DEFAULT '',
                    methodology       TEXT NOT NULL DEFAULT 'STRIDE',
                    status            TEXT NOT NULL DEFAULT 'draft',
                    threat_count      INTEGER NOT NULL DEFAULT 0,
                    mitigated_count   INTEGER NOT NULL DEFAULT 0,
                    risk_score        REAL NOT NULL DEFAULT 0.0,
                    created_by        TEXT NOT NULL DEFAULT '',
                    created_at        TEXT NOT NULL,
                    updated_at        TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS model_threats (
                    id                    TEXT PRIMARY KEY,
                    model_id              TEXT NOT NULL,
                    org_id                TEXT NOT NULL,
                    threat_name           TEXT NOT NULL,
                    stride_category       TEXT NOT NULL,
                    description           TEXT NOT NULL DEFAULT '',
                    affected_component    TEXT NOT NULL DEFAULT '',
                    likelihood            TEXT NOT NULL DEFAULT 'medium',
                    impact                TEXT NOT NULL DEFAULT 'medium',
                    risk_level            TEXT NOT NULL DEFAULT 'medium',
                    mitigated             INTEGER NOT NULL DEFAULT 0,
                    mitigation_description TEXT NOT NULL DEFAULT '',
                    created_at            TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS model_components (
                    id               TEXT PRIMARY KEY,
                    model_id         TEXT NOT NULL,
                    org_id           TEXT NOT NULL,
                    component_name   TEXT NOT NULL,
                    component_type   TEXT NOT NULL,
                    trust_boundary   TEXT NOT NULL DEFAULT '',
                    data_flows       TEXT NOT NULL DEFAULT '[]',
                    created_at       TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_models_org
                    ON threat_models(org_id);
                CREATE INDEX IF NOT EXISTS idx_threats_model
                    ON model_threats(model_id, org_id);
                CREATE INDEX IF NOT EXISTS idx_components_model
                    ON model_components(model_id, org_id);
            """)

    def _row_to_dict(self, row) -> Dict[str, Any]:
        return dict(row) if row else {}

    def _get_model(self, conn, model_id: str, org_id: str) -> Optional[Dict[str, Any]]:
        row = conn.execute(
            "SELECT * FROM threat_models WHERE id=? AND org_id=?",
            (model_id, org_id),
        ).fetchone()
        return self._row_to_dict(row) if row else None

    # ------------------------------------------------------------------
    # Model lifecycle
    # ------------------------------------------------------------------

    def create_model(
        self,
        org_id: str,
        model_name: str,
        system_description: str = "",
        methodology: str = "STRIDE",
        created_by: str = "",
    ) -> Dict[str, Any]:
        """Create a new threat model in draft status."""
        if methodology not in _VALID_METHODOLOGIES:
            raise ValueError(f"Invalid methodology: {methodology!r}. "
                             f"Valid: {_VALID_METHODOLOGIES}")
        model_id = str(uuid.uuid4())
        now = _now()
        row = {
            "id": model_id,
            "org_id": org_id,
            "model_name": model_name,
            "system_description": system_description,
            "methodology": methodology,
            "status": "draft",
            "threat_count": 0,
            "mitigated_count": 0,
            "risk_score": 0.0,
            "created_by": created_by,
            "created_at": now,
            "updated_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO threat_models
                       (id, org_id, model_name, system_description, methodology, status,
                        threat_count, mitigated_count, risk_score, created_by,
                        created_at, updated_at)
                       VALUES (:id,:org_id,:model_name,:system_description,:methodology,
                               :status,:threat_count,:mitigated_count,:risk_score,
                               :created_by,:created_at,:updated_at)""",
                    row,
                )
        return row

    def add_component(
        self,
        model_id: str,
        org_id: str,
        component_name: str,
        component_type: str,
        trust_boundary: str = "",
        data_flows: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Add a component to a threat model."""
        if component_type not in _VALID_COMPONENT_TYPES:
            raise ValueError(f"Invalid component_type: {component_type!r}. "
                             f"Valid: {_VALID_COMPONENT_TYPES}")
        comp_id = str(uuid.uuid4())
        now = _now()
        data_flows_json = json.dumps(data_flows or [])
        row = {
            "id": comp_id,
            "model_id": model_id,
            "org_id": org_id,
            "component_name": component_name,
            "component_type": component_type,
            "trust_boundary": trust_boundary,
            "data_flows": data_flows_json,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                model = self._get_model(conn, model_id, org_id)
                if not model:
                    raise ValueError(f"Model {model_id!r} not found for org {org_id!r}")
                conn.execute(
                    """INSERT INTO model_components
                       (id, model_id, org_id, component_name, component_type,
                        trust_boundary, data_flows, created_at)
                       VALUES (:id,:model_id,:org_id,:component_name,:component_type,
                               :trust_boundary,:data_flows,:created_at)""",
                    row,
                )
                conn.execute(
                    "UPDATE threat_models SET updated_at=? WHERE id=? AND org_id=?",
                    (now, model_id, org_id),
                )
        result = dict(row)
        result["data_flows"] = data_flows or []
        return result

    def add_threat(
        self,
        model_id: str,
        org_id: str,
        threat_name: str,
        stride_category: str,
        description: str = "",
        affected_component: str = "",
        likelihood: str = "medium",
        impact: str = "medium",
    ) -> Dict[str, Any]:
        """Add a threat to a model. Auto-computes risk_level; updates model counters."""
        if stride_category not in _VALID_STRIDE_CATEGORIES:
            raise ValueError(f"Invalid stride_category: {stride_category!r}. "
                             f"Valid: {_VALID_STRIDE_CATEGORIES}")
        if likelihood not in _VALID_LIKELIHOODS:
            raise ValueError(f"Invalid likelihood: {likelihood!r}")
        if impact not in _VALID_IMPACTS:
            raise ValueError(f"Invalid impact: {impact!r}")

        risk_level = _compute_risk_level(likelihood, impact)
        threat_id = str(uuid.uuid4())
        now = _now()
        row = {
            "id": threat_id,
            "model_id": model_id,
            "org_id": org_id,
            "threat_name": threat_name,
            "stride_category": stride_category,
            "description": description,
            "affected_component": affected_component,
            "likelihood": likelihood,
            "impact": impact,
            "risk_level": risk_level,
            "mitigated": 0,
            "mitigation_description": "",
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                model = self._get_model(conn, model_id, org_id)
                if not model:
                    raise ValueError(f"Model {model_id!r} not found for org {org_id!r}")
                conn.execute(
                    """INSERT INTO model_threats
                       (id, model_id, org_id, threat_name, stride_category, description,
                        affected_component, likelihood, impact, risk_level, mitigated,
                        mitigation_description, created_at)
                       VALUES (:id,:model_id,:org_id,:threat_name,:stride_category,
                               :description,:affected_component,:likelihood,:impact,
                               :risk_level,:mitigated,:mitigation_description,:created_at)""",
                    row,
                )
                # Update threat_count and recompute risk_score
                new_threat_count = (model["threat_count"] or 0) + 1
                new_risk_score = _recompute_model_risk_score(conn, model_id, org_id)
                conn.execute(
                    "UPDATE threat_models SET threat_count=?, risk_score=?, updated_at=? "
                    "WHERE id=? AND org_id=?",
                    (new_threat_count, new_risk_score, now, model_id, org_id),
                )
        return row

    def mitigate_threat(
        self,
        model_id: str,
        threat_id: str,
        org_id: str,
        mitigation_description: str = "",
    ) -> Dict[str, Any]:
        """Mark a threat as mitigated; recompute model risk_score from unmitigated only."""
        now = _now()
        with self._lock:
            with self._conn() as conn:
                model = self._get_model(conn, model_id, org_id)
                if not model:
                    raise ValueError(f"Model {model_id!r} not found for org {org_id!r}")
                threat = conn.execute(
                    "SELECT * FROM model_threats WHERE id=? AND model_id=? AND org_id=?",
                    (threat_id, model_id, org_id),
                ).fetchone()
                if not threat:
                    raise ValueError(f"Threat {threat_id!r} not found in model {model_id!r}")
                was_mitigated = threat["mitigated"]
                conn.execute(
                    "UPDATE model_threats SET mitigated=1, mitigation_description=? "
                    "WHERE id=? AND model_id=? AND org_id=?",
                    (mitigation_description, threat_id, model_id, org_id),
                )
                # Only increment mitigated_count if it wasn't already mitigated
                new_mitigated_count = (model["mitigated_count"] or 0) + (0 if was_mitigated else 1)
                new_risk_score = _recompute_model_risk_score(conn, model_id, org_id)
                conn.execute(
                    "UPDATE threat_models SET mitigated_count=?, risk_score=?, updated_at=? "
                    "WHERE id=? AND org_id=?",
                    (new_mitigated_count, new_risk_score, now, model_id, org_id),
                )
                updated = conn.execute(
                    "SELECT * FROM model_threats WHERE id=? AND model_id=? AND org_id=?",
                    (threat_id, model_id, org_id),
                ).fetchone()
                return self._row_to_dict(updated)

    def finalize_model(self, model_id: str, org_id: str) -> Dict[str, Any]:
        """Transition model status to finalized."""
        now = _now()
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    "UPDATE threat_models SET status='finalized', updated_at=? "
                    "WHERE id=? AND org_id=?",
                    (now, model_id, org_id),
                )
                row = conn.execute(
                    "SELECT * FROM threat_models WHERE id=? AND org_id=?",
                    (model_id, org_id),
                ).fetchone()
                if not row:
                    raise ValueError(f"Model {model_id!r} not found")
                return self._row_to_dict(row)

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get_model(self, model_id: str, org_id: str) -> Dict[str, Any]:
        """Return model with its components and threats."""
        with self._lock:
            with self._conn() as conn:
                model = self._get_model(conn, model_id, org_id)
                if not model:
                    raise ValueError(f"Model {model_id!r} not found for org {org_id!r}")
                components = conn.execute(
                    "SELECT * FROM model_components WHERE model_id=? AND org_id=? "
                    "ORDER BY created_at",
                    (model_id, org_id),
                ).fetchall()
                threats = conn.execute(
                    "SELECT * FROM model_threats WHERE model_id=? AND org_id=? "
                    "ORDER BY created_at",
                    (model_id, org_id),
                ).fetchall()
                # Parse data_flows JSON for each component
                comps_list = []
                for c in components:
                    cd = dict(c)
                    try:
                        cd["data_flows"] = json.loads(cd.get("data_flows") or "[]")
                    except (json.JSONDecodeError, TypeError):
                        cd["data_flows"] = []
                    comps_list.append(cd)
                model["components"] = comps_list
                model["threats"] = [dict(t) for t in threats]
                return model

    def list_models(
        self,
        org_id: str,
        status: Optional[str] = None,
        methodology: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List models with optional status/methodology filters."""
        with self._lock:
            with self._conn() as conn:
                sql = "SELECT * FROM threat_models WHERE org_id=?"
                params: list = [org_id]
                if status:
                    sql += " AND status=?"
                    params.append(status)
                if methodology:
                    sql += " AND methodology=?"
                    params.append(methodology)
                sql += " ORDER BY created_at DESC"
                rows = conn.execute(sql, params).fetchall()
                return [dict(r) for r in rows]

    def get_stride_summary(self, model_id: str, org_id: str) -> Dict[str, Any]:
        """Return per-STRIDE-category counts, mitigated count, and risk_level distribution."""
        with self._lock:
            with self._conn() as conn:
                model = self._get_model(conn, model_id, org_id)
                if not model:
                    raise ValueError(f"Model {model_id!r} not found for org {org_id!r}")
                rows = conn.execute(
                    "SELECT stride_category, risk_level, mitigated, COUNT(*) as cnt "
                    "FROM model_threats WHERE model_id=? AND org_id=? "
                    "GROUP BY stride_category, risk_level, mitigated",
                    (model_id, org_id),
                ).fetchall()

                summary: Dict[str, Any] = {}
                for cat in _VALID_STRIDE_CATEGORIES:
                    summary[cat] = {
                        "count": 0,
                        "mitigated": 0,
                        "risk_level_distribution": {"critical": 0, "high": 0, "medium": 0, "low": 0},
                    }

                for r in rows:
                    cat = r["stride_category"]
                    if cat not in summary:
                        summary[cat] = {
                            "count": 0,
                            "mitigated": 0,
                            "risk_level_distribution": {"critical": 0, "high": 0, "medium": 0, "low": 0},
                        }
                    summary[cat]["count"] += r["cnt"]
                    if r["mitigated"]:
                        summary[cat]["mitigated"] += r["cnt"]
                    rl = r["risk_level"]
                    if rl in summary[cat]["risk_level_distribution"]:
                        summary[cat]["risk_level_distribution"][rl] += r["cnt"]

                return {
                    "model_id": model_id,
                    "org_id": org_id,
                    "stride_summary": summary,
                }

    def get_unmitigated_threats(self, org_id: str) -> List[Dict[str, Any]]:
        """Return all unmitigated threats across all models for an org."""
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(
                    """SELECT t.*, m.model_name, m.methodology
                       FROM model_threats t
                       JOIN threat_models m ON m.id = t.model_id
                       WHERE t.org_id=? AND t.mitigated=0
                       ORDER BY t.created_at DESC""",
                    (org_id,),
                ).fetchall()
                return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # GAP-056: Auto-threat-model from design doc ingest
    # ------------------------------------------------------------------

    # Map STRIDE heuristic threat-types (from ThreatModelingEngine) to the
    # pipeline's stride_category taxonomy.
    _STRIDE_CATEGORY_MAP = {
        "spoofing": "S-Spoofing",
        "tampering": "T-Tampering",
        "repudiation": "R-Repudiation",
        "information_disclosure": "I-InfoDisclosure",
        "denial_of_service": "D-DenialOfService",
        "elevation_of_privilege": "E-ElevationOfPrivilege",
    }

    _SEV_TO_LIKELIHOOD_IMPACT = {
        "critical": ("high", "critical"),
        "high": ("medium", "high"),
        "medium": ("medium", "medium"),
        "low": ("low", "low"),
    }

    def auto_threat_model_from_doc(
        self,
        org_id: str,
        doc_ingest_id: str,
        model_name: Optional[str] = None,
        created_by: str = "auto-ingest",
    ) -> Dict[str, Any]:
        """Chain ingest -> extract -> draft threat model in the pipeline.

        1. Ensure STRIDE elements are extracted for the referenced design-doc ingest
           (re-runs extraction for idempotency).
        2. Create a new draft threat model in this pipeline engine.
        3. Register each unique parsed component as a model_component.
        4. Register each extracted STRIDE threat as a model_threat with mapped
           stride_category + likelihood/impact derived from severity.
        Returns the draft model record with counts and traceability ids.
        """
        if not org_id:
            raise ValueError("org_id is required")
        if not doc_ingest_id:
            raise ValueError("doc_ingest_id is required")

        # Lazy import to avoid circular imports at module load
        from core.threat_modeling_engine import ThreatModelingEngine  # noqa: WPS433

        tme = ThreatModelingEngine()
        ingest = tme._get_ingest(org_id, doc_ingest_id)  # noqa: SLF001
        if not ingest:
            raise ValueError(
                f"doc_ingest_id '{doc_ingest_id}' not found for org '{org_id}'"
            )
        extracted = tme.extract_stride_elements(org_id, doc_ingest_id)

        try:
            components = json.loads(ingest.get("parsed_components_json") or "[]")
        except (TypeError, ValueError, json.JSONDecodeError):
            components = []

        effective_name = (
            model_name
            or f"Auto model from {ingest.get('doc_source', 'design-doc')}"
        )
        model = self.create_model(
            org_id=org_id,
            model_name=effective_name,
            system_description=(
                f"Draft model auto-generated from design doc ingest "
                f"{doc_ingest_id}"
            ),
            methodology="STRIDE",
            created_by=created_by,
        )
        model_id = model["id"]

        components_added = 0
        for comp_name in components:
            if not isinstance(comp_name, str) or not comp_name.strip():
                continue
            try:
                self.add_component(
                    model_id=model_id,
                    org_id=org_id,
                    component_name=comp_name.strip(),
                    component_type="process",
                    trust_boundary="",
                    data_flows=[],
                )
                components_added += 1
            except ValueError:
                # Skip invalid component rows but keep the pipeline going.
                continue

        threats_added = 0
        for threat in extracted:
            stride_cat = self._STRIDE_CATEGORY_MAP.get(
                threat.get("threat_type", ""),
                "I-InfoDisclosure",
            )
            sev = (threat.get("severity") or "medium").lower()
            likelihood, impact = self._SEV_TO_LIKELIHOOD_IMPACT.get(
                sev, ("medium", "medium")
            )
            try:
                self.add_threat(
                    model_id=model_id,
                    org_id=org_id,
                    threat_name=(
                        f"{threat.get('threat_type', 'threat')} on "
                        f"{threat.get('component', 'component')}"
                    ),
                    stride_category=stride_cat,
                    description=threat.get("description", ""),
                    affected_component=threat.get("component", ""),
                    likelihood=likelihood,
                    impact=impact,
                )
                threats_added += 1
            except ValueError:
                continue

        return {
            "model_id": model_id,
            "model_name": effective_name,
            "org_id": org_id,
            "doc_ingest_id": doc_ingest_id,
            "components_added": components_added,
            "threats_added": threats_added,
            "status": "draft",
            "source": "design-doc-ingest",
        }
